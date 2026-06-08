<div align="center">

# orbital-trust-sec

### Módulo de Cibersegurança · Orbital Trust
**Global Solution · 1º Semestre 2026**

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-AEAD-success?style=for-the-badge&logo=letsencrypt&logoColor=white)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![FIAP](https://img.shields.io/badge/FIAP-3ESR-ED1C24?style=for-the-badge)](https://www.fiap.com.br/)
[![Disciplina](https://img.shields.io/badge/Cibersegurança_1-Oerton_Fernandes-0A66C2?style=for-the-badge)]()

> Criptografia autenticada de dados geográficos sensíveis em sensores terrestres,
> integrada ao pipeline do Orbital Trust.

</div>

---

## Destaques

- **Criptografia AEAD** com AES-256-GCM na **coordenada do sensor** (dado sensível de localização)
- **Mitigação dupla** — Information Disclosure (confidencialidade) + Tampering (autenticação)
- **Banco real em Docker** — PostgreSQL persiste a coordenada **sempre cifrada** (data at rest)
- **Três cenários** demonstram roundtrip, unicidade de ciphertext e detecção de adulteração
- **Justificativa técnica** documentada — por que GCM e não CBC

---

## Sumário

1. [Sobre o projeto](#sobre-o-projeto)
2. [Sobre este repositório](#sobre-este-repositório)
3. [Ameaça mitigada](#ameaça-mitigada)
4. [Implementação prática — AES-256-GCM](#implementação-prática--aes-256-gcm)
5. [Fluxo de criptografia](#fluxo-de-criptografia)
6. [Exemplo de uso](#exemplo-de-uso)
7. [Controles de segurança no Orbital Trust](#controles-de-segurança-no-orbital-trust)
8. [Estrutura do projeto](#estrutura-do-projeto)
9. [Como rodar](#como-rodar)
10. [Decisões de design](#decisões-de-design)
11. [Considerações para produção](#considerações-para-produção)
12. [Evidências](#evidências)
13. [Bibliotecas utilizadas](#bibliotecas-utilizadas)
14. [Referências](#referências)
15. [Integrantes](#integrantes)

---

## Sobre o projeto

O **Orbital Trust** é um MVP que transforma **imagens orbitais abertas**
(Sentinel-2, Landsat e tiles públicos) em alertas ambientais confiáveis sobre
queimadas, solo exposto, água, vegetação e baixa visibilidade.

A arquitetura é desacoplada em três camadas: **IoT/CV** (Python + OpenCV) carrega
frames e gera um payload JSON padronizado; **API/ML** (FastAPI) refina o risco
ambiental e emite recomendações; e o **App Mobile** (React Native/Expo) exibe os
alertas. A confiança da análise sustenta o índice de confiabilidade do alerta.

Para o histórico de leituras e alertas, a solução prevê uma camada de
**persistência (PostgreSQL)**. É exatamente nesse ponto que entra este módulo: o
campo `coordenada` — a localização exata do sensor — é o dado mais sensível do
payload e **nunca** é gravado em texto claro. Este repositório sobe esse banco em
Docker e demonstra a coordenada cifrada **em repouso** (*data at rest*).

---

## Sobre este repositório

Implementação prática do módulo de cibersegurança entregue na disciplina
**Cibersegurança 1** (Prof. MSc. Oerton Fernandes), integrada ao projeto da GS.

---

## Ameaça mitigada

Análise via modelo **STRIDE**:

| Ameaça STRIDE              | Vetor                                              | Mitigação aplicada                  |
|----------------------------|----------------------------------------------------|-------------------------------------|
| **Information Disclosure** | Coordenada do sensor exposta em texto claro (em repouso ou num dump) | AES-256-GCM na coordenada |
| **Tampering**              | Adulteração de bytes do dado criptografado         | Autenticação AEAD (tag GCM)         |

> Sem o controle: o vazamento do dado exporia a **localização exata** de cada
> sensor — informação operacionalmente crítica e potencialmente sensível para
> segurança física dos equipamentos.

---

## Implementação prática — AES-256-GCM

Criptografia **AES-256 em modo GCM** aplicada à **coordenada do sensor** — o dado
mais sensível do payload, pois revela a localização exata da infraestrutura
monitorada — **antes** de ser persistida ou transmitida.

### Por que GCM e não CBC?

| Critério                       | CBC                              | **GCM**                          |
|--------------------------------|----------------------------------|----------------------------------|
| Confidencialidade              | Sim                              | Sim                              |
| Autenticação / integridade     | Requer HMAC separado             | Embutida (AEAD)                  |
| Padding oracle                 | Vulnerável                       | Não se aplica                    |
| Performance                    | Boa                              | Comparável (instruções AES-NI)   |
| Detecção de tampering          | Silenciosa                       | `CryptographicException`         |

O modo **GCM** inclui autenticação embutida (AEAD — *Authenticated Encryption
with Associated Data*). Se um atacante adulterar o dado no banco, o `Decrypt`
lança `CryptographicException` **antes** de retornar qualquer dado, eliminando
a classe de ataques de padding oracle.

### Parâmetros criptográficos

| Parâmetro          | Valor                  | Justificativa                                              |
|--------------------|------------------------|------------------------------------------------------------|
| Algoritmo          | AES                    | Padrão NIST FIPS-197                                       |
| Tamanho da chave   | 256 bits               | Margem contra ataques quânticos (Grover ⇒ 128-bit security)|
| Modo               | GCM                    | AEAD — confidencialidade + autenticidade num único passo   |
| Nonce              | 96 bits (12 bytes)     | Recomendação NIST SP 800-38D — formato canônico do GCM     |
| Tag de autenticação| 128 bits (16 bytes)    | Maior nível de segurança suportado pelo GCM                |
| Geração de nonce   | `RandomNumberGenerator`| CSPRNG — único por mensagem (requisito crítico do GCM)     |

---

## Fluxo de criptografia

```mermaid
flowchart LR
    A[Sensor / Payload] -->|Coordenada<br/>-23.5505, -46.6333| B[CryptoService.Encrypt]
    B -->|nonce 12B + tag 16B + cipher| C[(Dado em repouso<br/>Base64)]
    C -->|Base64| D[CryptoService.Decrypt]
    D -->|tag válida| E[API / Dashboard]
    D -->|tag inválida| F[CryptographicException]

    style B fill:#1e3a8a,stroke:#3b82f6,color:#fff
    style D fill:#1e3a8a,stroke:#3b82f6,color:#fff
    style F fill:#7f1d1d,stroke:#ef4444,color:#fff
    style E fill:#14532d,stroke:#22c55e,color:#fff
```

### Estrutura do ciphertext serializado

```
┌─────────────┬─────────────┬──────────────────────┐
│ nonce (12B) │  tag (16B)  │ ciphertext (n bytes) │
└─────────────┴─────────────┴──────────────────────┘
                      ↓
                Base64 encode
                      ↓
       guardado/transmitido como `Coordenada`
```

O nonce vai junto do ciphertext porque é necessário para descriptografar —
**não é segredo**, apenas precisa ser único por mensagem sob a mesma chave.

---

## Exemplo de uso

```csharp
using OrbitalTrust.Security;

// Antes de guardar/transmitir: criptografa a coordenada
var coordenada = "-23.5505, -46.6333";
var protegida  = CryptoService.Encrypt(coordenada);
// → Base64 ilegível: "nonce|tag|ciphertext"

// Ao consumir: descriptografa de volta
var coord = CryptoService.Decrypt(protegida);
// → "-23.5505, -46.6333"

// Detecção de adulteração (autenticação GCM)
try
{
    CryptoService.Decrypt(dadoAdulterado);
}
catch (CryptographicException)
{
    // tag inválida — o dado foi alterado
    Console.Error.WriteLine("Tampering detectado na coordenada.");
}
```

> O contrato é simples (`string → string` em Base64), então qualquer camada da
> solução — inclusive a API em Python, via serviço ou porta dedicada — pode
> consumir o controle sem acoplamento de linguagem.

---

## Controles de segurança no Orbital Trust

| #   | Controle                          | Tipo            | Aplica em                                  |
|:---:|-----------------------------------|-----------------|--------------------------------------------|
|  1  | TLS/HTTPS obrigatório             | Preventivo      | API de Análise (FastAPI)                    |
|  2  | Autenticação + Roles IAM          | Preventivo      | API — sensor_node / analyst / admin        |
|  3  | **AES-256-GCM na coordenada**     | **Preventivo**  | **Coordenada do sensor** ← este repo       |
|  4  | Monitoramento de logs             | Detectivo       | API + persistência                         |
|  5  | mTLS para IoT                     | Preventivo      | Nó IoT / CV                                 |

---

## Estrutura do projeto

```
orbital-trust-sec/
├── src/
│   ├── CryptoService/
│   │   ├── CryptoService.cs            ← Encrypt / Decrypt (AES-256-GCM)
│   │   ├── Program.cs                  ← 3 cenários demonstrativos
│   │   └── CryptoService.csproj
│   └── DbSeed/
│       ├── Program.cs                  ← grava coordenada cifrada no Postgres (Npgsql)
│       └── DbSeed.csproj               ← reusa o mesmo CryptoService
├── db/
│   └── init.sql                        ← esquema: tabela leituras_sensor
├── tests/
│   └── CryptoService.Tests/
│       ├── CryptoServiceTests.cs       ← suíte xUnit (roundtrip, tampering, nonce)
│       └── CryptoService.Tests.csproj
├── evidencias/
│   ├── output.txt                      ← saída do CryptoService (3 cenários)
│   ├── output-banco.txt                ← saída da gravação no banco + SELECT cru
│   ├── print_execucao.png              ← screenshot do terminal (CryptoService)
│   └── print_banco.png                 ← screenshot do banco cifrado (data at rest)
├── docker-compose.yml                  ← PostgreSQL 16
├── .gitignore
└── README.md
```

---

## Como rodar

> **Requisito:** .NET 8 SDK

```bash
cd src/CryptoService
dotnet run
```

### Chave de criptografia

A chave é lida da variável de ambiente `ORBITAL_TRUST_KEY` (Base64 de 32 bytes).
Se não definida, usa uma chave de demonstração — **adequado apenas para esta
entrega**, jamais para produção.

```bash
# PowerShell
$env:ORBITAL_TRUST_KEY = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
dotnet run

# bash
export ORBITAL_TRUST_KEY=$(openssl rand -base64 32)
dotnet run
```

### Rodando os testes

```bash
cd tests/CryptoService.Tests
dotnet test
```

### Output esperado

```text
╔══════════════════════════════════════════════════════╗
║     ORBITAL TRUST — CryptoService  |  GS 2026        ║
║     Cibersegurança 1  ·  FIAP  ·  Turma 3ESR         ║
╚══════════════════════════════════════════════════════╝

[ CENÁRIO 1 ]  Campo: SensorTerrestre.Coordenada
  Original              : -23.5505, -46.6333
  Criptografado (Base64): <valor único a cada execução>
  Descriptografado      : -23.5505, -46.6333
  Integridade OK        : True

[ CENÁRIO 2 ]  Campo: SensorTerrestre.Coordenada (segundo sensor)
  Original              : -15.7801, -47.9292
  Criptografado (Base64): <valor único a cada execução>
  Descriptografado      : -15.7801, -47.9292
  Integridade OK        : True

[ CENÁRIO 3 ]  Tamper detection
  Adulteração detectada : CryptographicException lançada.
```

### Cenários demonstrados

| Cenário | O que prova                                                  |
|:-------:|--------------------------------------------------------------|
|    1    | Roundtrip Encrypt → Decrypt preserva o dado original         |
|    2    | Nonces aleatórios produzem ciphertexts distintos por execução|
|    3    | Adulteração de 1 byte → `CryptographicException` (AEAD)      |

---

## Banco de dados — coordenada cifrada em repouso (Docker)

Além do CryptoService standalone, o repositório demonstra o controle integrado a
um **banco real**: um PostgreSQL em Docker que persiste a coordenada **sempre
cifrada**. O app `DbSeed` reutiliza o mesmo `CryptoService`, grava as leituras e
relê do banco — provando que quem inspeciona a tabela vê apenas Base64.

```bash
# 1. Sobe o PostgreSQL (cria a tabela via db/init.sql)
docker compose up -d

# 2. Grava 2 leituras com a coordenada cifrada e relê do banco
dotnet run --project src/DbSeed

# 3. Prova de ouro: SELECT cru no banco — só se vê Base64, mesmo com acesso total
docker exec orbital-trust-db psql -U orbital -d orbital_trust \
  -c "SELECT id, sensor_nome, left(coordenada,44) AS no_banco FROM leituras_sensor;"

# Encerra e remove o volume
docker compose down -v
```

> **Por que isso importa:** o cenário do banco deixa de ser hipótese. Mesmo que um
> atacante comprometa o PostgreSQL e faça `SELECT *`, a coordenada exata de cada
> sensor permanece protegida — só a aplicação, de posse da chave, recupera o texto
> claro. É a mitigação de **Information Disclosure** em *data at rest*, tangível.

Evidência da execução em [`evidencias/output-banco.txt`](./evidencias/output-banco.txt)
e [`evidencias/print_banco.png`](./evidencias/print_banco.png).

---

## Decisões de design

| Decisão                                | Alternativa descartada        | Motivo                                                        |
|----------------------------------------|-------------------------------|---------------------------------------------------------------|
| AES-256-GCM (AEAD)                     | AES-CBC + HMAC                | GCM resolve tudo num único passo — sem risco de padding oracle|
| Nonce aleatório de 96 bits             | Nonce determinístico (contador)| Não exige estado compartilhado entre serviços                |
| Serialização `nonce ‖ tag ‖ cipher`    | Campos separados no banco     | Um único campo Base64 simplifica migração e ORM               |
| Tag de 128 bits                        | Tag de 96 / 112 bits          | Máxima resistência a forjamento sem custo significativo       |
| Chave estática no código (demo)        | Variável de ambiente / Vault  | Apenas para evidência de execução — ver seção abaixo          |

---

## Considerações para produção

Esta entrega é um **proof of concept** para a disciplina. Para deploy em
produção, o gerenciamento de chave precisa ser endereçado:

| Tópico                  | Estado atual              | Roadmap para produção                         |
|-------------------------|---------------------------|-----------------------------------------------|
| Origem da chave         | Constante no código       | Azure Key Vault / AWS KMS / HashiCorp Vault   |
| Rotação                 | Não aplicável             | Versionar chaves (header com `key_id`)        |
| Auditoria de acesso     | Inexistente               | Log de cada operação Encrypt/Decrypt          |
| Re-criptografia em massa| Não previsto              | Job de rotação batch com `key_id` versionado  |
| Hardening do binário    | Build padrão              | Assinatura de assembly + reproducible builds  |

> A chave de demonstração no código fonte está marcada com comentário explícito
> indicando que **não deve ser usada em produção**.

---

## Evidências

Ver pasta [`/evidencias`](./evidencias):

| Arquivo               | Conteúdo                                            |
|-----------------------|-----------------------------------------------------|
| `output.txt`          | Output do CryptoService — 3 cenários                 |
| `print_execucao.png`  | Screenshot do terminal — CryptoService              |
| `output-banco.txt`    | Gravação no PostgreSQL + SELECT cru (coordenada cifrada) |
| `print_banco.png`     | Screenshot — coordenada cifrada em repouso no banco |

---

## Bibliotecas utilizadas

| Biblioteca                      | Origem            | Observação                          |
|---------------------------------|-------------------|-------------------------------------|
| `System.Security.Cryptography`  | built-in .NET     | Núcleo do CryptoService — sem deps  |
| `System.Text`                   | built-in .NET     | Encoding UTF-8                      |
| `xUnit 2.9`                     | testes            | Apenas em `CryptoService.Tests`     |
| `Npgsql 8.0`                    | demo de banco     | Driver PostgreSQL — apenas no `DbSeed` |

O **CryptoService** (núcleo do controle) tem **zero dependências externas** — só a
BCL do .NET. O `Npgsql` é usado exclusivamente na demonstração de banco (`DbSeed`).

---

## Referências

- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) — *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*
- [NIST FIPS-197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) — *Advanced Encryption Standard (AES)*
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Microsoft Docs — `AesGcm` Class](https://learn.microsoft.com/dotnet/api/system.security.cryptography.aesgcm)
- [STRIDE Threat Model](https://learn.microsoft.com/azure/security/develop/threat-modeling-tool-threats) — Microsoft

---

## Integrantes

<div align="center">

| Nome                          | RM         |
|-------------------------------|:----------:|
| Victor Dias                   | RM558017   |
| Gustavo Paulino               | RM554779   |
| Guilherme Abe                 | RM554743   |
| Fernando Luiz                 | RM555201   |
| Thomas Reichmann              | RM554812   |

**FIAP · 3ESR · 2026**

</div>
