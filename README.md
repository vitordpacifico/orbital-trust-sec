# orbital-trust-sec

Módulo de Cibersegurança do projeto **Orbital Trust** — Global Solution 1º Semestre 2026.

## Sobre o projeto

O Orbital Trust é uma plataforma de monitoramento ambiental que combina dados satelitais
com sensores visuais terrestres para gerar alertas confiáveis sobre queimadas,
desmatamento, enchentes e seca. O diferencial é o **Índice de Confiabilidade Orbital (ICO)**,
que cruza a análise do modelo de Machine Learning com a detecção visual em tempo real.

## Sobre este repositório

Implementação prática do módulo de cibersegurança entregue na disciplina
**Cibersegurança 1** (Prof. MSc. Oerton Fernandes), integrada ao projeto da GS.

## Implementação prática — AES-256-GCM

Implementamos criptografia **AES-256-GCM** no campo `Coordenada` da entidade
`SensorTerrestre`. Dados de localização de sensores são criptografados antes de
persistir no banco de dados, mitigando **Information Disclosure** em caso de acesso
indevido ao banco.

**Por que GCM e não CBC?**
O modo GCM inclui autenticação embutida (AEAD — Authenticated Encryption with
Associated Data). Se um atacante adulterar o dado no banco, o Decrypt lança
`CryptographicException` antes de retornar qualquer dado. Isso elimina a classe de
ataques de padding oracle presente no modo CBC sem custo adicional de performance.

## Como a segurança está integrada ao Orbital Trust

| # | Controle | Tipo | Aplica em |
|---|---|---|---|
| 1 | TLS/HTTPS obrigatório | Preventivo | API de Alertas |
| 2 | Autenticação + Roles IAM | Preventivo | API — sensor_node / analyst / admin |
| 3 | **AES-256-GCM em coordenadas** | **Preventivo** | **Banco — campo Coordenada** ← este repo |
| 4 | Monitoramento de logs | Detectivo | API + Banco |
| 5 | mTLS para IoT | Preventivo | Nó Sensor / Câmera |

## Como rodar

**Requisito:** .NET 8 ou superior

```bash
cd src/CryptoService
dotnet run
```

**Output esperado:**

```
╔══════════════════════════════════════════════════════╗
║     ORBITAL TRUST — CryptoService  |  GS 2026       ║
╚══════════════════════════════════════════════════════╝

[ CENÁRIO 1 ]  Campo: SensorTerrestre.Coordenada
  Original    : -23.5505, -46.6333
  Criptografado (Base64): <valor único a cada execução>
  Descriptografado: -23.5505, -46.6333
  Integridade OK  : True

[ CENÁRIO 3 ]  Tamper detection
  Adulteração detectada: CryptographicException lançada.
```

## Evidências

Ver pasta `/evidencias`:
- `output.txt` — output completo da execução
- `print_execucao.png` — screenshot do terminal

## Bibliotecas utilizadas

- `System.Security.Cryptography` — built-in .NET 8, sem dependências externas
- `System.Text` — built-in .NET 8

## Integrantes

| Nome | RM |
|---|---|
| Victor Dias | RM558017 |
| Gustavo Paulino | RM554779 |
