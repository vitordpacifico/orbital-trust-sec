using OrbitalTrust.Security;

Console.OutputEncoding = System.Text.Encoding.UTF8;

Console.WriteLine("╔══════════════════════════════════════════════════════╗");
Console.WriteLine("║     ORBITAL TRUST — CryptoService  |  GS 2026       ║");
Console.WriteLine("║     Cibersegurança 1  ·  FIAP  ·  Turma 3ESR        ║");
Console.WriteLine("╚══════════════════════════════════════════════════════╝");
Console.WriteLine();

// ── Cenário 1: coordenada de sensor terrestre (dado sensível)
Console.WriteLine("[ CENÁRIO 1 ]  Campo: SensorTerrestre.Coordenada");
Console.WriteLine("──────────────────────────────────────────────────────");

string coordenada = "-23.5505, -46.6333"; // São Paulo — coordenada fictícia de sensor
Console.WriteLine($"  Original    : {coordenada}");

string encCoord = CryptoService.Encrypt(coordenada);
Console.WriteLine($"  Criptografado (Base64):");
Console.WriteLine($"  {encCoord}");

string decCoord = CryptoService.Decrypt(encCoord);
Console.WriteLine($"  Descriptografado: {decCoord}");
Console.WriteLine($"  Integridade OK  : {coordenada == decCoord}");
Console.WriteLine();

// ── Cenário 2: segundo sensor com coordenada diferente
Console.WriteLine("[ CENÁRIO 2 ]  Campo: SensorTerrestre.Coordenada (segundo sensor)");
Console.WriteLine("──────────────────────────────────────────────────────");

string coordenada2 = "-15.7801, -47.9292"; // Brasília — coordenada fictícia
Console.WriteLine($"  Original    : {coordenada2}");

string encCoord2 = CryptoService.Encrypt(coordenada2);
Console.WriteLine($"  Criptografado (Base64):");
Console.WriteLine($"  {encCoord2}");

string decCoord2 = CryptoService.Decrypt(encCoord2);
Console.WriteLine($"  Descriptografado: {decCoord2}");
Console.WriteLine($"  Integridade OK  : {coordenada2 == decCoord2}");
Console.WriteLine();

// ── Cenário 3: tentativa de adulteração (tamper detection)
Console.WriteLine("[ CENÁRIO 3 ]  Tamper detection — autenticação GCM");
Console.WriteLine("──────────────────────────────────────────────────────");

string enc = CryptoService.Encrypt("-10.9472, -37.0731");
byte[] raw = Convert.FromBase64String(enc);
raw[^1] ^= 0xFF; // flip do último byte do ciphertext — Base64 segue válida, mas GCM rejeita
string tamperedB64 = Convert.ToBase64String(raw);

try
{
    CryptoService.Decrypt(tamperedB64);
    Console.WriteLine("  FALHA: dado adulterado não foi detectado.");
}
catch (System.Security.Cryptography.CryptographicException)
{
    Console.WriteLine("  Adulteração detectada: CryptographicException lançada.");
    Console.WriteLine("  Modo GCM rejeita dados com tag inválida — proteção contra Tampering.");
}

Console.WriteLine();
Console.WriteLine("══════════════════════════════════════════════════════");
Console.WriteLine("  AES-256-GCM integrado ao Orbital Trust com sucesso.");
Console.WriteLine("  Controle aplicado: Banco de Dados — campo Coordenada.");
Console.WriteLine("  Mitiga: Information Disclosure + Tampering no banco.");
Console.WriteLine("══════════════════════════════════════════════════════");
