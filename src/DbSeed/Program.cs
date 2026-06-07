using Npgsql;
using OrbitalTrust.Security;

// ─────────────────────────────────────────────────────────────────────────────
//  Orbital Trust · Demo de criptografia em repouso (data at rest)
//
//  Prova prática de que a coordenada do sensor é persistida SEMPRE cifrada:
//   1. Grava duas leituras no PostgreSQL com a coordenada passada por Encrypt().
//   2. Lê a coluna `coordenada` crua (o que está fisicamente no banco) → Base64.
//   3. Decifra com Decrypt() para mostrar o roundtrip — só a aplicação, de posse
//      da chave, recupera o texto claro.
//
//  Pré-requisito: `docker compose up -d` (PostgreSQL no ar).
// ─────────────────────────────────────────────────────────────────────────────

Console.OutputEncoding = System.Text.Encoding.UTF8;

// Connection string: aceita override por env var, default casa com o docker-compose.
string connString = Environment.GetEnvironmentVariable("ORBITAL_TRUST_DB")
    ?? "Host=localhost;Port=5432;Username=orbital;Password=orbital;Database=orbital_trust";

Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║   ORBITAL TRUST — Coordenada cifrada no banco (data at rest)  ║");
Console.WriteLine("║   Cibersegurança 1  ·  FIAP  ·  Turma 3ESR                    ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
Console.WriteLine();

await using var dataSource = new NpgsqlDataSourceBuilder(connString).Build();
await using var conn = await dataSource.OpenConnectionAsync();

// ── Limpa execuções anteriores para a demo ser idempotente
await using (var truncate = new NpgsqlCommand("TRUNCATE leituras_sensor RESTART IDENTITY;", conn))
    await truncate.ExecuteNonQueryAsync();

// ── Leituras de exemplo (coordenadas fictícias de sensores terrestres)
var leituras = new (string Sensor, string Coordenada)[]
{
    ("sensor-sp-01",  "-23.5505, -46.6333"), // São Paulo
    ("sensor-bsb-02", "-15.7801, -47.9292"), // Brasília
};

Console.WriteLine("[ 1 ]  Gravando leituras — coordenada cifrada ANTES de persistir");
Console.WriteLine("────────────────────────────────────────────────────────────────");
foreach (var (sensor, coord) in leituras)
{
    // A coordenada é cifrada AQUI; o banco nunca vê o texto claro.
    string cifrada = CryptoService.Encrypt(coord);

    await using var insert = new NpgsqlCommand(
        "INSERT INTO leituras_sensor (sensor_nome, coordenada) VALUES (@s, @c);", conn);
    insert.Parameters.AddWithValue("s", sensor);
    insert.Parameters.AddWithValue("c", cifrada);
    await insert.ExecuteNonQueryAsync();

    Console.WriteLine($"  {sensor,-14}  texto claro  : {coord}");
    Console.WriteLine($"  {"",-14}  → gravado    : {Trunc(cifrada, 52)}");
    Console.WriteLine();
}

Console.WriteLine("[ 2 ]  SELECT direto no banco — o que está fisicamente armazenado");
Console.WriteLine("────────────────────────────────────────────────────────────────");
Console.WriteLine("  (mesmo com acesso total ao banco, só se vê Base64 ilegível)");
Console.WriteLine();

await using (var select = new NpgsqlCommand(
    "SELECT id, sensor_nome, coordenada FROM leituras_sensor ORDER BY id;", conn))
await using (var reader = await select.ExecuteReaderAsync())
{
    while (await reader.ReadAsync())
    {
        int id        = reader.GetInt32(0);
        string sensor = reader.GetString(1);
        string armaz  = reader.GetString(2);            // o que está NO banco
        string claro  = CryptoService.Decrypt(armaz);   // só a app recupera

        Console.WriteLine($"  #{id} {sensor}");
        Console.WriteLine($"     no banco  (cifrado) : {Trunc(armaz, 50)}");
        Console.WriteLine($"     decifrado pela app  : {claro}");
        Console.WriteLine();
    }
}

Console.WriteLine("════════════════════════════════════════════════════════════════");
Console.WriteLine("  Coordenada protegida em repouso com AES-256-GCM.");
Console.WriteLine("  Mitiga Information Disclosure mesmo com o banco comprometido.");
Console.WriteLine("════════════════════════════════════════════════════════════════");

static string Trunc(string s, int max) => s.Length <= max ? s : s[..max] + "…";
