using System.Security.Cryptography;
using System.Text;

namespace OrbitalTrust.Security;

/// <summary>
/// Serviço de criptografia AES-256-GCM para campos sensíveis do Orbital Trust.
/// Aplica-se ao campo Coordenada da entidade SensorTerrestre antes de persistir no banco.
/// Modo GCM escolhido sobre CBC por incluir autenticação embutida (AEAD),
/// eliminando vulnerabilidades de padding oracle sem custo adicional.
/// </summary>
public static class CryptoService
{
    // Em produção: carregar de variável de ambiente ou Azure Key Vault
    // Aqui geramos uma chave estática de demonstração para evidência de execução
    private static readonly byte[] _key = Convert.FromBase64String(
        "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="); // 256-bit demo key

    /// <summary>
    /// Criptografa um dado sensível com AES-256-GCM.
    /// Retorna string Base64 contendo nonce (12 bytes) | tag (16 bytes) | ciphertext.
    /// </summary>
    public static string Encrypt(string plaintext)
    {
        using var aes = new AesGcm(_key, 16); // tag 128 bits
        var nonce  = new byte[12];             // nonce 96 bits — padrão recomendado para GCM
        var tag    = new byte[16];
        var input  = Encoding.UTF8.GetBytes(plaintext);
        var cipher = new byte[input.Length];

        RandomNumberGenerator.Fill(nonce);
        aes.Encrypt(nonce, input, cipher, tag);

        // Serialização: nonce (12) | tag (16) | ciphertext → Base64
        // Estrutura garante que Decrypt possa extrair cada componente por offset fixo
        return Convert.ToBase64String(
            nonce.Concat(tag).Concat(cipher).ToArray());
    }

    /// <summary>
    /// Descriptografa e autentica um campo previamente criptografado por Encrypt().
    /// Lança CryptographicException se o dado foi adulterado (autenticação GCM falha).
    /// </summary>
    public static string Decrypt(string b64)
    {
        var data   = Convert.FromBase64String(b64);
        var nonce  = data[..12];
        var tag    = data[12..28];
        var cipher = data[28..];
        var plain  = new byte[cipher.Length];

        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(nonce, cipher, tag, plain); // lança se tag inválida

        return Encoding.UTF8.GetString(plain);
    }
}
