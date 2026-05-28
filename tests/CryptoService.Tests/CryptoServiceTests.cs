using System.Security.Cryptography;
using OrbitalTrust.Security;
using Xunit;

namespace OrbitalTrust.Tests;

public class CryptoServiceTests
{
    [Theory]
    [InlineData("-23.5505, -46.6333")]
    [InlineData("-15.7801, -47.9292")]
    [InlineData("0.0, 0.0")]
    [InlineData("")]
    public void Encrypt_Decrypt_Roundtrip_PreservaDado(string original)
    {
        var cipher = CryptoService.Encrypt(original);
        var plain  = CryptoService.Decrypt(cipher);

        Assert.Equal(original, plain);
    }

    [Fact]
    public void Encrypt_ProduzCiphertextDiferenteParaMesmoInput()
    {
        const string input = "-23.5505, -46.6333";

        var a = CryptoService.Encrypt(input);
        var b = CryptoService.Encrypt(input);

        Assert.NotEqual(a, b); // nonces aleatórios garantem unicidade
    }

    [Fact]
    public void Decrypt_DadoAdulterado_LancaCryptographicException()
    {
        var cipher = CryptoService.Encrypt("-10.9472, -37.0731");
        var raw    = Convert.FromBase64String(cipher);
        raw[^1]   ^= 0xFF; // flip do último byte do ciphertext
        var tampered = Convert.ToBase64String(raw);

        Assert.ThrowsAny<CryptographicException>(() => CryptoService.Decrypt(tampered));
    }

    [Fact]
    public void Decrypt_NonceAdulterado_LancaCryptographicException()
    {
        var cipher = CryptoService.Encrypt("-10.9472, -37.0731");
        var raw    = Convert.FromBase64String(cipher);
        raw[0]    ^= 0xFF; // flip de byte do nonce
        var tampered = Convert.ToBase64String(raw);

        Assert.ThrowsAny<CryptographicException>(() => CryptoService.Decrypt(tampered));
    }

    [Fact]
    public void Decrypt_TagAdulterada_LancaCryptographicException()
    {
        var cipher = CryptoService.Encrypt("-10.9472, -37.0731");
        var raw    = Convert.FromBase64String(cipher);
        raw[12]   ^= 0xFF; // primeiro byte da tag (offset 12)
        var tampered = Convert.ToBase64String(raw);

        Assert.ThrowsAny<CryptographicException>(() => CryptoService.Decrypt(tampered));
    }

    [Fact]
    public void Encrypt_TamanhoMinimoEsperado()
    {
        var cipher = CryptoService.Encrypt("x");
        var raw    = Convert.FromBase64String(cipher);

        // 12 (nonce) + 16 (tag) + 1 (ciphertext de "x" em UTF-8) = 29
        Assert.Equal(29, raw.Length);
    }
}
