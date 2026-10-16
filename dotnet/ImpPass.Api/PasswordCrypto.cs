using System.Security.Cryptography;
using System.Text;

namespace ImpPass.Api;

public sealed class PasswordCrypto
{
    private const int Iterations = 100_000;
    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;

    public static string StableId(string value)
    {
        var hash = SHA1.HashData(Encoding.UTF8.GetBytes(value));
        return Base64UrlEncode(hash);
    }

    public static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Base64UrlDecode(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized += new string('=', (4 - normalized.Length % 4) % 4);
        return Convert.FromBase64String(normalized);
    }

    public static byte[] NewSalt() => RandomNumberGenerator.GetBytes(16);

    public static byte[] DeriveKey(string masterPassword, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(masterPassword),
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            KeyBytes);

    public static EncryptedValue Encrypt(string plaintext, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var input = Encoding.UTF8.GetBytes(plaintext);
        var cipher = new byte[input.Length];
        var tag = new byte[TagBytes];

        using var aes = new AesGcm(key, TagBytes);
        aes.Encrypt(nonce, input, cipher, tag);

        // Web Crypto stores ciphertext followed by the authentication tag.
        var combined = new byte[cipher.Length + tag.Length];
        Buffer.BlockCopy(cipher, 0, combined, 0, cipher.Length);
        Buffer.BlockCopy(tag, 0, combined, cipher.Length, tag.Length);

        return new EncryptedValue(Base64UrlEncode(combined), Base64UrlEncode(nonce));
    }

    public static string Decrypt(EncryptedValue value, byte[] key)
    {
        var combined = Base64UrlDecode(value.Cipher);
        var nonce = Base64UrlDecode(value.Iv);
        if (combined.Length < TagBytes)
            throw new CryptographicException("Encrypted value is incomplete.");

        var cipherLength = combined.Length - TagBytes;
        var cipher = combined[..cipherLength];
        var tag = combined[cipherLength..];
        var plaintext = new byte[cipherLength];

        using var aes = new AesGcm(key, TagBytes);
        aes.Decrypt(nonce, cipher, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }
}

public sealed record EncryptedValue(string Cipher, string Iv);
public sealed record SessionContext(string SessionId, string UserId, byte[] Key, long ExpireOn);
public sealed record PasswordRecord(string Id, string Pid, string Password);
