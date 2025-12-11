using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace DotNetSecurityToolkit.Crypto;

/// <summary>
/// AES-256-CBC based encryption service.
/// Uses SecurityToolkitOptions.SecretKey as the base key material.
/// Output is URL-safe Base64 encoded.
/// </summary>
public sealed class AesEncryptionService : IEncryptionService
{
    private readonly SecurityToolkitOptions _options;
    private readonly IUrlEncoder _urlEncoder;
    private readonly byte[] _keyBytes;

    public AesEncryptionService(IOptions<SecurityToolkitOptions> options, IUrlEncoder urlEncoder)
    {
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
        _urlEncoder = urlEncoder ?? throw new ArgumentNullException(nameof(urlEncoder));

        if (string.IsNullOrWhiteSpace(_options.SecretKey))
        {
            throw new InvalidOperationException(
                "SecurityToolkitOptions.SecretKey must be configured in appsettings.json (section 'DotNetSecurityToolkit').");
        }

        // Derive a 256-bit key from the configured SecretKey using SHA256.
        using var sha = SHA256.Create();
        _keyBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(_options.SecretKey));
    }

    public string Encrypt(string plainText)
    {
        if (plainText is null)
        {
            throw new ArgumentNullException(nameof(plainText));
        }

        using var aes = Aes.Create();
        aes.Key = _keyBytes;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        aes.GenerateIV();
        var iv = aes.IV;

        using var encryptor = aes.CreateEncryptor(aes.Key, iv);
        using var ms = new MemoryStream();
        using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var writer = new StreamWriter(cryptoStream, Encoding.UTF8))
        {
            writer.Write(plainText);
        }

        var cipherBytes = ms.ToArray();

        // Concatenate IV + cipher and encode as URL-safe Base64.
        var combined = new byte[iv.Length + cipherBytes.Length];
        Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
        Buffer.BlockCopy(cipherBytes, 0, combined, iv.Length, cipherBytes.Length);

        return _urlEncoder.ToUrlSafeBase64(combined);
    }

    public string Decrypt(string cipherText)
    {
        if (cipherText is null)
        {
            throw new ArgumentNullException(nameof(cipherText));
        }

        var combined = _urlEncoder.FromUrlSafeBase64(cipherText);

        // Extract IV + cipher from combined bytes.
        using var aes = Aes.Create();
        var ivLength = aes.BlockSize / 8;
        if (combined.Length < ivLength)
        {
            throw new CryptographicException("Invalid cipher text.");
        }

        var iv = new byte[ivLength];
        var cipher = new byte[combined.Length - ivLength];

        Buffer.BlockCopy(combined, 0, iv, 0, ivLength);
        Buffer.BlockCopy(combined, ivLength, cipher, 0, cipher.Length);

        aes.Key = _keyBytes;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(cipher);
        using var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var reader = new StreamReader(cryptoStream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    public string EncryptBytes(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        var plain = Convert.ToBase64String(data);
        return Encrypt(plain);
    }

    public byte[] DecryptBytes(string cipher)
    {
        var plain = Decrypt(cipher);
        return Convert.FromBase64String(plain);
    }

    public bool IsEncryptedPayload(string cipher)
    {
        try
        {
            var raw = _urlEncoder.FromUrlSafeBase64(cipher);
            return raw.Length > 16; // IV(16) + data
        }
        catch
        {
            return false;
        }
    }

}
