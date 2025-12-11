using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DotNetSecurityToolkit.Crypto;

/// <summary>
/// AES-256-CBC based encryption service.
/// Uses SecurityToolkitOptions.SecretKey as the base key material.
/// Output is URL-safe Base64 encoded.
/// </summary>
public sealed class AesEncryptionService : IEncryptionService
{
    private static readonly byte[] FormatMarker = Encoding.ASCII.GetBytes("DST1");
    private const int HmacSize = 32; // HMACSHA256 output size

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

        var cipherBytes = EncryptToBytes(plainText, out var iv);

        var macInput = new byte[FormatMarker.Length + iv.Length + cipherBytes.Length];
        Buffer.BlockCopy(FormatMarker, 0, macInput, 0, FormatMarker.Length);
        Buffer.BlockCopy(iv, 0, macInput, FormatMarker.Length, iv.Length);
        Buffer.BlockCopy(cipherBytes, 0, macInput, FormatMarker.Length + iv.Length, cipherBytes.Length);

        using var hmac = new HMACSHA256(_keyBytes);
        var tag = hmac.ComputeHash(macInput);

        var payload = new byte[macInput.Length + tag.Length];
        Buffer.BlockCopy(macInput, 0, payload, 0, macInput.Length);
        Buffer.BlockCopy(tag, 0, payload, macInput.Length, tag.Length);

        return _urlEncoder.ToUrlSafeBase64(payload);
    }

    public string Decrypt(string cipherText)
    {
        if (cipherText is null)
        {
            throw new ArgumentNullException(nameof(cipherText));
        }

        var combined = _urlEncoder.FromUrlSafeBase64(cipherText);

        if (IsVersionedPayload(combined))
        {
            return DecryptVersionedPayload(combined);
        }

        return DecryptLegacyPayload(combined);
    }

    public bool TryDecrypt(string cipherText, out string? plainText)
    {
        try
        {
            plainText = Decrypt(cipherText);
            return true;
        }
        catch
        {
            plainText = null;
            return false;
        }
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
            return IsVersionedPayload(raw) || raw.Length > 16; // IV(16) + data
        }
        catch
        {
            return false;
        }
    }

    public bool TryDecryptObject<T>(string cipherText, out T? value, JsonSerializerOptions? serializerOptions = null)
    {
        value = default;

        if (!TryDecrypt(cipherText, out var plainText) || plainText is null)
        {
            return false;
        }

        try
        {
            value = JsonSerializer.Deserialize<T>(plainText, serializerOptions);
            return value is not null;
        }
        catch
        {
            value = default;
            return false;
        }
    }

    public string EncryptObject<T>(T value, JsonSerializerOptions? serializerOptions = null)
    {
        var json = JsonSerializer.Serialize(value, serializerOptions);
        return Encrypt(json);
    }

    public T? DecryptObject<T>(string cipherText, JsonSerializerOptions? serializerOptions = null)
    {
        var json = Decrypt(cipherText);
        return JsonSerializer.Deserialize<T>(json, serializerOptions);
    }

    private byte[] EncryptToBytes(string plainText, out byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = _keyBytes;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        aes.GenerateIV();
        iv = aes.IV;

        using var encryptor = aes.CreateEncryptor(aes.Key, iv);
        using var ms = new MemoryStream();
        using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var writer = new StreamWriter(cryptoStream, Encoding.UTF8))
        {
            writer.Write(plainText);
        }

        return ms.ToArray();
    }

    private string DecryptLegacyPayload(byte[] combined)
    {
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

        return DecryptWithParameters(iv, cipher);
    }

    private string DecryptVersionedPayload(byte[] payload)
    {
        using var aes = Aes.Create();
        var ivLength = aes.BlockSize / 8;
        var macInputLength = payload.Length - HmacSize;

        if (macInputLength <= FormatMarker.Length + ivLength)
        {
            throw new CryptographicException("Cipher text is too short.");
        }

        var macInput = new byte[macInputLength];
        Buffer.BlockCopy(payload, 0, macInput, 0, macInputLength);

        var expectedTag = new byte[HmacSize];
        Buffer.BlockCopy(payload, macInputLength, expectedTag, 0, HmacSize);

        using var hmac = new HMACSHA256(_keyBytes);
        var actualTag = hmac.ComputeHash(macInput);
        if (!CryptographicOperations.FixedTimeEquals(expectedTag, actualTag))
        {
            throw new CryptographicException("Cipher text failed integrity validation.");
        }

        var iv = new byte[ivLength];
        Buffer.BlockCopy(payload, FormatMarker.Length, iv, 0, ivLength);

        var cipherLength = macInputLength - FormatMarker.Length - ivLength;
        var cipher = new byte[cipherLength];
        Buffer.BlockCopy(payload, FormatMarker.Length + ivLength, cipher, 0, cipherLength);

        return DecryptWithParameters(iv, cipher);
    }

    private static bool IsVersionedPayload(byte[] combined)
    {
        if (combined.Length < FormatMarker.Length + HmacSize + 16)
        {
            return false;
        }

        for (var i = 0; i < FormatMarker.Length; i++)
        {
            if (combined[i] != FormatMarker[i])
            {
                return false;
            }
        }

        return true;
    }

    private string DecryptWithParameters(byte[] iv, byte[] cipher)
    {
        using var aes = Aes.Create();
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

}
