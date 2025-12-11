using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DotNetSecurityToolkit.Crypto;

/// <summary>
/// AES-256-CBC based encryption service with key rotation support.
/// Uses SecurityToolkitOptions.SecretKey or the configured key ring as the base key material.
/// Output is URL-safe Base64 encoded.
/// </summary>
public sealed class AesEncryptionService : IEncryptionService
{
    private static readonly byte[] FormatMarker = Encoding.ASCII.GetBytes("DST1");
    private const int HmacSize = 32; // HMACSHA256 output size

    private readonly IUrlEncoder _urlEncoder;
    private readonly IKeyRing _keyRing;

    public AesEncryptionService(
        IOptions<SecurityToolkitOptions> options,
        IUrlEncoder urlEncoder,
        IKeyRing keyRing)
    {
        _ = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _urlEncoder = urlEncoder ?? throw new ArgumentNullException(nameof(urlEncoder));
        _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));
    }

    public string Encrypt(string plainText)
    {
        if (plainText is null)
        {
            throw new ArgumentNullException(nameof(plainText));
        }

        var keyBytes = DeriveKeyBytes(_keyRing.GetCurrent(KeyPurpose.Encryption).Value);
        var cipherBytes = EncryptToBytes(plainText, keyBytes, out var iv);

        var macInput = new byte[FormatMarker.Length + iv.Length + cipherBytes.Length];
        Buffer.BlockCopy(FormatMarker, 0, macInput, 0, FormatMarker.Length);
        Buffer.BlockCopy(iv, 0, macInput, FormatMarker.Length, iv.Length);
        Buffer.BlockCopy(cipherBytes, 0, macInput, FormatMarker.Length + iv.Length, cipherBytes.Length);

        using var hmac = new HMACSHA256(keyBytes);
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
        var candidates = GetEncryptionKeys();

        foreach (var key in candidates)
        {
            try
            {
                if (IsVersionedPayload(combined))
                {
                    return DecryptVersionedPayload(combined, key);
                }

                return DecryptLegacyPayload(combined, key);
            }
            catch (CryptographicException)
            {
                // try next candidate
            }
        }

        throw new CryptographicException("Unable to decrypt payload with available keys.");
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

    private byte[] EncryptToBytes(string plainText, byte[] keyBytes, out byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = keyBytes;
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

    private string DecryptLegacyPayload(byte[] combined, byte[] keyBytes)
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

        return DecryptWithParameters(iv, cipher, keyBytes);
    }

    private string DecryptVersionedPayload(byte[] payload, byte[] keyBytes)
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

        using var hmac = new HMACSHA256(keyBytes);
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

        return DecryptWithParameters(iv, cipher, keyBytes);
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

    private string DecryptWithParameters(byte[] iv, byte[] cipher, byte[] keyBytes)
    {
        using var aes = Aes.Create();
        aes.Key = keyBytes;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(cipher);
        using var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var reader = new StreamReader(cryptoStream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private IEnumerable<byte[]> GetEncryptionKeys()
    {
        var keys = _keyRing.GetAll(KeyPurpose.Encryption).ToList();
        if (!keys.Any())
        {
            throw new InvalidOperationException("No encryption keys available.");
        }

        foreach (var material in keys)
        {
            yield return DeriveKeyBytes(material.Value);
        }
    }

    private static byte[] DeriveKeyBytes(string keyValue)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(Encoding.UTF8.GetBytes(keyValue));
    }
}
