using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace DotNetSecurityToolkit.Crypto;

/// <summary>
/// Chooses between Data Protection and AES encryption services while maintaining backward compatibility.
/// </summary>
public sealed class CompositeEncryptionService : IEncryptionService
{
    private readonly DataProtectionEncryptionService _dataProtection;
    private readonly AesEncryptionService _aes;
    private readonly SecurityToolkitOptions _options;

    public CompositeEncryptionService(
        DataProtectionEncryptionService dataProtection,
        AesEncryptionService aes,
        IOptions<SecurityToolkitOptions> options)
    {
        _dataProtection = dataProtection ?? throw new ArgumentNullException(nameof(dataProtection));
        _aes = aes ?? throw new ArgumentNullException(nameof(aes));
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
    }

    private IEncryptionService Active => _options.PreferDataProtection ? _dataProtection : _aes;

    public string Decrypt(string cipherText)
    {
        try
        {
            return Active.Decrypt(cipherText);
        }
        catch
        {
            return _aes.Decrypt(cipherText);
        }
    }

    public byte[] DecryptBytes(string cipher)
    {
        return Convert.FromBase64String(Decrypt(cipher));
    }

    public T? DecryptObject<T>(string cipherText, JsonSerializerOptions? serializerOptions = null)
    {
        return Active.DecryptObject<T>(cipherText, serializerOptions);
    }

    public string Encrypt(string plainText)
    {
        return Active.Encrypt(plainText);
    }

    public string EncryptBytes(byte[] data)
    {
        return Active.EncryptBytes(data);
    }

    public string EncryptObject<T>(T value, JsonSerializerOptions? serializerOptions = null)
    {
        return Active.EncryptObject(value, serializerOptions);
    }

    public bool IsEncryptedPayload(string cipher)
    {
        return Active.IsEncryptedPayload(cipher) || _aes.IsEncryptedPayload(cipher);
    }

    public bool TryDecrypt(string cipherText, out string? plainText)
    {
        if (Active.TryDecrypt(cipherText, out plainText))
        {
            return true;
        }

        return _aes.TryDecrypt(cipherText, out plainText);
    }

    public bool TryDecryptObject<T>(string cipherText, out T? value, JsonSerializerOptions? serializerOptions = null)
    {
        if (Active.TryDecryptObject(cipherText, out value, serializerOptions))
        {
            return true;
        }

        return _aes.TryDecryptObject(cipherText, out value, serializerOptions);
    }
}
