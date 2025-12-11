using DotNetSecurityToolkit.Abstractions;
using Microsoft.AspNetCore.DataProtection;
using System.Text.Json;

namespace DotNetSecurityToolkit.Crypto;

/// <summary>
/// IEncryptionService implementation backed by ASP.NET Core Data Protection.
/// </summary>
public sealed class DataProtectionEncryptionService : IEncryptionService
{
    private readonly IDataProtector _protector;

    public DataProtectionEncryptionService(IDataProtectionProvider dataProtectionProvider)
    {
        if (dataProtectionProvider is null)
        {
            throw new ArgumentNullException(nameof(dataProtectionProvider));
        }

        _protector = dataProtectionProvider.CreateProtector("DotNetSecurityToolkit.Encryption");
    }

    public string Decrypt(string cipherText)
    {
        return _protector.Unprotect(cipherText);
    }

    public byte[] DecryptBytes(string cipher)
    {
        var plaintext = Decrypt(cipher);
        return Convert.FromBase64String(plaintext);
    }

    public T? DecryptObject<T>(string cipherText, JsonSerializerOptions? serializerOptions = null)
    {
        var json = Decrypt(cipherText);
        return JsonSerializer.Deserialize<T>(json, serializerOptions);
    }

    public string Encrypt(string plainText)
    {
        return _protector.Protect(plainText);
    }

    public string EncryptBytes(byte[] data)
    {
        var payload = Convert.ToBase64String(data);
        return Encrypt(payload);
    }

    public string EncryptObject<T>(T value, JsonSerializerOptions? serializerOptions = null)
    {
        var json = JsonSerializer.Serialize(value, serializerOptions);
        return Encrypt(json);
    }

    public bool IsEncryptedPayload(string cipher)
    {
        return !string.IsNullOrWhiteSpace(cipher);
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

    public bool TryDecryptObject<T>(string cipherText, out T? value, JsonSerializerOptions? serializerOptions = null)
    {
        if (TryDecrypt(cipherText, out var plain) && plain is not null)
        {
            try
            {
                value = JsonSerializer.Deserialize<T>(plain, serializerOptions);
                return value is not null;
            }
            catch
            {
                value = default;
                return false;
            }
        }

        value = default;
        return false;
    }
}
