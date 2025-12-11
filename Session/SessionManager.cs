using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DotNetSecurityToolkit.Abstractions;
using Microsoft.AspNetCore.Http;

namespace DotNetSecurityToolkit.Session;

/// <summary>
/// Session-based helper for storing raw, encrypted, or typed values.
/// </summary>
public sealed class SessionManager : ISessionManager
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IEncryptionService _encryptionService;

    public SessionManager(IHttpContextAccessor httpContextAccessor, IEncryptionService encryptionService)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
    }

    public void SetString(string key, string value)
    {
        var session = GetSessionOrThrow();
        session.SetString(key, value);
    }

    public string? GetString(string key)
    {
        var session = _httpContextAccessor.HttpContext?.Session;
        return session?.GetString(key);
    }

    public void SetObject<T>(string key, T value, JsonSerializerOptions? serializerOptions = null)
    {
        var json = JsonSerializer.Serialize(value, serializerOptions);
        SetString(key, json);
    }

    public bool TryGetObject<T>(string key, out T? value, JsonSerializerOptions? serializerOptions = null)
    {
        var json = GetString(key);
        if (json is null)
        {
            value = default;
            return false;
        }

        try
        {
            value = JsonSerializer.Deserialize<T>(json, serializerOptions);
            return value is not null;
        }
        catch
        {
            value = default;
            return false;
        }
    }

    public void Remove(string key)
    {
        var session = GetSessionOrThrow();
        session.Remove(key);
    }

    public void Clear()
    {
        var session = GetSessionOrThrow();
        session.Clear();
    }

    public bool ContainsKey(string key)
    {
        var session = _httpContextAccessor.HttpContext?.Session;
        return session?.TryGetValue(key, out _) ?? false;
    }

    public string GetOrCreateSessionToken(string tokenKey = "session-token", int byteLength = 24)
    {
        var session = GetSessionOrThrow();
        if (session.TryGetValue(tokenKey, out var existing))
        {
            return Encoding.UTF8.GetString(existing);
        }

        var tokenBytes = RandomNumberGenerator.GetBytes(byteLength);
        var token = Convert.ToHexString(tokenBytes);
        session.SetString(tokenKey, token);
        return token;
    }

    public void SetEncrypted(string key, string plainText)
    {
        var cipher = _encryptionService.Encrypt(plainText);
        SetString(key, cipher);
    }

    public string? GetDecrypted(string key)
    {
        var cipher = GetString(key);
        if (cipher is null)
        {
            return null;
        }
        
        try
        {
            return _encryptionService.Decrypt(cipher);
        }
        catch
        {
            return null;
        }
    }

    private ISession GetSessionOrThrow()
    {
        var context = _httpContextAccessor.HttpContext
                      ?? throw new InvalidOperationException("No active HttpContext.");

        return context.Session;
    }
}
