using DotNetSecurityToolkit.Abstractions;
using Microsoft.AspNetCore.Http;
using System.Text.Json;

namespace DotNetSecurityToolkit.Cookies;

/// <summary>
/// Secure, session-oriented cookie helper.
/// Values are encrypted using IEncryptionService.
/// </summary>
public sealed class CookieManager : ICookieManager
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IEncryptionService _encryptionService;

    public CookieManager(
        IHttpContextAccessor httpContextAccessor,
        IEncryptionService encryptionService)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
    }

    public void SetEncryptedCookie(string key, string value, DateTimeOffset? expires = null)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        var context = _httpContextAccessor.HttpContext
                      ?? throw new InvalidOperationException("No active HttpContext.");

        var encrypted = _encryptionService.Encrypt(value);

        context.Response.Cookies.Append(key, encrypted, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            IsEssential = true,
            Expires = expires
        });
    }

    public void SetEncryptedObjectCookie<T>(string key, T value, DateTimeOffset? expires = null, JsonSerializerOptions? serializerOptions = null)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        var serialized = JsonSerializer.Serialize(value, serializerOptions);
        SetEncryptedCookie(key, serialized, expires);
    }

    public string? GetDecryptedCookie(string key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        var context = _httpContextAccessor.HttpContext;
        if (context is null)
        {
            return null;
        }

        if (!context.Request.Cookies.TryGetValue(key, out var encrypted))
        {
            return null;
        }

        return _encryptionService.TryDecrypt(encrypted, out var decrypted)
            ? decrypted
            : null;
    }

    public string? GetDecryptedCookieOrDefault(string key, string? defaultValue = null)
    {
        var value = GetDecryptedCookie(key);
        return value ?? defaultValue;
    }

    public void DeleteCookie(string key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        var context = _httpContextAccessor.HttpContext;
        context?.Response.Cookies.Delete(key);
    }

    public void DeleteCookies(params string[] keys)
    {
        foreach (var key in keys)
        {
            DeleteCookie(key);
        }
    }

    public bool TryGetDecryptedCookie(string key, out string? value)
    {
        value = GetDecryptedCookie(key);
        return value != null;
    }

    public bool TryGetDecryptedObjectCookie<T>(string key, out T? value, JsonSerializerOptions? serializerOptions = null)
    {
        value = default;

        var context = _httpContextAccessor.HttpContext;
        if (context is null)
        {
            return false;
        }

        return context.Request.Cookies.TryGetValue(key, out var encrypted)
               && _encryptionService.TryDecryptObject(encrypted, out value, serializerOptions);
    }

    public bool CookieExists(string key)
    {
        var ctx = _httpContextAccessor.HttpContext;
        return ctx?.Request.Cookies.ContainsKey(key) ?? false;
    }

    public void RenewEncryptedCookie(string key, TimeSpan lifetime)
    {
        var value = GetDecryptedCookie(key);
        if (value != null)
        {
            SetEncryptedCookie(key, value, DateTimeOffset.UtcNow.Add(lifetime));
        }
    }

}
