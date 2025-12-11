using System.Security.Claims;
using System.Text.Json;

namespace DotNetSecurityToolkit.Abstractions;

/// <summary>
/// One-way password hashing abstraction.
/// </summary>
public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyHashedPassword(string hash, string password);

    /// <summary>
    /// Indicates whether a stored hash should be regenerated according to current options.
    /// </summary>
    bool NeedsRehash(string hash);

    /// <summary>
    /// Verifies the password and reports if a rehash is recommended.
    /// </summary>
    bool VerifyHashedPassword(string hash, string password, out bool needsRehash);

    /// <summary>
    /// Generates a random salt of the requested size.
    /// </summary>
    byte[] GenerateSalt(int size);

    /// <summary>
    /// Hashes a password using a caller supplied salt.
    /// </summary>
    string HashPasswordWithCustomSalt(string password, byte[] salt);

    /// <summary>
    /// Breaks the stored hash format into its components for diagnostics or migrations.
    /// </summary>
    (int Iterations, byte[] Salt, byte[] Key) ParseHashComponents(string hash);
}

/// <summary>
/// Symmetric encryption abstraction (two-way).
/// </summary>
public interface IEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);

    string EncryptBytes(byte[] data);
    byte[] DecryptBytes(string cipher);
    bool IsEncryptedPayload(string cipher);

    /// <summary>
    /// Serializes the provided value as JSON and encrypts it.
    /// </summary>
    string EncryptObject<T>(T value, JsonSerializerOptions? serializerOptions = null);

    /// <summary>
    /// Decrypts and deserializes the JSON payload.
    /// </summary>
    T? DecryptObject<T>(string cipherText, JsonSerializerOptions? serializerOptions = null);
}

/// <summary>
/// URL-safe text operations.
/// </summary>
public interface IUrlEncoder
{
    string ToUrlSafeBase64(byte[] data);
    byte[] FromUrlSafeBase64(string urlSafe);
    string Slugify(string input, int maxLength = 80);
    bool IsUrlSafeBase64(string value);
    string GenerateShortToken(int length = 12);
    string NormalizeForSlug(string text);
    string EncodeQueryValue(string value);
    string AppendQueryString(string baseUrl, IDictionary<string, string?> parameters);
    string EnsureTrailingSlash(string url);
    string CombinePathSegments(params string[] segments);
}

/// <summary>
/// Cookie helper abstraction. Designed for session-based, secure cookies.
/// </summary>
public interface ICookieManager
{
    void SetEncryptedCookie(string key, string value, DateTimeOffset? expires = null);
    string? GetDecryptedCookie(string key);
    void DeleteCookie(string key);

    bool TryGetDecryptedCookie(string key, out string? value);
    bool CookieExists(string key);
    void RenewEncryptedCookie(string key, TimeSpan lifetime);
    string? GetDecryptedCookieOrDefault(string key, string? defaultValue = null);
    void SetEncryptedObjectCookie<T>(string key, T value, DateTimeOffset? expires = null,
        JsonSerializerOptions? serializerOptions = null);
    bool TryGetDecryptedObjectCookie<T>(string key, out T? value, JsonSerializerOptions? serializerOptions = null);
    void DeleteCookies(params string[] keys);
}

/// <summary>
/// JWT token creation abstraction for issuing access tokens.
/// </summary>
public interface IJwtTokenService
{
    string CreateToken(IEnumerable<Claim> claims, DateTime? expires = null);

    /// <summary>
    /// Convenience overload that accepts a dictionary and converts it to claims.
    /// </summary>
    string CreateTokenFromDictionary(IDictionary<string, string?> claims, DateTime? expires = null);

    /// <summary>
    /// Creates a secure random refresh token.
    /// </summary>
    string CreateRefreshToken(int byteLength = 32);

    /// <summary>
    /// Validates a JWT and returns the resulting principal when valid.
    /// </summary>
    ClaimsPrincipal? ValidateToken(string token, bool validateLifetime = true);
}

/// <summary>
/// Session helper abstraction for storing typed values securely.
/// </summary>
public interface ISessionManager
{
    void SetString(string key, string value);
    string? GetString(string key);
    void SetObject<T>(string key, T value, JsonSerializerOptions? serializerOptions = null);
    bool TryGetObject<T>(string key, out T? value, JsonSerializerOptions? serializerOptions = null);
    void Remove(string key);
    void Clear();
    bool ContainsKey(string key);
    string GetOrCreateSessionToken(string tokenKey = "session-token", int byteLength = 24);
    void SetEncrypted(string key, string plainText);
    string? GetDecrypted(string key);
}
