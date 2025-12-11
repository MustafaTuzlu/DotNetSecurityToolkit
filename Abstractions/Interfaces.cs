using System.Security.Claims;

namespace DotNetSecurityToolkit.Abstractions;

/// <summary>
/// One-way password hashing abstraction.
/// </summary>
public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyHashedPassword(string hash, string password);
}

/// <summary>
/// Symmetric encryption abstraction (two-way).
/// </summary>
public interface IEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
}

/// <summary>
/// URL-safe text operations.
/// </summary>
public interface IUrlEncoder
{
    string ToUrlSafeBase64(byte[] data);
    byte[] FromUrlSafeBase64(string urlSafe);
    string Slugify(string input, int maxLength = 80);
}

/// <summary>
/// Cookie helper abstraction. Designed for session-based, secure cookies.
/// </summary>
public interface ICookieManager
{
    void SetEncryptedCookie(string key, string value, DateTimeOffset? expires = null);
    string? GetDecryptedCookie(string key);
    void DeleteCookie(string key);

}

/// <summary>
/// JWT token creation abstraction for issuing access tokens.
/// </summary>
public interface IJwtTokenService
{
    string CreateToken(IEnumerable<Claim> claims, DateTime? expires = null);
}
