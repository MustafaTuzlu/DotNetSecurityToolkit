using System.Security.Cryptography;
using DotNetSecurityToolkit.Abstractions;

namespace DotNetSecurityToolkit.AntiForgery;

/// <summary>
/// Implements the double-submit cookie pattern using random tokens.
/// </summary>
public sealed class AntiForgeryService : IAntiForgeryService
{
    public AntiForgeryTokenPair IssueToken(string? subject = null, TimeSpan? lifetime = null)
    {
        var expires = DateTimeOffset.UtcNow.Add(lifetime ?? TimeSpan.FromHours(1));
        var cookieToken = CreateToken();
        var requestToken = CreateToken();
        return new AntiForgeryTokenPair(cookieToken, requestToken, expires);
    }

    public bool ValidateToken(string cookieToken, string requestToken, string? subject = null)
    {
        if (string.IsNullOrWhiteSpace(cookieToken) || string.IsNullOrWhiteSpace(requestToken))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Convert.FromBase64String(cookieToken),
            Convert.FromBase64String(requestToken));
    }

    private static string CreateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes);
    }
}
