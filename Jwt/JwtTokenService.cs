using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Linq;

namespace DotNetSecurityToolkit.Jwt;

/// <summary>
/// Service for issuing JWT access tokens using configured <see cref="JwtOptions"/>.
/// </summary>
public sealed class JwtTokenService : IJwtTokenService
{
    private readonly JwtOptions _options;
    private readonly JwtSecurityTokenHandler _handler = new();

    public JwtTokenService(IOptions<JwtOptions> options)
    {
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));

        if (string.IsNullOrWhiteSpace(_options.SigningKey))
        {
            throw new InvalidOperationException(
                "JwtOptions.SigningKey must be configured in appsettings.json (section 'DotNetSecurityToolkit:Jwt').");
        }
    }

    public string CreateToken(IEnumerable<Claim> claims, DateTime? expires = null)
    {
        if (claims is null)
        {
            throw new ArgumentNullException(nameof(claims));
        }

        var keyBytes = Encoding.UTF8.GetBytes(_options.SigningKey);
        var signingCredentials = new SigningCredentials(
            new SymmetricSecurityKey(keyBytes),
            SecurityAlgorithms.HmacSha256);

        var now = DateTime.UtcNow;
        var expiresAt = expires ?? now.AddMinutes(_options.AccessTokenExpirationMinutes);

        var jwt = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: now,
            expires: expiresAt,
            signingCredentials: signingCredentials);

        return _handler.WriteToken(jwt);
    }

    public string CreateTokenFromDictionary(IDictionary<string, string?> claims, DateTime? expires = null)
    {
        if (claims is null)
        {
            throw new ArgumentNullException(nameof(claims));
        }

        var claimList = claims
            .Where(pair => pair.Value is not null)
            .Select(pair => new Claim(pair.Key, pair.Value!));

        return CreateToken(claimList, expires);
    }

    public string CreateRefreshToken(int byteLength = 32)
    {
        var bytes = RandomNumberGenerator.GetBytes(byteLength);
        return Base64UrlEncoder.Encode(bytes);
    }

    public ClaimsPrincipal? ValidateToken(string token, bool validateLifetime = true)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentNullException(nameof(token));
        }

        var keyBytes = Encoding.UTF8.GetBytes(_options.SigningKey);
        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = !string.IsNullOrWhiteSpace(_options.Issuer),
            ValidIssuer = _options.Issuer,
            ValidateAudience = !string.IsNullOrWhiteSpace(_options.Audience),
            ValidAudience = _options.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
            ValidateLifetime = _options.ValidateLifetime && validateLifetime,
            ClockSkew = TimeSpan.FromMinutes(1)
        };

        try
        {
            var principal = _handler.ValidateToken(token, parameters, out _);
            return principal;
        }
        catch
        {
            return null;
        }
    }
}
