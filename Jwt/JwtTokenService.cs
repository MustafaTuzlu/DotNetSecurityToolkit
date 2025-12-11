using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

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
}
