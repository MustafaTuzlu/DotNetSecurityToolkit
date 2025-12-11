using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Crypto;
using DotNetSecurityToolkit.Jwt;
using FluentAssertions;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace DotNetSecurityToolkit.Core.Tests;

public class JwtTokenServiceTests
{
    private static JwtTokenService CreateService()
    {
        var jwtOptions = Options.Create(new JwtOptions
        {
            SigningKey = "jwt-signing-key",
            Issuer = "issuer",
            Audience = "audience",
            ValidateLifetime = true
        });

        var rotation = Options.Create(new KeyRotationOptions
        {
            CurrentKeyId = "kid",
            JwtSigningKeys = new() { ["kid"] = "jwt-signing-key" }
        });

        var keyRing = new KeyRing(rotation, Options.Create(new SecurityToolkitOptions()), jwtOptions);
        return new JwtTokenService(jwtOptions, keyRing);
    }

    [Fact]
    public void CreateAndValidateToken_RoundTrips()
    {
        var service = CreateService();
        var token = service.CreateToken(new[] { new Claim("sub", "123"), new Claim("role", "admin") });

        var principal = service.ValidateToken(token);

        principal.Should().NotBeNull();
        principal!.FindFirst("role")!.Value.Should().Be("admin");
    }

    [Fact]
    public void CreateTokenFromDictionary_IgnoresNullValues()
    {
        var service = CreateService();
        var token = service.CreateTokenFromDictionary(new Dictionary<string, string?>
        {
            ["sub"] = "1",
            ["skip"] = null
        });

        var principal = service.ValidateToken(token);
        principal!.FindFirst("sub")!.Value.Should().Be("1");
        principal.FindFirst("skip").Should().BeNull();
    }
}
