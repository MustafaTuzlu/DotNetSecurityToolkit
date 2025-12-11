using System.Security.Claims;
using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Jwt;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace DotNetSecurityToolkit.Tests;

public class JwtTokenServiceTests
{
    [Fact]
    public void CreateToken_WithClaims_CanBeValidated()
    {
        var service = CreateService();
        var claims = new[] { new Claim("sub", "123"), new Claim("scope", "api.read") };

        var token = service.CreateToken(claims);
        var principal = service.ValidateToken(token);

        principal.Should().NotBeNull();
        principal!.FindFirst("sub")!.Value.Should().Be("123");
        principal.FindFirst("scope")!.Value.Should().Be("api.read");
    }

    [Fact]
    public void CreateTokenFromDictionary_IgnoresNullValues()
    {
        var service = CreateService();
        var claims = new Dictionary<string, string?>
        {
            ["sub"] = "user-1",
            ["optional"] = null
        };

        var token = service.CreateTokenFromDictionary(claims);
        var principal = service.ValidateToken(token);

        principal.Should().NotBeNull();
        principal!.FindFirst("sub")!.Value.Should().Be("user-1");
        principal.FindFirst("optional").Should().BeNull();
    }

    [Fact]
    public void ValidateToken_WithDifferentKey_ReturnsNull()
    {
        var issuerService = CreateService(signingKey: "issuer-key");
        var validatorService = CreateService(signingKey: "validator-key");
        var token = issuerService.CreateToken(new[] { new Claim("sub", "abc") });

        var principal = validatorService.ValidateToken(token);

        principal.Should().BeNull();
    }

    [Fact]
    public void CreateRefreshToken_ReturnsUrlSafeValue()
    {
        var service = CreateService();

        var refreshToken = service.CreateRefreshToken(24);

        refreshToken.Should().NotBeNullOrWhiteSpace();
        Base64UrlEncoder.DecodeBytes(refreshToken).Should().NotBeEmpty();
    }

    private static JwtTokenService CreateService(string signingKey = "test-signing-key-1234567890")
    {
        var options = Options.Create(new JwtOptions
        {
            Issuer = "issuer",
            Audience = "audience",
            SigningKey = signingKey,
            AccessTokenExpirationMinutes = 5,
            ValidateLifetime = true
        });

        var keyRing = new FakeKeyRing(signingKey);
        return new JwtTokenService(options, keyRing);
    }

    private sealed class FakeKeyRing : IKeyRing
    {
        private readonly IReadOnlyList<KeyMaterial> _materials;

        public FakeKeyRing(string signingKey)
        {
            _materials = new[] { new KeyMaterial("kid-1", signingKey, KeyPurpose.JwtSigning) };
        }

        public IEnumerable<KeyMaterial> GetAll(KeyPurpose purpose)
        {
            return purpose == KeyPurpose.JwtSigning ? _materials : Array.Empty<KeyMaterial>();
        }

        public KeyMaterial GetCurrent(KeyPurpose purpose)
        {
            return GetAll(purpose).First();
        }

        public bool TryGet(string keyId, KeyPurpose purpose, out KeyMaterial material)
        {
            material = GetAll(purpose).FirstOrDefault(k => k.KeyId == keyId)!;
            return material is not null;
        }
    }
}
