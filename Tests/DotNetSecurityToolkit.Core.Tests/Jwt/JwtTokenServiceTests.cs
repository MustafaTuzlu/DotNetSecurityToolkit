using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Extensions;
using DotNetSecurityToolkit.Jwt;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace DotNetSecurityToolkit.Core.Tests.Jwt;

public class JwtTokenServiceTests
{
    [Fact]
    public void Constructor_ThrowsWhenSigningKeyMissing()
    {
        var options = Options.Create(new JwtOptions());

        Action act = () => _ = new JwtTokenService(options);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*SigningKey must be configured*");
    }

    [Fact]
    public void CreateToken_ThrowsWhenClaimsNull()
    {
        var options = Options.Create(new JwtOptions
        {
            SigningKey = new string('k', 32)
        });
        var service = new JwtTokenService(options);

        Action act = () => service.CreateToken(null!);

        act.Should().Throw<ArgumentNullException>()
            .Which.ParamName.Should().Be("claims");
    }

    [Fact]
    public void CreateToken_EmitsConfiguredClaimsAndMetadata()
    {
        var options = Options.Create(new JwtOptions
        {
            Issuer = "issuer.example",
            Audience = "audience.example",
            SigningKey = new string('s', 64),
            AccessTokenExpirationMinutes = 30
        });
        var service = new JwtTokenService(options);
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, "user-123"),
            new Claim("role", "admin"),
        };

        var before = DateTime.UtcNow;
        var tokenString = service.CreateToken(claims);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);

        jwt.Issuer.Should().Be(options.Value.Issuer);
        jwt.Audiences.Should().ContainSingle().Which.Should().Be(options.Value.Audience);
        jwt.Claims.Should().ContainSingle(c => c.Type == JwtRegisteredClaimNames.Sub && c.Value == "user-123");
        jwt.Claims.Should().ContainSingle(c => c.Type == "role" && c.Value == "admin");

        var expectedExpiration = before.AddMinutes(options.Value.AccessTokenExpirationMinutes);
        jwt.ValidTo.Should().BeCloseTo(expectedExpiration, precision: TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void AddJwtAuthentication_ConfiguresJwtBearerOptions()
    {
        var services = new ServiceCollection();
        var signingKey = new string('k', 64);

        services.AddJwtAuthentication(options =>
        {
            options.SigningKey = signingKey;
            options.Issuer = "issuer";
            options.Audience = "audience";
            options.ValidateLifetime = false;
        });

        var provider = services.BuildServiceProvider();
        var optionsMonitor = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>();

        var jwtBearerOptions = optionsMonitor.Get(JwtBearerDefaults.AuthenticationScheme);
        jwtBearerOptions.TokenValidationParameters.Should().NotBeNull();

        var parameters = jwtBearerOptions.TokenValidationParameters!;
        parameters.IssuerSigningKey.Should().BeOfType<SymmetricSecurityKey>()
            .Which.Key.Should().BeEquivalentTo(Encoding.UTF8.GetBytes(signingKey));
        parameters.ValidateIssuer.Should().BeTrue();
        parameters.ValidateAudience.Should().BeTrue();
        parameters.ValidIssuer.Should().Be("issuer");
        parameters.ValidAudience.Should().Be("audience");
        parameters.ValidateLifetime.Should().BeFalse();
    }

    [Fact]
    public void AddJwtAuthentication_RegistersTokenService()
    {
        var services = new ServiceCollection();

        services.AddJwtAuthentication(options => options.SigningKey = new string('x', 64));

        var provider = services.BuildServiceProvider();

        var tokenService = provider.GetService<IJwtTokenService>();

        tokenService.Should().NotBeNull();
    }
}
