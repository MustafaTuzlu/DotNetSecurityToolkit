using System.Security.Cryptography;
using DotNetSecurityToolkit.AntiForgery;
using DotNetSecurityToolkit.Abstractions;
using FluentAssertions;
using Xunit;

namespace DotNetSecurityToolkit.Tests;

public class AntiForgeryServiceTests
{
    private readonly AntiForgeryService _service = new();

    [Fact]
    public void IssueToken_GeneratesTokensWithExpiration()
    {
        var before = DateTimeOffset.UtcNow;

        AntiForgeryTokenPair pair = _service.IssueToken();

        pair.CookieToken.Should().NotBeNullOrWhiteSpace();
        pair.RequestToken.Should().NotBeNullOrWhiteSpace();
        pair.CookieToken.Should().NotBe(pair.RequestToken);
        pair.ExpiresAt.Should().BeOnOrAfter(before.AddMinutes(59))
            .And.BeOnOrBefore(before.AddHours(1).AddMinutes(1));
    }

    [Fact]
    public void ValidateToken_MatchingTokens_ReturnsTrue()
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        var result = _service.ValidateToken(token, token);

        result.Should().BeTrue();
    }

    [Fact]
    public void ValidateToken_MismatchedTokens_ReturnsFalse()
    {
        AntiForgeryTokenPair pair = _service.IssueToken();

        var result = _service.ValidateToken(pair.CookieToken, pair.RequestToken);

        result.Should().BeFalse();
    }

    [Theory]
    [InlineData(null, "valid")]
    [InlineData("", "valid")]
    [InlineData("valid", null)]
    [InlineData("valid", " ")]
    public void ValidateToken_WhenEitherTokenIsMissing_ReturnsFalse(string? cookieToken, string? requestToken)
    {
        var result = _service.ValidateToken(cookieToken!, requestToken!);

        result.Should().BeFalse();
    }
}
