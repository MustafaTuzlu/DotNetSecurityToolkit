using DotNetSecurityToolkit.AntiForgery;
using FluentAssertions;

namespace DotNetSecurityToolkit.Core.Tests;

public class AntiForgeryServiceTests
{
    private readonly AntiForgeryService _service = new();

    [Fact]
    public void IssueToken_ReturnsDistinctTokens()
    {
        var pair = _service.IssueToken();

        pair.CookieToken.Should().NotBeNullOrEmpty();
        pair.RequestToken.Should().NotBe(pair.CookieToken);
    }

    [Fact]
    public void ValidateToken_ComparesTokensWithFixedTimeEquals()
    {
        var pair = _service.IssueToken();

        _service.ValidateToken(pair.CookieToken, pair.RequestToken).Should().BeTrue();
        _service.ValidateToken(pair.CookieToken, "invalid").Should().BeFalse();
    }
}
