using DotNetSecurityToolkit.Url;
using FluentAssertions;

namespace DotNetSecurityToolkit.Core.Tests;

public class UrlEncoderServiceTests
{
    private readonly UrlEncoderService _service = new();

    [Fact]
    public void Base64Conversions_RoundTrip()
    {
        var data = new byte[] { 1, 2, 3, 4 };
        var encoded = _service.ToUrlSafeBase64(data);
        var decoded = _service.FromUrlSafeBase64(encoded);

        decoded.Should().Equal(data);
        _service.IsUrlSafeBase64(encoded).Should().BeTrue();
    }

    [Fact]
    public void Slugify_NormalizesText()
    {
        _service.Slugify("Merhaba Dünya!").Should().Be("merhaba-dunya");
        _service.NormalizeForSlug("Çeşme").Should().Be("cesme");
    }

    [Fact]
    public void AppendQueryString_AddsParameters()
    {
        var url = _service.AppendQueryString("https://example.com", new Dictionary<string, string?>
        {
            ["a"] = "1",
            ["b"] = null
        });

        url.Should().Contain("a=1");
        url.Should().NotContain("b=");
    }

    [Fact]
    public void CombinePathSegments_JoinsSegments()
    {
        _service.CombinePathSegments("/api/", "/v1/", "users").Should().Be("api/v1/users");
        _service.EnsureTrailingSlash("https://example.com/api").Should().EndWith("/");
    }
}
