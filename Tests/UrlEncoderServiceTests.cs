using System.Text;
using DotNetSecurityToolkit.Url;
using FluentAssertions;
using Xunit;

namespace DotNetSecurityToolkit.Tests;

public class UrlEncoderServiceTests
{
    private readonly UrlEncoderService _service = new();

    [Fact]
    public void ToUrlSafeBase64_And_FromUrlSafeBase64_RoundTrip()
    {
        var data = Encoding.UTF8.GetBytes("example-data");

        var encoded = _service.ToUrlSafeBase64(data);
        var decoded = _service.FromUrlSafeBase64(encoded);

        decoded.Should().Equal(data);
    }

    [Fact]
    public void Slugify_RemovesSpecialCharactersAndCollapsesSeparators()
    {
        var result = _service.Slugify("Hello, World!   -- Ünicode", maxLength: 50);

        result.Should().Be("hello-world-unicode");
    }

    [Fact]
    public void GenerateShortToken_RespectsRequestedLength()
    {
        var token = _service.GenerateShortToken(length: 10);

        token.Should().HaveLength(10);
        _service.IsUrlSafeBase64(token).Should().BeTrue();
    }

    [Fact]
    public void AppendQueryString_SkipsNullValues()
    {
        var baseUrl = "https://example.com/resource";
        var parameters = new Dictionary<string, string?>
        {
            ["a"] = "1",
            ["b"] = null,
            ["c"] = "3"
        };

        var result = _service.AppendQueryString(baseUrl, parameters);

        result.Should().Be("https://example.com/resource?a=1&c=3");
    }

    [Fact]
    public void CombinePathSegments_TrimsSeparators()
    {
        var result = _service.CombinePathSegments("/api/", "/v1/", "items");

        result.Should().Be("api/v1/items");
    }
}
