using DotNetSecurityToolkit.Cookies;
using DotNetSecurityToolkit.Abstractions;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Moq;

namespace DotNetSecurityToolkit.Core.Tests;

public class CookieManagerTests
{
    [Fact]
    public void SetEncryptedCookie_WritesEncryptedValue()
    {
        var context = new DefaultHttpContext();
        var accessor = Mock.Of<IHttpContextAccessor>(a => a.HttpContext == context);
        var encryption = new Mock<IEncryptionService>();
        encryption.Setup(e => e.Encrypt("value")).Returns("cipher");

        var manager = new CookieManager(accessor, encryption.Object);
        manager.SetEncryptedCookie("key", "value", DateTimeOffset.UtcNow.AddMinutes(5));

        context.Response.Headers["Set-Cookie"].ToString().Should().Contain("cipher");
    }

    [Fact]
    public void GetDecryptedCookie_ReturnsPlainText()
    {
        var context = new DefaultHttpContext();
        context.Request.Cookies = new RequestCookieCollection(new Dictionary<string, string> { ["key"] = "cipher" });
        var accessor = Mock.Of<IHttpContextAccessor>(a => a.HttpContext == context);
        var encryption = new Mock<IEncryptionService>();
        encryption.Setup(e => e.TryDecrypt("cipher", out It.Ref<string?>.IsAny))
            .Returns((string cipher, out string? plain) => { plain = "plain"; return true; });

        var manager = new CookieManager(accessor, encryption.Object);
        manager.GetDecryptedCookie("key").Should().Be("plain");
    }

    [Fact]
    public void RenewEncryptedCookie_ReissuesWhenPresent()
    {
        var context = new DefaultHttpContext();
        context.Request.Cookies = new RequestCookieCollection(new Dictionary<string, string> { ["key"] = "cipher" });
        var accessor = Mock.Of<IHttpContextAccessor>(a => a.HttpContext == context);
        var encryption = new Mock<IEncryptionService>();
        encryption.Setup(e => e.TryDecrypt("cipher", out It.Ref<string?>.IsAny))
            .Returns((string cipher, out string? plain) => { plain = "plain"; return true; });
        encryption.Setup(e => e.Encrypt("plain")).Returns("cipher2");

        var manager = new CookieManager(accessor, encryption.Object);
        manager.RenewEncryptedCookie("key", TimeSpan.FromMinutes(1));

        context.Response.Headers["Set-Cookie"].ToString().Should().Contain("cipher2");
    }
}
