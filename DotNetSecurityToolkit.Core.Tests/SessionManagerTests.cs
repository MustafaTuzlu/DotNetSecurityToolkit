using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Core.Tests.Helpers;
using DotNetSecurityToolkit.Session;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Moq;

namespace DotNetSecurityToolkit.Core.Tests;

public class SessionManagerTests
{
    private static (SessionManager Manager, FakeSession Session) CreateManager()
    {
        var context = new DefaultHttpContext();
        var session = new FakeSession();
        context.Features.Set<ISessionFeature>(new SessionFeature { Session = session });
        var accessor = Mock.Of<IHttpContextAccessor>(a => a.HttpContext == context);
        var encryption = new Mock<IEncryptionService>();
        encryption.Setup(e => e.Encrypt(It.IsAny<string>())).Returns<string>(s => $"enc-{s}");
        encryption.Setup(e => e.TryDecrypt(It.IsAny<string>(), out It.Ref<string?>.IsAny))
            .Returns((string cipher, out string? plain) => { plain = cipher.Replace("enc-", ""); return true; });

        return (new SessionManager(accessor, encryption.Object), session);
    }

    [Fact]
    public void SetAndGetString_Works()
    {
        var (manager, session) = CreateManager();
        manager.SetString("k", "v");

        manager.GetString("k").Should().Be("v");
        session.Keys.Should().Contain("k");
    }

    [Fact]
    public void ObjectOperations_RoundTrip()
    {
        var (manager, _) = CreateManager();
        manager.SetObject("obj", new { Name = "test" });
        manager.TryGetObject("obj", out Dictionary<string, string>? result).Should().BeTrue();
        result!["Name"].Should().Be("test");
    }

    [Fact]
    public void EncryptionHelpers_Work()
    {
        var (manager, _) = CreateManager();
        manager.SetEncrypted("secret", "value");
        manager.GetDecrypted("secret").Should().Be("value");
    }

    [Fact]
    public void SessionToken_IsStableAcrossReads()
    {
        var (manager, _) = CreateManager();
        var first = manager.GetOrCreateSessionToken();
        var second = manager.GetOrCreateSessionToken();

        first.Should().Be(second);
    }
}
