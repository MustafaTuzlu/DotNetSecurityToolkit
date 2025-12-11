using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Crypto;
using DotNetSecurityToolkit.Url;
using FluentAssertions;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Core.Tests;

public class AesEncryptionServiceTests
{
    private static AesEncryptionService CreateService()
    {
        var rotationOptions = Options.Create(new KeyRotationOptions
        {
            CurrentKeyId = "enc1",
            EncryptionKeys = new() { ["enc1"] = "super-secret-key-material" }
        });

        var security = Options.Create(new SecurityToolkitOptions());
        var keyRing = new KeyRing(rotationOptions, security);
        return new AesEncryptionService(security, new UrlEncoderService(), keyRing);
    }

    [Fact]
    public void EncryptAndDecrypt_RoundTrips()
    {
        var service = CreateService();

        var cipher = service.Encrypt("hello world");
        var plain = service.Decrypt(cipher);

        plain.Should().Be("hello world");
        service.IsEncryptedPayload(cipher).Should().BeTrue();
    }

    [Fact]
    public void TryDecrypt_ReturnsFalseOnInvalid()
    {
        var service = CreateService();

        service.TryDecrypt("invalid", out var plain).Should().BeFalse();
        plain.Should().BeNull();
    }
}
