using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Crypto;
using DotNetSecurityToolkit.Url;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Core.Tests;

public class CompositeEncryptionServiceTests
{
    private static CompositeEncryptionService CreateComposite(bool preferDataProtection)
    {
        var rotation = Options.Create(new KeyRotationOptions
        {
            CurrentKeyId = "enc",
            EncryptionKeys = new() { ["enc"] = "fallback-key" }
        });

        var securityOptions = Options.Create(new SecurityToolkitOptions { PreferDataProtection = preferDataProtection });
        var keyRing = new KeyRing(rotation, securityOptions);
        var aes = new AesEncryptionService(securityOptions, new UrlEncoderService(), keyRing);
        var dataProtection = new DataProtectionEncryptionService(DataProtectionProvider.Create("composite-tests"));

        return new CompositeEncryptionService(dataProtection, aes, securityOptions);
    }

    [Fact]
    public void UsesPreferredEncryptionService()
    {
        var composite = CreateComposite(preferDataProtection: true);
        var cipher = composite.Encrypt("value");

        composite.Decrypt(cipher).Should().Be("value");
    }

    [Fact]
    public void FallsBackToAesWhenDataProtectionFails()
    {
        var composite = CreateComposite(preferDataProtection: true);
        var aesOnly = CreateComposite(preferDataProtection: false);

        var cipher = aesOnly.Encrypt("value");

        composite.Decrypt(cipher).Should().Be("value");
    }
}
