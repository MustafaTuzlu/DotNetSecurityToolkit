using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Crypto;
using FluentAssertions;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Core.Tests;

public class KeyRingTests
{
    [Fact]
    public void GetCurrent_ReturnsConfiguredKey()
    {
        var rotation = Options.Create(new KeyRotationOptions
        {
            CurrentKeyId = "k1",
            EncryptionKeys = new() { ["k1"] = "secret1" }
        });
        var ring = new KeyRing(rotation, Options.Create(new SecurityToolkitOptions()), Options.Create(new JwtOptions()))
;

        var material = ring.GetCurrent(KeyPurpose.Encryption);

        material.KeyId.Should().Be("k1");
        material.Value.Should().Be("secret1");
    }

    [Fact]
    public void EnumerateIncludesLegacyWhenAllowed()
    {
        var rotation = Options.Create(new KeyRotationOptions
        {
            AllowLegacySecretKey = true,
            EncryptionKeys = new()
        });
        var security = Options.Create(new SecurityToolkitOptions { SecretKey = "legacy" });
        var ring = new KeyRing(rotation, security);

        ring.GetAll(KeyPurpose.Encryption).Should().Contain(k => k.KeyId == "legacy-secret" && k.Value == "legacy");
    }
}
