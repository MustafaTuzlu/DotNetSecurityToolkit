using DotNetSecurityToolkit.Crypto;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;

namespace DotNetSecurityToolkit.Core.Tests;

public class DataProtectionEncryptionServiceTests
{
    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var provider = DataProtectionProvider.Create("tests");
        var service = new DataProtectionEncryptionService(provider);

        var cipher = service.Encrypt("secret");
        service.Decrypt(cipher).Should().Be("secret");
    }

    [Fact]
    public void TryDecrypt_ReturnsFalseOnTamperedData()
    {
        var provider = DataProtectionProvider.Create("tests");
        var service = new DataProtectionEncryptionService(provider);

        service.TryDecrypt("bad-data", out var plain).Should().BeFalse();
        plain.Should().BeNull();
    }
}
