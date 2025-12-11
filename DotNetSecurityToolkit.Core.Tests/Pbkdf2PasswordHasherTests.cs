using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Crypto;
using DotNetSecurityToolkit.Abstractions;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;

namespace DotNetSecurityToolkit.Core.Tests;

public class Pbkdf2PasswordHasherTests
{
    private static Pbkdf2PasswordHasher CreateHasher(int iterations = 200_000, int keySize = 32)
    {
        var options = Options.Create(new SecurityToolkitOptions
        {
            PasswordHashIterations = iterations,
            MinimumPasswordHashIterations = iterations,
            PasswordKeySize = keySize,
            PasswordSaltSize = 16
        });

        var sink = Mock.Of<ISecurityEventSink>();
        return new Pbkdf2PasswordHasher(options, sink);
    }

    [Fact]
    public void HashAndVerify_WorksRoundTrip()
    {
        var hasher = CreateHasher();

        var hash = hasher.HashPassword("password");
        var parts = hash.Split('.');

        parts.Should().HaveCount(3);
        hasher.VerifyHashedPassword(hash, "password").Should().BeTrue();
        hasher.VerifyHashedPassword(hash, "wrong").Should().BeFalse();
    }

    [Fact]
    public void Verify_WithNeedsRehashReportsFlag()
    {
        var hasher = CreateHasher(iterations: 200_000);
        var weakerHash = new Pbkdf2PasswordHasher(Options.Create(new SecurityToolkitOptions
        {
            PasswordHashIterations = 50_000,
            MinimumPasswordHashIterations = 50_000,
            PasswordKeySize = 32,
            PasswordSaltSize = 16
        }), Mock.Of<ISecurityEventSink>()).HashPassword("pwd");

        hasher.VerifyHashedPassword(weakerHash, "pwd", out var needsRehash).Should().BeTrue();
        needsRehash.Should().BeTrue();
    }

    [Fact]
    public void NeedsRehash_ReturnsTrueForMismatchedKeySize()
    {
        var hasher = CreateHasher(keySize: 64);
        var hash = hasher.HashPassword("pwd");

        var defaultHasher = CreateHasher(keySize: 32);
        defaultHasher.NeedsRehash(hash).Should().BeTrue();
    }
}
