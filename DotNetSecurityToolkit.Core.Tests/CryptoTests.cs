using DotNetSecurityToolkit.Crypto;
using FluentAssertions;

namespace DotNetSecurityToolkit.Core.Tests;

public class CryptoTests
{
    [Fact]
    public void ComputeHashes_ReturnExpectedValues()
    {
        Crypto.ComputeMd5("abc").Should().Be("900150983cd24fb0d6963f7d28e17f72");
        Crypto.ComputeSha1("abc").Should().Be("a9993e364706816aba3e25717850c26c9cd0d89d");
        Crypto.ComputeSha256("abc").Should().Be("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
