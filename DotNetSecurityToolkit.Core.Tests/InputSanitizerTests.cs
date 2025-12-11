using DotNetSecurityToolkit.Validation;
using FluentAssertions;

namespace DotNetSecurityToolkit.Core.Tests;

public class InputSanitizerTests
{
    private readonly InputSanitizer _sanitizer = new();

    [Fact]
    public void Sanitize_RemovesUnsafeCharactersAndTrims()
    {
        var result = _sanitizer.Sanitize("  hello<script>alert(1)</script>  ", maxLength: 10);

        result.Should().Be("helloscript");
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void IsSafe_ReturnsFalseForInvalidInput(string? input)
    {
        _sanitizer.IsSafe(input!, 5).Should().BeFalse();
    }

    [Fact]
    public void IsSafe_ValidatesLengthAndCharacters()
    {
        _sanitizer.IsSafe("good_text", maxLength: 5).Should().BeFalse();
        _sanitizer.IsSafe("good-text", maxLength: 20).Should().BeTrue();
    }
}
