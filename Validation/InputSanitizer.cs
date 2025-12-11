using System.Text.RegularExpressions;
using DotNetSecurityToolkit.Abstractions;

namespace DotNetSecurityToolkit.Validation;

/// <summary>
/// Basic allow-list input sanitizer that strips risky characters and enforces maximum lengths.
/// </summary>
public sealed class InputSanitizer : IInputSanitizer
{
    private static readonly Regex UnsafeCharacters = new("[^\w@\-\.: ]", RegexOptions.Compiled);

    public string Sanitize(string input, int maxLength = 2048)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        var trimmed = input.Length > maxLength ? input[..maxLength] : input;
        return UnsafeCharacters.Replace(trimmed, string.Empty).Trim();
    }

    public bool IsSafe(string input, int maxLength = 2048)
    {
        if (string.IsNullOrEmpty(input) || input.Length > maxLength)
        {
            return false;
        }

        return !UnsafeCharacters.IsMatch(input);
    }
}
