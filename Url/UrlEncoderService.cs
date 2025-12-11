using DotNetSecurityToolkit.Abstractions;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DotNetSecurityToolkit.Url;

/// <summary>
/// URL-safe Base64 and slug operations.
/// </summary>
public sealed class UrlEncoderService : IUrlEncoder
{
    public string ToUrlSafeBase64(byte[] data)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        var base64 = Convert.ToBase64String(data);
        return base64
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    public byte[] FromUrlSafeBase64(string urlSafe)
    {
        if (urlSafe is null)
        {
            throw new ArgumentNullException(nameof(urlSafe));
        }

        var base64 = urlSafe
            .Replace('-', '+')
            .Replace('_', '/');

        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }

        return Convert.FromBase64String(base64);
    }

    public string Slugify(string input, int maxLength = 80)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        var normalized = input.ToLowerInvariant().Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder();

        foreach (var ch in normalized)
        {
            var unicodeCategory = CharUnicodeInfo.GetUnicodeCategory(ch);
            if (unicodeCategory == UnicodeCategory.NonSpacingMark)
            {
                continue;
            }

            if (char.IsLetterOrDigit(ch))
            {
                sb.Append(ch);
            }
            else if (char.IsWhiteSpace(ch) || ch == '-' || ch == '_')
            {
                sb.Append('-');
            }

            if (sb.Length >= maxLength)
            {
                break;
            }
        }

        var slug = Regex.Replace(sb.ToString(), "-{2,}", "-").Trim('-');
        return slug;
    }

    public bool IsUrlSafeBase64(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        return Regex.IsMatch(value, "^[A-Za-z0-9_-]+$");
    }

    public string GenerateShortToken(int length = 12)
    {
        var bytes = RandomNumberGenerator.GetBytes(length);
        var urlSafe = ToUrlSafeBase64(bytes);
        return urlSafe.Substring(0, Math.Min(length, urlSafe.Length));
    }

    public string NormalizeForSlug(string text)
    {
        if (text == null)
            throw new ArgumentNullException(nameof(text));

        var normalized = text.ToLowerInvariant().Normalize(NormalizationForm.FormD);

        var sb = new StringBuilder();
        foreach (var ch in normalized)
        {
            var unicodeCategory = CharUnicodeInfo.GetUnicodeCategory(ch);
            if (unicodeCategory != UnicodeCategory.NonSpacingMark)
            {
                if (char.IsLetterOrDigit(ch))
                    sb.Append(ch);
                else
                    sb.Append('-');
            }
        }

        return Regex.Replace(sb.ToString(), "-{2,}", "-").Trim('-');
    }

}
