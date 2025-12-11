using System.Security.Cryptography;
using System.Text;

namespace DotNetSecurityToolkit.Crypto;

/// <summary>
/// Provides one-way hashing helpers for common algorithms.
/// </summary>
public static class Crypto
{
    /// <summary>
    /// Computes an MD5 hash of the supplied text.
    /// </summary>
    public static string ComputeMd5(string input) => ComputeHash(input, MD5.Create());

    /// <summary>
    /// Computes a SHA1 hash of the supplied text.
    /// </summary>
    public static string ComputeSha1(string input) => ComputeHash(input, SHA1.Create());

    /// <summary>
    /// Computes a SHA256 hash of the supplied text.
    /// </summary>
    public static string ComputeSha256(string input) => ComputeHash(input, SHA256.Create());

    /// <summary>
    /// Computes a SHA384 hash of the supplied text.
    /// </summary>
    public static string ComputeSha384(string input) => ComputeHash(input, SHA384.Create());

    /// <summary>
    /// Computes a SHA512 hash of the supplied text.
    /// </summary>
    public static string ComputeSha512(string input) => ComputeHash(input, SHA512.Create());

    private static string ComputeHash(string input, HashAlgorithm algorithm)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        using (algorithm)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            var hashBytes = algorithm.ComputeHash(bytes);
            var builder = new StringBuilder(hashBytes.Length * 2);

            foreach (var b in hashBytes)
            {
                builder.Append(b.ToString("x2"));
            }

            return builder.ToString();
        }
    }
}
