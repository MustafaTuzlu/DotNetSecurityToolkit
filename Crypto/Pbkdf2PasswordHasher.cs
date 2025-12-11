using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace DotNetSecurityToolkit.Crypto;

/// <summary>
/// PBKDF2 based password hasher.
/// Stored format: {iterations}.{saltBase64}.{hashBase64}
/// </summary>
public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    private readonly SecurityToolkitOptions _options;

    public Pbkdf2PasswordHasher(IOptions<SecurityToolkitOptions> options)
    {
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
    }

    public string HashPassword(string password)
    {
        if (password is null)
        {
            throw new ArgumentNullException(nameof(password));
        }

        var salt = RandomNumberGenerator.GetBytes(_options.PasswordSaltSize);

        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            salt,
            _options.PasswordHashIterations,
            HashAlgorithmName.SHA256);

        var key = pbkdf2.GetBytes(_options.PasswordKeySize);

        return string.Join('.',
            _options.PasswordHashIterations.ToString(),
            Convert.ToBase64String(salt),
            Convert.ToBase64String(key));
    }

    public bool VerifyHashedPassword(string hash, string password)
    {
        if (hash is null)
        {
            throw new ArgumentNullException(nameof(hash));
        }

        if (password is null)
        {
            throw new ArgumentNullException(nameof(password));
        }

        var parts = hash.Split('.');
        if (parts.Length != 3)
        {
            return false;
        }

        if (!int.TryParse(parts[0], out var iterations))
        {
            return false;
        }

        var salt = Convert.FromBase64String(parts[1]);
        var expectedKey = Convert.FromBase64String(parts[2]);

        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256);

        var actualKey = pbkdf2.GetBytes(expectedKey.Length);

        return CryptographicOperations.FixedTimeEquals(expectedKey, actualKey);
    }

    public bool VerifyHashedPassword(string hash, string password, out bool needsRehash)
    {
        var isValid = VerifyHashedPassword(hash, password);
        needsRehash = isValid && NeedsRehash(hash);
        return isValid;
    }

    public bool NeedsRehash(string hash)
    {
        try
        {
            var parts = ParseHashComponents(hash);
            return parts.Iterations < _options.PasswordHashIterations || parts.Key.Length != _options.PasswordKeySize;
        }
        catch
        {
            return true;
        }
    }

    public byte[] GenerateSalt(int size)
    {
        return RandomNumberGenerator.GetBytes(size);
    }

    public string HashPasswordWithCustomSalt(string password, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            salt,
            _options.PasswordHashIterations,
            HashAlgorithmName.SHA256);

        var key = pbkdf2.GetBytes(_options.PasswordKeySize);

        return $"{_options.PasswordHashIterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(key)}";
    }

    public (int Iterations, byte[] Salt, byte[] Key) ParseHashComponents(string hash)
    {
        var parts = hash.Split('.');
        return (
            int.Parse(parts[0]),
            Convert.FromBase64String(parts[1]),
            Convert.FromBase64String(parts[2])
        );
    }

}
