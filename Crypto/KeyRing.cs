using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Crypto;

/// <summary>
/// Simple in-memory key ring that supports versioned encryption and JWT signing keys.
/// </summary>
public sealed class KeyRing : IKeyRing
{
    private readonly KeyRotationOptions _rotationOptions;
    private readonly SecurityToolkitOptions _securityOptions;
    private readonly JwtOptions _jwtOptions;

    public KeyRing(
        IOptions<KeyRotationOptions> rotationOptions,
        IOptions<SecurityToolkitOptions> securityOptions,
        IOptions<JwtOptions>? jwtOptions = null)
    {
        _rotationOptions = rotationOptions.Value ?? throw new ArgumentNullException(nameof(rotationOptions));
        _securityOptions = securityOptions.Value ?? throw new ArgumentNullException(nameof(securityOptions));
        _jwtOptions = jwtOptions?.Value ?? new JwtOptions();
    }

    public KeyMaterial GetCurrent(KeyPurpose purpose)
    {
        var keyId = _rotationOptions.CurrentKeyId;
        if (TryGet(keyId, purpose, out var material))
        {
            return material;
        }

        var first = GetAll(purpose).FirstOrDefault();
        if (first is null)
        {
            throw new InvalidOperationException($"No keys configured for purpose {purpose}.");
        }

        return first;
    }

    public IEnumerable<KeyMaterial> GetAll(KeyPurpose purpose)
    {
        return purpose switch
        {
            KeyPurpose.Encryption => EnumerateEncryptionKeys(),
            KeyPurpose.JwtSigning => EnumerateJwtKeys(),
            _ => Array.Empty<KeyMaterial>()
        };
    }

    public bool TryGet(string keyId, KeyPurpose purpose, out KeyMaterial material)
    {
        material = GetAll(purpose).FirstOrDefault(k => string.Equals(k.KeyId, keyId, StringComparison.OrdinalIgnoreCase));
        return material is not null;
    }

    private IEnumerable<KeyMaterial> EnumerateEncryptionKeys()
    {
        foreach (var pair in _rotationOptions.EncryptionKeys)
        {
            yield return new KeyMaterial(pair.Key, pair.Value, KeyPurpose.Encryption);
        }

        if (_rotationOptions.AllowLegacySecretKey && !string.IsNullOrWhiteSpace(_securityOptions.SecretKey))
        {
            yield return new KeyMaterial("legacy-secret", _securityOptions.SecretKey, KeyPurpose.Encryption);
        }
    }

    private IEnumerable<KeyMaterial> EnumerateJwtKeys()
    {
        foreach (var pair in _rotationOptions.JwtSigningKeys)
        {
            yield return new KeyMaterial(pair.Key, pair.Value, KeyPurpose.JwtSigning);
        }

        if (_rotationOptions.AllowLegacyJwtSigningKey && !string.IsNullOrWhiteSpace(_jwtOptions.SigningKey))
        {
            yield return new KeyMaterial("legacy-jwt", _jwtOptions.SigningKey, KeyPurpose.JwtSigning);
        }
    }
}
