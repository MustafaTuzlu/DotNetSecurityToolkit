namespace DotNetSecurityToolkit.Configuration;

/// <summary>
/// Options for configuring key rotation and key rings.
/// Bind from configuration section "DotNetSecurityToolkit:KeyRotation".
/// </summary>
public sealed class KeyRotationOptions
{
    public const string SectionName = "KeyRotation";

    /// <summary>
    /// Current key identifier to use for encryption/signing operations.
    /// </summary>
    public string CurrentKeyId { get; set; } = "default";

    /// <summary>
    /// Versioned keys dedicated to encryption payloads.
    /// </summary>
    public IDictionary<string, string> EncryptionKeys { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Versioned keys dedicated to JWT signing.
    /// </summary>
    public IDictionary<string, string> JwtSigningKeys { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Whether to also include SecurityToolkitOptions.SecretKey as a legacy encryption key.
    /// </summary>
    public bool AllowLegacySecretKey { get; set; } = true;

    /// <summary>
    /// Whether to include JwtOptions.SigningKey as a legacy signing key.
    /// </summary>
    public bool AllowLegacyJwtSigningKey { get; set; } = true;
}
