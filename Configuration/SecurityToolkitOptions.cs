namespace DotNetSecurityToolkit.Configuration;

/// <summary>
/// Options for configuring DotNetSecurityToolkit.
/// Bind from configuration section "DotNetSecurityToolkit".
/// </summary>
public sealed class SecurityToolkitOptions
{
    /// <summary>
    /// Configuration section name used in appsettings.json.
    /// </summary>
    public const string SectionName = "DotNetSecurityToolkit";

    /// <summary>
    /// Secret key used for symmetric encryption operations.
    /// Recommended length: at least 32 characters with high entropy.
    /// </summary>
    public string SecretKey { get; set; } = string.Empty;

    /// <summary>
    /// Number of iterations to use for PBKDF2 password hashing.
    /// </summary>
    public int PasswordHashIterations { get; set; } = 100_000;

    /// <summary>
    /// Size of the salt in bytes for password hashing.
    /// </summary>
    public int PasswordSaltSize { get; set; } = 16;

    /// <summary>
    /// Size of the derived key in bytes.
    /// </summary>
    public int PasswordKeySize { get; set; } = 32;
}
