namespace DotNetSecurityToolkit.Configuration;

/// <summary>
/// Options for configuring JWT authentication.
/// Bind from configuration section "DotNetSecurityToolkit:Jwt".
/// </summary>
public sealed class JwtOptions
{
    /// <summary>
    /// Configuration section name relative to SecurityToolkitOptions.
    /// </summary>
    public const string SectionName = "Jwt";

    /// <summary>
    /// Issuer claim placed on created tokens and validated on inbound tokens.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Audience claim placed on created tokens and validated on inbound tokens.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Symmetric signing key used for creating and validating tokens.
    /// Recommended length: at least 32 characters with high entropy.
    /// </summary>
    public string SigningKey { get; set; } = string.Empty;

    /// <summary>
    /// Lifetime of generated access tokens, in minutes.
    /// </summary>
    public int AccessTokenExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Whether token lifetime should be validated for inbound tokens.
    /// </summary>
    public bool ValidateLifetime { get; set; } = true;
}
