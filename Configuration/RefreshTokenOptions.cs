namespace DotNetSecurityToolkit.Configuration;

/// <summary>
/// Options for handling refresh tokens and device binding.
/// Bind from configuration section "DotNetSecurityToolkit:RefreshTokens".
/// </summary>
public sealed class RefreshTokenOptions
{
    public const string SectionName = "RefreshTokens";

    /// <summary>
    /// Lifetime of refresh tokens in days.
    /// </summary>
    public int LifetimeDays { get; set; } = 30;

    /// <summary>
    /// Whether refresh tokens must be bound to a device fingerprint.
    /// </summary>
    public bool RequireDeviceBinding { get; set; } = true;

    /// <summary>
    /// Whether to automatically revoke tokens after a single use.
    /// </summary>
    public bool OneTimeUse { get; set; } = true;
}
