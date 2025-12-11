namespace DotNetSecurityToolkit.Configuration;

/// <summary>
/// In-memory rate limiting options for API requests.
/// Bind from configuration section "DotNetSecurityToolkit:RateLimiting".
/// </summary>
public sealed class RateLimitingOptions
{
    public const string SectionName = "RateLimiting";

    /// <summary>
    /// Maximum number of requests allowed within a window.
    /// </summary>
    public int RequestsPerWindow { get; set; } = 100;

    /// <summary>
    /// Length of the sliding window in seconds.
    /// </summary>
    public int WindowSeconds { get; set; } = 60;

    /// <summary>
    /// Whether rate limiting is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Whether to emit Retry-After headers when throttling.
    /// </summary>
    public bool EmitRetryAfterHeader { get; set; } = true;
}
