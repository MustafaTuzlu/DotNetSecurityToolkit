namespace DotNetSecurityToolkit.Configuration;

/// <summary>
/// Options controlling the SecurityHeadersMiddleware defaults.
/// </summary>
public sealed class SecurityHeadersOptions
{
    public const string SectionName = "SecurityHeaders";

    public bool EnableHsts { get; set; } = true;
    public bool EnableContentTypeOptions { get; set; } = true;
    public bool EnableReferrerPolicy { get; set; } = true;
    public bool EnableFrameOptions { get; set; } = true;
    public bool EnableCsp { get; set; } = true;

    public string ReferrerPolicy { get; set; } = "no-referrer";
    public string FrameOptions { get; set; } = "DENY";
    public string ContentSecurityPolicy { get; set; } = "default-src 'self'; frame-ancestors 'none';";
}
