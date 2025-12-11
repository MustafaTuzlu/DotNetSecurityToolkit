namespace DotNetSecurityToolkit.Configuration;

/// <summary>
/// Options controlling security telemetry emission.
/// </summary>
public sealed class TelemetryOptions
{
    public const string SectionName = "Telemetry";

    /// <summary>
    /// Whether security events should be emitted.
    /// </summary>
    public bool Enabled { get; set; } = true;
}
