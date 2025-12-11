namespace DotNetSecurityToolkit.Configuration;

/// <summary>
/// Options for configuring exception handling behavior.
/// Bind from configuration section "DotNetSecurityToolkit:ExceptionHandling".
/// </summary>
public sealed class ExceptionHandlingOptions
{
    /// <summary>
    /// Configuration section name relative to SecurityToolkitOptions.
    /// </summary>
    public const string SectionName = "ExceptionHandling";

    /// <summary>
    /// Whether to include stack traces in the descriptor.
    /// </summary>
    public bool IncludeStackTrace { get; set; } = false;

    /// <summary>
    /// Whether to include the exception type name in the descriptor.
    /// </summary>
    public bool IncludeExceptionType { get; set; } = true;

    /// <summary>
    /// Whether to use the innermost exception instead of the top-level exception.
    /// </summary>
    public bool UseInnermostException { get; set; } = true;

    /// <summary>
    /// Whether to include the inner exception message when available.
    /// </summary>
    public bool IncludeInnerExceptionMessage { get; set; } = false;

    /// <summary>
    /// Whether to expose the exception message or use the configured fallback.
    /// </summary>
    public bool ExposeExceptionMessages { get; set; } = false;

    /// <summary>
    /// A default user-facing message used when exception messages are not exposed.
    /// </summary>
    public string DefaultMessage { get; set; } = "An unexpected error occurred.";

    /// <summary>
    /// Default application-specific code to emit when no mapping is found.
    /// </summary>
    public string DefaultErrorCode { get; set; } = "error";

    /// <summary>
    /// Map of exception type names to error codes.
    /// </summary>
    public IDictionary<string, string> ExceptionCodeMapping { get; set; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Override messages for specific exception types when messages are not exposed.
    /// </summary>
    public IDictionary<string, string> ExceptionMessageOverrides { get; set; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
