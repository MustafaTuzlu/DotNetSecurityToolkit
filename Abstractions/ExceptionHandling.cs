using DotNetSecurityToolkit.Configuration;

namespace DotNetSecurityToolkit.Abstractions;

/// <summary>
/// Standardized representation of an exception to expose to callers or logs.
/// </summary>
public sealed class ExceptionDescriptor
{
    /// <summary>
    /// Application-defined error code.
    /// </summary>
    public required string Code { get; init; }

    /// <summary>
    /// User-facing message for the error.
    /// </summary>
    public required string Message { get; init; }

    /// <summary>
    /// The full name of the exception type when exposed.
    /// </summary>
    public string? ExceptionType { get; init; }

    /// <summary>
    /// Optional stack trace when configured to include it.
    /// </summary>
    public string? StackTrace { get; init; }

    /// <summary>
    /// Message from the inner exception when exposed.
    /// </summary>
    public string? InnerExceptionMessage { get; init; }

    /// <summary>
    /// Arbitrary contextual metadata that was provided during handling.
    /// </summary>
    public IReadOnlyDictionary<string, object?> Metadata { get; init; } =
        new Dictionary<string, object?>();
}

/// <summary>
/// Advanced exception handling abstraction that produces consistent descriptors.
/// </summary>
public interface IExceptionHandlingService
{
    /// <summary>
    /// Generates a descriptor using the currently configured options.
    /// </summary>
    ExceptionDescriptor CreateDescriptor(Exception exception, IDictionary<string, object?>? metadata = null);

    /// <summary>
    /// Generates a descriptor using explicit options that override the current configuration.
    /// </summary>
    ExceptionDescriptor CreateDescriptor(
        Exception exception,
        ExceptionHandlingOptions overrideOptions,
        IDictionary<string, object?>? metadata = null);

    /// <summary>
    /// Produces a log-friendly message from the descriptor.
    /// </summary>
    string BuildLogMessage(ExceptionDescriptor descriptor);
}
