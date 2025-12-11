using System.Linq;
using System.Text;
using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Exceptions;

/// <summary>
/// Default implementation for creating standardized exception descriptors.
/// </summary>
public sealed class ExceptionHandlingService : IExceptionHandlingService
{
    private readonly IOptionsMonitor<ExceptionHandlingOptions> _options;

    public ExceptionHandlingService(IOptionsMonitor<ExceptionHandlingOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc />
    public ExceptionDescriptor CreateDescriptor(Exception exception, IDictionary<string, object?>? metadata = null)
    {
        return CreateDescriptor(exception, _options.CurrentValue, metadata);
    }

    /// <inheritdoc />
    public ExceptionDescriptor CreateDescriptor(
        Exception exception,
        ExceptionHandlingOptions overrideOptions,
        IDictionary<string, object?>? metadata = null)
    {
        if (exception is null)
        {
            throw new ArgumentNullException(nameof(exception));
        }

        if (overrideOptions is null)
        {
            throw new ArgumentNullException(nameof(overrideOptions));
        }

        var selectedException = overrideOptions.UseInnermostException
            ? GetInnermostException(exception)
            : exception;

        var code = ResolveErrorCode(selectedException, overrideOptions);
        var message = ResolveMessage(selectedException, overrideOptions);

        return new ExceptionDescriptor
        {
            Code = code,
            Message = message,
            ExceptionType = overrideOptions.IncludeExceptionType
                ? selectedException.GetType().FullName
                : null,
            StackTrace = overrideOptions.IncludeStackTrace
                ? selectedException.StackTrace
                : null,
            InnerExceptionMessage = overrideOptions.IncludeInnerExceptionMessage
                ? selectedException.InnerException?.Message
                : null,
            Metadata = metadata is null
                ? new Dictionary<string, object?>()
                : new Dictionary<string, object?>(metadata)
        };
    }

    /// <inheritdoc />
    public string BuildLogMessage(ExceptionDescriptor descriptor)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        var builder = new StringBuilder();
        builder.Append('[').Append(descriptor.Code).Append("] ").Append(descriptor.Message);

        if (!string.IsNullOrWhiteSpace(descriptor.ExceptionType))
        {
            builder.Append(" (" ).Append(descriptor.ExceptionType).Append(')');
        }

        if (!string.IsNullOrWhiteSpace(descriptor.InnerExceptionMessage))
        {
            builder.Append(" | Inner: ").Append(descriptor.InnerExceptionMessage);
        }

        if (descriptor.Metadata.Count > 0)
        {
            builder.Append(" | Metadata: ");
            builder.Append(string.Join(", ", descriptor.Metadata.Select(kvp => $"{kvp.Key}={kvp.Value}")));
        }

        if (!string.IsNullOrWhiteSpace(descriptor.StackTrace))
        {
            builder.Append("\n").Append(descriptor.StackTrace);
        }

        return builder.ToString();
    }

    private static Exception GetInnermostException(Exception exception)
    {
        var current = exception;
        while (current.InnerException is not null)
        {
            current = current.InnerException;
        }

        return current;
    }

    private static string ResolveErrorCode(Exception exception, ExceptionHandlingOptions options)
    {
        var exceptionType = exception.GetType().FullName ?? exception.GetType().Name;

        if (options.ExceptionCodeMapping.TryGetValue(exceptionType, out var mappedCode) &&
            !string.IsNullOrWhiteSpace(mappedCode))
        {
            return mappedCode;
        }

        return options.DefaultErrorCode;
    }

    private static string ResolveMessage(Exception exception, ExceptionHandlingOptions options)
    {
        var exceptionType = exception.GetType().FullName ?? exception.GetType().Name;

        if (!options.ExposeExceptionMessages)
        {
            if (options.ExceptionMessageOverrides.TryGetValue(exceptionType, out var overriddenMessage) &&
                !string.IsNullOrWhiteSpace(overriddenMessage))
            {
                return overriddenMessage;
            }

            return options.DefaultMessage;
        }

        return string.IsNullOrWhiteSpace(exception.Message)
            ? options.DefaultMessage
            : exception.Message;
    }
}
