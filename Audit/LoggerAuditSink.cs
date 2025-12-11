using DotNetSecurityToolkit.Abstractions;
using Microsoft.Extensions.Logging;

namespace DotNetSecurityToolkit.Audit;

/// <summary>
/// Default audit sink that writes events to ILogger.
/// </summary>
public sealed class LoggerAuditSink : IAuditSink
{
    private readonly ILogger<LoggerAuditSink> _logger;

    public LoggerAuditSink(ILogger<LoggerAuditSink> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task WriteAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Audit: {EventType} by {Subject} at {OccurredAt} - {Description} {@Metadata}",
            auditEvent.EventType,
            auditEvent.Subject,
            auditEvent.OccurredAt,
            auditEvent.Description,
            auditEvent.Metadata);

        return Task.CompletedTask;
    }
}
