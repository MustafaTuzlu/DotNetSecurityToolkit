using System.Diagnostics;
using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Telemetry;

/// <summary>
/// Emits security telemetry via ILogger and ActivitySource.
/// </summary>
public sealed class SecurityEventSink : ISecurityEventSink
{
    private static readonly ActivitySource ActivitySource = new("DotNetSecurityToolkit.Security");
    private readonly ILogger<SecurityEventSink> _logger;
    private readonly TelemetryOptions _options;

    public SecurityEventSink(ILogger<SecurityEventSink> logger, IOptions<TelemetryOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
    }

    public Activity? BeginScope(string name, IDictionary<string, object?>? tags = null)
    {
        if (!_options.Enabled)
        {
            return null;
        }

        var activity = ActivitySource.StartActivity(name, ActivityKind.Internal);
        if (activity is not null && tags is not null)
        {
            foreach (var tag in tags)
            {
                activity.AddTag(tag.Key, tag.Value);
            }
        }

        return activity;
    }

    public void Record(string eventName, IDictionary<string, object?>? properties = null)
    {
        if (!_options.Enabled)
        {
            return;
        }

        using var activity = ActivitySource.StartActivity(eventName, ActivityKind.Internal);
        if (activity is not null && properties is not null)
        {
            foreach (var property in properties)
            {
                activity.AddTag(property.Key, property.Value);
            }
        }

        _logger.LogInformation("Security event {Event} {@Properties}", eventName, properties);
    }
}
