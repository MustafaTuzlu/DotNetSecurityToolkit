using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Core.Tests.Helpers;
using DotNetSecurityToolkit.Telemetry;
using FluentAssertions;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Core.Tests;

public class SecurityEventSinkTests
{
    [Fact]
    public void BeginScope_ReturnsNullWhenDisabled()
    {
        var logger = new FakeLogger<SecurityEventSink>();
        var sink = new SecurityEventSink(logger, Options.Create(new TelemetryOptions { Enabled = false }));

        sink.BeginScope("test").Should().BeNull();
        sink.Record("evt");
        logger.Entries.Should().BeEmpty();
    }

    [Fact]
    public void Record_EmitsLogWhenEnabled()
    {
        var logger = new FakeLogger<SecurityEventSink>();
        var sink = new SecurityEventSink(logger, Options.Create(new TelemetryOptions { Enabled = true }));

        sink.Record("evt", new Dictionary<string, object?> { ["a"] = 1 });

        logger.Entries.Should().HaveCount(1);
        logger.Entries[0].Message.Should().Contain("evt");
    }
}
