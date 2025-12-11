using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Audit;
using DotNetSecurityToolkit.Core.Tests.Helpers;
using FluentAssertions;

namespace DotNetSecurityToolkit.Core.Tests;

public class LoggerAuditSinkTests
{
    [Fact]
    public async Task WriteAsync_LogsAuditEvent()
    {
        var logger = new FakeLogger<LoggerAuditSink>();
        var sink = new LoggerAuditSink(logger);

        await sink.WriteAsync(new SecurityAuditEvent("login", "user"));

        logger.Entries.Should().HaveCount(1);
        logger.Entries[0].Message.Should().Contain("login");
    }
}
