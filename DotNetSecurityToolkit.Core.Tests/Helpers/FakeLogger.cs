using Microsoft.Extensions.Logging;

namespace DotNetSecurityToolkit.Core.Tests.Helpers;

internal sealed class FakeLogger<T> : ILogger<T>
{
    public List<LogEntry> Entries { get; } = new();

    public IDisposable BeginScope<TState>(TState state) => new NoopDisposable();

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        Entries.Add(new LogEntry(logLevel, formatter(state, exception), exception));
    }

    internal sealed record LogEntry(LogLevel Level, string Message, Exception? Exception);

    private sealed class NoopDisposable : IDisposable
    {
        public void Dispose()
        {
        }
    }
}
