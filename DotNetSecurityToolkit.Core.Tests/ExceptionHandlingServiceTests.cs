using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Exceptions;
using FluentAssertions;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Core.Tests;

public class ExceptionHandlingServiceTests
{
    private static ExceptionHandlingService CreateService(ExceptionHandlingOptions? options = null)
    {
        options ??= new ExceptionHandlingOptions();
        var monitor = MockOptionsMonitor.Create(options);
        return new ExceptionHandlingService(monitor);
    }

    [Fact]
    public void CreateDescriptor_UsesMappingsAndOverrides()
    {
        var options = new ExceptionHandlingOptions
        {
            ExceptionCodeMapping = { [typeof(InvalidOperationException).FullName!] = "invalid-op" },
            ExceptionMessageOverrides = { [typeof(InvalidOperationException).FullName!] = "custom" },
            ExposeExceptionMessages = false,
            IncludeExceptionType = true,
            IncludeInnerExceptionMessage = true
        };

        var service = CreateService(options);
        var descriptor = service.CreateDescriptor(new InvalidOperationException("secret", new Exception("inner")), options, new Dictionary<string, object?> { ["key"] = "value" });

        descriptor.Code.Should().Be("invalid-op");
        descriptor.Message.Should().Be("custom");
        descriptor.ExceptionType.Should().Contain(nameof(InvalidOperationException));
        descriptor.InnerExceptionMessage.Should().Be("inner");
        descriptor.Metadata.Should().ContainKey("key");
    }

    [Fact]
    public void BuildLogMessage_IncludesMetadata()
    {
        var service = CreateService();
        var descriptor = new Abstractions.ExceptionDescriptor
        {
            Code = "ERR",
            Message = "Problem",
            Metadata = new Dictionary<string, object?> { ["a"] = 1 }
        };

        service.BuildLogMessage(descriptor).Should().Contain("a=1");
    }
}

internal static class MockOptionsMonitor
{
    public static IOptionsMonitor<T> Create<T>(T value) where T : class
    {
        return new TestOptionsMonitor<T>(value);
    }

    private sealed class TestOptionsMonitor<T> : IOptionsMonitor<T> where T : class
    {
        public TestOptionsMonitor(T value)
        {
            CurrentValue = value;
        }

        public T CurrentValue { get; }

        public T Get(string? name) => CurrentValue;

        public IDisposable OnChange(Action<T, string> listener) => new NoopDisposable();

        private sealed class NoopDisposable : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }
}
