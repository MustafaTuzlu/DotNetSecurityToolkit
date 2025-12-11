using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Middleware.RateLimiting;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Core.Tests;

public class RateLimitingMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_Returns429WhenLimitExceeded()
    {
        var options = Options.Create(new RateLimitingOptions
        {
            Enabled = true,
            RequestsPerWindow = 1,
            WindowSeconds = 60,
            EmitRetryAfterHeader = true
        });

        var cache = new MemoryCache(new MemoryCacheOptions());
        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new RateLimitingMiddleware(next, options, cache);

        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");

        await middleware.InvokeAsync(context);
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);

        context.Response.Clear();
        await middleware.InvokeAsync(context);
        context.Response.StatusCode.Should().Be(StatusCodes.Status429TooManyRequests);
        context.Response.Headers.RetryAfter.Should().NotBeNull();
    }
}
