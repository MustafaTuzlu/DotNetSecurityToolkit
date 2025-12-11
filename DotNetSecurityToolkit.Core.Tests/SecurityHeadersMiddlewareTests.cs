using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Middleware;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Core.Tests;

public class SecurityHeadersMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_AddsConfiguredHeaders()
    {
        var options = Options.Create(new SecurityHeadersOptions
        {
            EnableCsp = true,
            ContentSecurityPolicy = "default-src 'self'",
            EnableHsts = true,
            EnableFrameOptions = true,
            FrameOptions = "DENY",
            EnableReferrerPolicy = true,
            ReferrerPolicy = "no-referrer"
        });

        var called = false;
        RequestDelegate next = _ => { called = true; return Task.CompletedTask; };
        var middleware = new SecurityHeadersMiddleware(next, options);
        var context = new DefaultHttpContext();

        await middleware.InvokeAsync(context);

        called.Should().BeTrue();
        context.Response.Headers.ContentSecurityPolicy.Should().Be("default-src 'self'");
        context.Response.Headers.StrictTransportSecurity.Should().NotBeNull();
        context.Response.Headers.XFrameOptions.Should().Be("DENY");
    }
}
