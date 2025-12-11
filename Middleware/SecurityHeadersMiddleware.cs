using DotNetSecurityToolkit.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Middleware;

/// <summary>
/// Adds modern security headers including HSTS, CSP, and referrer policy.
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SecurityHeadersOptions _options;

    public SecurityHeadersMiddleware(RequestDelegate next, IOptions<SecurityHeadersOptions> options)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (_options.EnableHsts)
        {
            context.Response.Headers.StrictTransportSecurity = "max-age=63072000; includeSubDomains";
        }

        if (_options.EnableContentTypeOptions)
        {
            context.Response.Headers.XContentTypeOptions = "nosniff";
        }

        if (_options.EnableFrameOptions)
        {
            context.Response.Headers.XFrameOptions = _options.FrameOptions;
        }

        if (_options.EnableReferrerPolicy)
        {
            context.Response.Headers["Referrer-Policy"] = _options.ReferrerPolicy;
        }

        if (_options.EnableCsp)
        {
            context.Response.Headers.ContentSecurityPolicy = _options.ContentSecurityPolicy;
        }

        await _next(context);
    }
}
