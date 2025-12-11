using DotNetSecurityToolkit.Middleware;
using DotNetSecurityToolkit.Middleware.RateLimiting;
using Microsoft.AspNetCore.Builder;

namespace DotNetSecurityToolkit.Extensions;

/// <summary>
/// Middleware registration helpers for the toolkit.
/// </summary>
public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseSecurityToolkitHeaders(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SecurityHeadersMiddleware>();
    }

    public static IApplicationBuilder UseSecurityToolkitRateLimiting(this IApplicationBuilder app)
    {
        return app.UseMiddleware<RateLimitingMiddleware>();
    }
}
