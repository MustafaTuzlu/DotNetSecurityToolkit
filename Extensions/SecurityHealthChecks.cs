using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace DotNetSecurityToolkit.Extensions;

/// <summary>
/// Adds health checks that validate cryptographic configuration strength.
/// </summary>
public static class SecurityHealthChecks
{
    public static IHealthChecksBuilder AddSecurityToolkitHealthChecks(this IServiceCollection services)
    {
        return services.AddHealthChecks().AddCheck<SecurityToolkitHealthCheck>("security-toolkit");
    }
}

internal sealed class SecurityToolkitHealthCheck : IHealthCheck
{
    private readonly SecurityToolkitOptions _options;
    private readonly JwtOptions _jwtOptions;

    public SecurityToolkitHealthCheck(IOptions<SecurityToolkitOptions> options, IOptions<JwtOptions> jwtOptions)
    {
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
        _jwtOptions = jwtOptions.Value ?? new JwtOptions();
    }

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(_options.SecretKey) || _options.SecretKey.Length < 32)
        {
            errors.Add("SecretKey must be at least 32 characters.");
        }

        if (_options.PasswordHashIterations < _options.MinimumPasswordHashIterations)
        {
            errors.Add("PasswordHashIterations below enforced minimum.");
        }

        if (!string.IsNullOrWhiteSpace(_jwtOptions.SigningKey) && _jwtOptions.SigningKey.Length < 32)
        {
            errors.Add("JWT signing key must be at least 32 characters.");
        }

        return errors.Count == 0
            ? Task.FromResult(HealthCheckResult.Healthy())
            : Task.FromResult(HealthCheckResult.Unhealthy(string.Join(" ", errors)));
    }
}
