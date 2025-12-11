using Microsoft.Extensions.Configuration;

namespace DotNetSecurityToolkit.Extensions;

/// <summary>
/// Convenience helpers for registering common secret sources.
/// </summary>
public static class SecretsExtensions
{
    public static IConfigurationBuilder AddSecurityToolkitEnvironmentSecrets(this IConfigurationBuilder builder, string prefix = "DOTNETSECURITYTOOLKIT_")
    {
        return builder.AddEnvironmentVariables(prefix);
    }

    public static IConfigurationBuilder AddSecurityToolkitInMemorySecrets(this IConfigurationBuilder builder, IDictionary<string, string?> secrets)
    {
        return builder.AddInMemoryCollection(secrets);
    }
}
