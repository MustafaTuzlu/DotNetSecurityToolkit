using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Cookies;
using DotNetSecurityToolkit.Crypto;
using DotNetSecurityToolkit.Url;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DotNetSecurityToolkit.Extensions;

/// <summary>
/// Service registration helpers for DotNetSecurityToolkit.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all toolkit services and binds options from configuration section "DotNetSecurityToolkit".
    /// </summary>
    public static IServiceCollection AddDotNetSecurityToolkit(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        services.Configure<SecurityToolkitOptions>(
            configuration.GetSection(SecurityToolkitOptions.SectionName));

        RegisterCore(services);

        return services;
    }

    /// <summary>
    /// Registers all toolkit services using an options delegate instead of IConfiguration.
    /// </summary>
    public static IServiceCollection AddDotNetSecurityToolkit(
        this IServiceCollection services,
        Action<SecurityToolkitOptions> configureOptions)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        if (configureOptions is null)
        {
            throw new ArgumentNullException(nameof(configureOptions));
        }

        services.Configure(configureOptions);

        RegisterCore(services);

        return services;
    }

    private static void RegisterCore(IServiceCollection services)
    {
        services.AddHttpContextAccessor();

        services.AddSingleton<IUrlEncoder, UrlEncoderService>();
        services.AddSingleton<IEncryptionService, AesEncryptionService>();
        services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.AddScoped<ICookieManager, CookieManager>();
    }
}
