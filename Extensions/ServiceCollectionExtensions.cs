using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Cookies;
using DotNetSecurityToolkit.Crypto;
using DotNetSecurityToolkit.Jwt;
using DotNetSecurityToolkit.Url;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;

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

    /// <summary>
    /// Registers toolkit services and configures JWT authentication using configuration section "DotNetSecurityToolkit:Jwt".
    /// </summary>
    public static IServiceCollection AddDotNetSecurityToolkitWithJwt(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services = services.AddDotNetSecurityToolkit(configuration);
        return services.AddJwtAuthentication(configuration);
    }

    /// <summary>
    /// Registers toolkit services and configures JWT authentication using an options delegate.
    /// </summary>
    public static IServiceCollection AddDotNetSecurityToolkitWithJwt(
        this IServiceCollection services,
        Action<SecurityToolkitOptions> configureToolkitOptions,
        Action<JwtOptions> configureJwtOptions)
    {
        services = services.AddDotNetSecurityToolkit(configureToolkitOptions);
        return services.AddJwtAuthentication(configureJwtOptions);
    }

    /// <summary>
    /// Configures JWT bearer authentication using configuration section "DotNetSecurityToolkit:Jwt".
    /// </summary>
    public static IServiceCollection AddJwtAuthentication(
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

        services.Configure<JwtOptions>(
            configuration.GetSection(SecurityToolkitOptions.SectionName)
                .GetSection(JwtOptions.SectionName));

        RegisterJwt(services);

        return services;
    }

    /// <summary>
    /// Configures JWT bearer authentication using an options delegate.
    /// </summary>
    public static IServiceCollection AddJwtAuthentication(
        this IServiceCollection services,
        Action<JwtOptions> configureOptions)
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

        RegisterJwt(services);

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

    private static void RegisterJwt(IServiceCollection services)
    {
        services.AddSingleton<IJwtTokenService, JwtTokenService>();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();

        services
            .AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<JwtOptions>>((options, jwtOptions) =>
            {
                if (string.IsNullOrWhiteSpace(jwtOptions.Value.SigningKey))
                {
                    throw new InvalidOperationException(
                        "JwtOptions.SigningKey must be configured in appsettings.json (section 'DotNetSecurityToolkit:Jwt').");
                }

                var keyBytes = Encoding.UTF8.GetBytes(jwtOptions.Value.SigningKey);
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
                    ValidateIssuer = !string.IsNullOrWhiteSpace(jwtOptions.Value.Issuer),
                    ValidateAudience = !string.IsNullOrWhiteSpace(jwtOptions.Value.Audience),
                    ValidIssuer = jwtOptions.Value.Issuer,
                    ValidAudience = jwtOptions.Value.Audience,
                    ValidateLifetime = jwtOptions.Value.ValidateLifetime,
                    ClockSkew = TimeSpan.Zero
                };
            });
    }
}
