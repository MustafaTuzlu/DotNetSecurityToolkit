using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.AntiForgery;
using DotNetSecurityToolkit.Audit;
using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Cookies;
using DotNetSecurityToolkit.Crypto;
using DotNetSecurityToolkit.Exceptions;
using DotNetSecurityToolkit.Fido;
using DotNetSecurityToolkit.Jwt;
using DotNetSecurityToolkit.Middleware.RateLimiting;
using DotNetSecurityToolkit.Session;
using DotNetSecurityToolkit.Telemetry;
using DotNetSecurityToolkit.Url;
using DotNetSecurityToolkit.Validation;
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
        services.Configure<ExceptionHandlingOptions>(
            configuration.GetSection(SecurityToolkitOptions.SectionName)
                .GetSection(ExceptionHandlingOptions.SectionName));
        services.Configure<KeyRotationOptions>(
            configuration.GetSection(SecurityToolkitOptions.SectionName)
                .GetSection(KeyRotationOptions.SectionName));
        services.Configure<RateLimitingOptions>(
            configuration.GetSection(SecurityToolkitOptions.SectionName)
                .GetSection(RateLimitingOptions.SectionName));
        services.Configure<RefreshTokenOptions>(
            configuration.GetSection(SecurityToolkitOptions.SectionName)
                .GetSection(RefreshTokenOptions.SectionName));
        services.Configure<SecurityHeadersOptions>(
            configuration.GetSection(SecurityToolkitOptions.SectionName)
                .GetSection(SecurityHeadersOptions.SectionName));
        services.Configure<TelemetryOptions>(
            configuration.GetSection(SecurityToolkitOptions.SectionName)
                .GetSection(TelemetryOptions.SectionName));

        RegisterCore(services);

        return services;
    }

    /// <summary>
    /// Registers all toolkit services using an options delegate instead of IConfiguration.
    /// </summary>
    public static IServiceCollection AddDotNetSecurityToolkit(
        this IServiceCollection services,
        Action<SecurityToolkitOptions> configureOptions,
        Action<ExceptionHandlingOptions>? configureExceptionHandling = null)
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
        services.Configure(configureExceptionHandling ?? (_ => { }));
        services.Configure<KeyRotationOptions>(_ => { });
        services.Configure<RateLimitingOptions>(_ => { });
        services.Configure<RefreshTokenOptions>(_ => { });
        services.Configure<SecurityHeadersOptions>(_ => { });
        services.Configure<TelemetryOptions>(_ => { });

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
        services.AddSession();
        services.AddMemoryCache();
        services.AddDataProtection();

        services.AddSingleton<ISecurityEventSink, SecurityEventSink>();
        services.AddSingleton<IKeyRing, KeyRing>();
        services.AddSingleton<DataProtectionEncryptionService>();
        services.AddSingleton<AesEncryptionService>();
        services.AddSingleton<CompositeEncryptionService>();
        services.AddSingleton<IEncryptionService>(sp => sp.GetRequiredService<CompositeEncryptionService>());
        services.AddSingleton<IUrlEncoder, UrlEncoderService>();
        services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.AddSingleton<IExceptionHandlingService, ExceptionHandlingService>();
        services.AddSingleton<IAuditSink, LoggerAuditSink>();
        services.AddSingleton<IInputSanitizer, InputSanitizer>();
        services.AddSingleton<IFidoChallengeService, FidoChallengeService>();
        services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        services.AddSingleton<IAntiForgeryService, AntiForgeryService>();
        services.AddScoped<ICookieManager, CookieManager>();
        services.AddScoped<ISessionManager, SessionManager>();
    }

    private static void RegisterJwt(IServiceCollection services)
    {
        services.AddSingleton<IJwtTokenService, JwtTokenService>();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();

        services
            .AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<JwtOptions>, IKeyRing>((options, jwtOptions, keyRing) =>
            {
                if (!keyRing.GetAll(KeyPurpose.JwtSigning).Any())
                {
                    throw new InvalidOperationException(
                        "JwtOptions.SigningKey must be configured in appsettings.json (section 'DotNetSecurityToolkit:Jwt').");
                }

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeyResolver = (_, _, _, _) =>
                    {
                        return keyRing.GetAll(KeyPurpose.JwtSigning)
                            .Select(material => new SymmetricSecurityKey(Encoding.UTF8.GetBytes(material.Value))
                            {
                                KeyId = material.KeyId
                            });
                    },
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
