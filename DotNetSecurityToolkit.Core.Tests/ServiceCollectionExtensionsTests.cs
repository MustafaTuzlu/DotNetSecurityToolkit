using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Extensions;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DotNetSecurityToolkit.Core.Tests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddDotNetSecurityToolkit_RegistersCoreServices()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{SecurityToolkitOptions.SectionName}:{KeyRotationOptions.SectionName}:EncryptionKeys:primary"] = "key",
            [$"{SecurityToolkitOptions.SectionName}:{KeyRotationOptions.SectionName}:CurrentKeyId"] = "primary"
        }).Build();

        var services = new ServiceCollection();
        services.AddDotNetSecurityToolkit(configuration);
        var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IEncryptionService>().Should().NotBeNull();
        provider.GetRequiredService<IPasswordHasher>().Should().NotBeNull();
        provider.GetRequiredService<ISessionManager>().Should().NotBeNull();
    }
}
