using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using DotNetSecurityToolkit.Jwt;
using FluentAssertions;
using Microsoft.Extensions.Options;

namespace DotNetSecurityToolkit.Core.Tests;

public class InMemoryRefreshTokenStoreTests
{
    [Fact]
    public async Task StoreAndRetrieve_PersistsUntilExpiry()
    {
        var store = new InMemoryRefreshTokenStore(Options.Create(new RefreshTokenOptions { LifetimeDays = 1 }));
        var entry = new RefreshTokenEntry("token", "sub", "device", DateTimeOffset.UtcNow.AddHours(1), new Dictionary<string, string?>());

        await store.StoreAsync(entry);
        var fetched = await store.GetAsync("token");

        fetched.Should().NotBeNull();
        fetched!.SubjectId.Should().Be("sub");

        await store.RevokeAsync("token");
        var revoked = await store.GetAsync("token");
        revoked.Should().BeNull();
    }

    [Fact]
    public async Task GetAsync_ReturnsNullWhenExpired()
    {
        var store = new InMemoryRefreshTokenStore(Options.Create(new RefreshTokenOptions { LifetimeDays = 1 }));
        var entry = new RefreshTokenEntry("token", "sub", "device", DateTimeOffset.UtcNow.AddDays(-1), new Dictionary<string, string?>());
        await store.StoreAsync(entry);

        var fetched = await store.GetAsync("token");
        fetched.Should().BeNull();
    }
}
