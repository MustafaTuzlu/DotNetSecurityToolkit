using DotNetSecurityToolkit.Abstractions;
using DotNetSecurityToolkit.Configuration;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;

namespace DotNetSecurityToolkit.Jwt;

/// <summary>
/// Simple in-memory refresh token store that supports device binding.
/// </summary>
public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly RefreshTokenOptions _options;
    private readonly ConcurrentDictionary<string, RefreshTokenEntry> _tokens = new();

    public InMemoryRefreshTokenStore(IOptions<RefreshTokenOptions> options)
    {
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
    }

    public Task StoreAsync(RefreshTokenEntry entry, CancellationToken cancellationToken = default)
    {
        _tokens[entry.Token] = entry with { ExpiresAt = entry.ExpiresAt == default ? DateTimeOffset.UtcNow.AddDays(_options.LifetimeDays) : entry.ExpiresAt };
        return Task.CompletedTask;
    }

    public Task<RefreshTokenEntry?> GetAsync(string token, CancellationToken cancellationToken = default)
    {
        if (_tokens.TryGetValue(token, out var entry))
        {
            if (entry.ExpiresAt < DateTimeOffset.UtcNow || entry.Revoked)
            {
                return Task.FromResult<RefreshTokenEntry?>(null);
            }

            return Task.FromResult<RefreshTokenEntry?>(entry);
        }

        return Task.FromResult<RefreshTokenEntry?>(null);
    }

    public Task RevokeAsync(string token, CancellationToken cancellationToken = default)
    {
        if (_tokens.TryGetValue(token, out var entry))
        {
            _tokens[token] = entry with { Revoked = true };
        }

        return Task.CompletedTask;
    }
}
