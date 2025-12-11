using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace DotNetSecurityToolkit.Core.Tests.Helpers;

internal sealed class FakeSession : ISession
{
    private readonly Dictionary<string, byte[]> _store = new();

    public IEnumerable<string> Keys => _store.Keys;

    public string Id { get; } = Guid.NewGuid().ToString();

    public bool IsAvailable { get; private set; } = true;

    public void Clear() => _store.Clear();

    public Task CommitAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    public Task LoadAsync(CancellationToken cancellationToken = default)
    {
        IsAvailable = true;
        return Task.CompletedTask;
    }

    public void Remove(string key)
    {
        _store.Remove(key);
    }

    public void Set(string key, byte[] value)
    {
        _store[key] = value.ToArray();
    }

    public bool TryGetValue(string key, out byte[] value)
    {
        if (_store.TryGetValue(key, out var stored))
        {
            value = stored.ToArray();
            return true;
        }

        value = Array.Empty<byte>();
        return false;
    }
}
