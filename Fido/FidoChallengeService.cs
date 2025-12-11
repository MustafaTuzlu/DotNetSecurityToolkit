using System.Security.Cryptography;
using DotNetSecurityToolkit.Abstractions;
using System.Collections.Concurrent;

namespace DotNetSecurityToolkit.Fido;

/// <summary>
/// Minimal WebAuthn/FIDO2 challenge generator for demonstration purposes.
/// </summary>
public sealed class FidoChallengeService : IFidoChallengeService
{
    private readonly ConcurrentDictionary<string, FidoChallenge> _challenges = new();

    public FidoChallenge CreateChallenge(string userId, TimeSpan? lifetime = null)
    {
        var deviceId = Guid.NewGuid().ToString("N");
        var challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var expires = DateTimeOffset.UtcNow.Add(lifetime ?? TimeSpan.FromMinutes(5));
        var record = new FidoChallenge(userId, challenge, deviceId, expires);
        _challenges[challenge] = record;
        return record;
    }

    public bool ValidateChallenge(string userId, string challenge, string deviceId)
    {
        if (_challenges.TryGetValue(challenge, out var record))
        {
            var valid = record.UserId == userId && record.DeviceId == deviceId && record.ExpiresAt > DateTimeOffset.UtcNow;
            if (valid)
            {
                _challenges.TryRemove(challenge, out _);
            }

            return valid;
        }

        return false;
    }
}
