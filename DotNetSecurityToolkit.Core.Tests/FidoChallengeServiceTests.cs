using DotNetSecurityToolkit.Fido;
using FluentAssertions;

namespace DotNetSecurityToolkit.Core.Tests;

public class FidoChallengeServiceTests
{
    [Fact]
    public void ChallengeAndValidation_Flows()
    {
        var service = new FidoChallengeService();
        var challenge = service.CreateChallenge("user");

        service.ValidateChallenge("user", challenge.Challenge, challenge.DeviceId).Should().BeTrue();
        service.ValidateChallenge("user", challenge.Challenge, challenge.DeviceId).Should().BeFalse();
    }
}
