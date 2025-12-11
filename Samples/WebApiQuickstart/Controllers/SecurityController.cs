using DotNetSecurityToolkit.Abstractions;
using Microsoft.AspNetCore.Mvc;
using WebApiQuickstart.Models;

namespace WebApiQuickstart.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SecurityController : ControllerBase
{
    private readonly IEncryptionService _encryptionService;
    private readonly IUrlEncoder _urlEncoder;
    private readonly ISessionManager _sessionManager;

    public SecurityController(
        IEncryptionService encryptionService,
        IUrlEncoder urlEncoder,
        ISessionManager sessionManager)
    {
        _encryptionService = encryptionService;
        _urlEncoder = urlEncoder;
        _sessionManager = sessionManager;
    }

    [HttpPost("encrypt")]
    public IActionResult Encrypt(EncryptRequest request)
    {
        var cipher = _encryptionService.Encrypt(request.PlainText);
        var roundTrip = _encryptionService.Decrypt(cipher);

        return Ok(new { cipher, roundTrip });
    }

    [HttpPost("url-safe")]
    public IActionResult UrlSafe([FromBody] string value)
    {
        var encoded = _urlEncoder.ToUrlSafeBase64(System.Text.Encoding.UTF8.GetBytes(value));
        var slug = _urlEncoder.Slugify(value);
        return Ok(new { encoded, slug });
    }

    [HttpPost("session")]
    public IActionResult SaveSession(SessionItemRequest request)
    {
        _sessionManager.SetEncrypted(request.Key, request.Value);
        var token = _sessionManager.GetOrCreateSessionToken();
        return Accepted(new { request.Key, request.Value, sessionToken = token });
    }

    [HttpGet("session/{key}")]
    public IActionResult ReadSession(string key)
    {
        var value = _sessionManager.GetDecrypted(key);
        return value is null ? NotFound() : Ok(new { key, value });
    }
}
