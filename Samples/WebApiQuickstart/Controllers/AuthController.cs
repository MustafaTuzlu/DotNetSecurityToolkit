using System.IdentityModel.Tokens.Jwt;
using DotNetSecurityToolkit.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApiQuickstart.Models;

namespace WebApiQuickstart.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private static readonly Dictionary<string, string> Users = new(StringComparer.OrdinalIgnoreCase);

    private readonly IPasswordHasher _passwordHasher;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly ICookieManager _cookieManager;

    public AuthController(
        IPasswordHasher passwordHasher,
        IJwtTokenService jwtTokenService,
        ICookieManager cookieManager)
    {
        _passwordHasher = passwordHasher;
        _jwtTokenService = jwtTokenService;
        _cookieManager = cookieManager;
    }

    [HttpPost("register")]
    public IActionResult Register(RegisterRequest request)
    {
        if (Users.ContainsKey(request.Email))
        {
            return Conflict(new { message = "User already exists." });
        }

        var hash = _passwordHasher.HashPassword(request.Password);
        Users[request.Email] = hash;

        return CreatedAtAction(nameof(Register), new { request.Email }, new { request.Email });
    }

    [HttpPost("login")]
    public IActionResult Login(LoginRequest request)
    {
        if (!Users.TryGetValue(request.Email, out var storedHash))
        {
            return Unauthorized();
        }

        var isValid = _passwordHasher.VerifyHashedPassword(storedHash, request.Password, out var needsRehash);
        if (!isValid)
        {
            return Unauthorized();
        }

        if (needsRehash)
        {
            Users[request.Email] = _passwordHasher.HashPassword(request.Password);
        }

        var claims = new Dictionary<string, string?>
        {
            [JwtRegisteredClaimNames.Sub] = request.Email,
            [JwtRegisteredClaimNames.Email] = request.Email,
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N")
        };

        var accessToken = _jwtTokenService.CreateTokenFromDictionary(claims);
        var refreshToken = _jwtTokenService.CreateRefreshToken();

        _cookieManager.SetEncryptedCookie("refresh-token", refreshToken, DateTimeOffset.UtcNow.AddDays(7));

        return Ok(new
        {
            accessToken,
            refreshTokenCookie = "refresh-token",
            rehashed = needsRehash
        });
    }

    [Authorize]
    [HttpGet("me")]
    public IActionResult Me()
    {
        var subject = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? User.Identity?.Name;
        var email = User.FindFirst(JwtRegisteredClaimNames.Email)?.Value;

        return Ok(new { subject, email });
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        _cookieManager.DeleteCookie("refresh-token");
        return NoContent();
    }
}
