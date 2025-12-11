# DotNetSecurityToolkit

DotNetSecurityToolkit provides reusable security helpers for ASP.NET Core apps. It wraps password hashing, symmetric encryption, secure cookies, URL-safe helpers, session utilities, and JWT token creation into a single registration call so you can start new Web API projects quickly.

## Getting started in a new Web API

1. Add a project reference to `DotNetSecurityToolkit.Core.csproj` (or the NuGet package when published).
2. Add configuration to `appsettings.json`:

```json
{
  "DotNetSecurityToolkit": {
    "SecretKey": "change-me-super-secret-key-change-me",
    "PasswordHashIterations": 120000,
    "PasswordSaltSize": 16,
    "PasswordKeySize": 32,
    "Jwt": {
      "Issuer": "dotnet-security-toolkit-sample",
      "Audience": "dotnet-security-toolkit-clients",
      "SigningKey": "change-me-very-secret-signing-key",
      "AccessTokenExpirationMinutes": 60,
      "ValidateLifetime": true
    }
  }
}
```

3. Register the toolkit services in `Program.cs`:

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();

// Bind options from configuration and enable JWT authentication.
builder.Services.AddDotNetSecurityToolkitWithJwt(builder.Configuration);

var app = builder.Build();

app.UseHttpsRedirection();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
```

The toolkit registers `IEncryptionService`, `IPasswordHasher`, `IUrlEncoder`, `ICookieManager`, `ISessionManager`, and `IJwtTokenService`. Sessions are enabled automatically, and JWT bearer authentication is configured with the provided options.

## Sample Web API template

A full, ready-to-run example is available under [`Samples/WebApiQuickstart`](Samples/WebApiQuickstart). It shows how to:

- Issue JWT access tokens with `IJwtTokenService`.
- Store encrypted refresh tokens in secure cookies with `ICookieManager`.
- Hash and verify passwords with `IPasswordHasher`.
- Use `ISessionManager` to persist encrypted session data.
- Encode URL-safe values with `IUrlEncoder`.

Run it with `dotnet run` from the sample directory after restoring packages.

## Usage snippets

### Hashing passwords
```csharp
public class AccountService
{
    private readonly IPasswordHasher _passwordHasher;
    public AccountService(IPasswordHasher passwordHasher) => _passwordHasher = passwordHasher;

    public string CreateUser(string email, string password)
    {
        var hash = _passwordHasher.HashPassword(password);
        // persist hash to your user store
        return hash;
    }
}
```

### Creating and validating JWT tokens
```csharp
var claims = new Dictionary<string, string?>
{
    [JwtRegisteredClaimNames.Sub] = userId,
    [JwtRegisteredClaimNames.Email] = email
};

string accessToken = jwtTokenService.CreateTokenFromDictionary(claims);
ClaimsPrincipal? principal = jwtTokenService.ValidateToken(accessToken);
```

### Working with secure cookies
```csharp
_cookieManager.SetEncryptedCookie("refresh-token", refreshToken, DateTimeOffset.UtcNow.AddDays(7));
if (_cookieManager.TryGetDecryptedCookie("refresh-token", out var token))
{
    // token contains decrypted value
}
```

### Encrypting arbitrary payloads
```csharp
var cipher = encryptionService.EncryptObject(new { Message = "secret" });
var payload = encryptionService.DecryptObject<Dictionary<string, string>>(cipher);

// When you need a non-throwing variant, use TryDecrypt/TryDecryptObject to safely
// inspect cookies or session values without exception handling.
if (encryptionService.TryDecryptObject(cipher, out Dictionary<string, string>? safePayload))
{
    // safePayload is only set when the MAC and JSON payload are both valid
}
```

### Using the session helper
```csharp
_sessionManager.SetEncrypted("cart", "123-456");
string? cartId = _sessionManager.GetDecrypted("cart");
```

With these helpers you can start a secure Web API with common building blocks already wired up.
