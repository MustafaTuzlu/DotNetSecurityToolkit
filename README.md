# DotNetSecurityToolkit

DotNetSecurityToolkit provides reusable security helpers for ASP.NET Core apps. It wraps password hashing, symmetric encryption, secure cookies, URL-safe helpers, session utilities, JWT token creation, and consistent exception descriptions into a single registration call so you can start new Web API projects quickly.

## Quick start for a new Web API

1. Add a project reference to `DotNetSecurityToolkit.Core.csproj` (or the NuGet package when published).
2. Provide configuration in `appsettings.json` (values shown are examples only):

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
    },
    "ExceptionHandling": {
      "IncludeStackTrace": false,
      "IncludeExceptionType": true,
      "UseInnermostException": true,
      "IncludeInnerExceptionMessage": false,
      "ExposeExceptionMessages": false,
      "DefaultMessage": "An unexpected error occurred.",
      "DefaultErrorCode": "error",
      "ExceptionCodeMapping": {},
      "ExceptionMessageOverrides": {}
    }
  }
}
```

3. Register the toolkit services in `Program.cs` (sessions require a session store such as distributed memory cache or Redis):

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

Use `AddDotNetSecurityToolkit` when you only need the core helpers, or `AddDotNetSecurityToolkitWithJwt` to wire up JWT bearer authentication alongside the helpers.

## Configuration reference

### `DotNetSecurityToolkit`
- `SecretKey`: base secret used by `AesEncryptionService` for encryption and for secure cookie/session helpers. Use at least 32 high-entropy characters.
- `PasswordHashIterations`: PBKDF2 iteration count used by `Pbkdf2PasswordHasher`.
- `PasswordSaltSize`: salt length (bytes) used when hashing passwords.
- `PasswordKeySize`: derived key length (bytes) for PBKDF2 hashes.

### `DotNetSecurityToolkit:Jwt`
Used by `JwtTokenService` and the JWT bearer authentication setup added by `AddJwtAuthentication`/`AddDotNetSecurityToolkitWithJwt`.
- `Issuer`: issuer value placed on and validated against JWTs.
- `Audience`: audience value placed on and validated against JWTs.
- `SigningKey`: symmetric key for signing and validation (use at least 32 high-entropy characters).
- `AccessTokenExpirationMinutes`: default access token lifetime for created tokens.
- `ValidateLifetime`: whether inbound JWT validation enforces expiration.

### `DotNetSecurityToolkit:ExceptionHandling`
Controls `ExceptionHandlingService`, which produces standardized exception descriptors for logging or API responses.
- `IncludeStackTrace`: attach stack traces to descriptors.
- `IncludeExceptionType`: include the full exception type name.
- `UseInnermostException`: drill down to the innermost exception before describing.
- `IncludeInnerExceptionMessage`: emit the message of the inner exception when present.
- `ExposeExceptionMessages`: expose the actual exception message; when false, fall back to configured defaults.
- `DefaultMessage`: default user-facing message when exception messages are hidden.
- `DefaultErrorCode`: fallback code when no mapping exists.
- `ExceptionCodeMapping`: per-exception-type error codes.
- `ExceptionMessageOverrides`: per-exception-type fallback messages when `ExposeExceptionMessages` is false.

## Service catalog and usage

### Password hashing (`IPasswordHasher`)
- Implements PBKDF2 with SHA-256 (`Pbkdf2PasswordHasher`).
- Hashes are stored as `{iterations}.{saltBase64}.{hashBase64}` and can be re-verified later.
- Respects `PasswordHashIterations`, `PasswordSaltSize`, and `PasswordKeySize` from configuration; `NeedsRehash` helps you rotate to stronger settings.

```csharp
var hash = _passwordHasher.HashPassword(password);
bool isValid = _passwordHasher.VerifyHashedPassword(hash, password, out bool needsRehash);
if (needsRehash)
{
    // regenerate the hash with current settings and persist it
}
```

### Encryption (`IEncryptionService`)
- AES-256-CBC with HMAC-SHA256 authentication (`AesEncryptionService`).
- Encoded payloads are URL-safe Base64 strings; `IsEncryptedPayload` can detect the format.
- Uses `SecretKey` from configuration; changing it invalidates previously encrypted values.

```csharp
var cipher = encryptionService.EncryptObject(new { Message = "secret" });
if (encryptionService.TryDecryptObject(cipher, out Dictionary<string, string>? payload))
{
    // payload now contains the decrypted JSON object
}
```

### URL helpers (`IUrlEncoder`)
- URL-safe Base64 encode/decode, slug generation, and short token creation.
- Query helpers (`EncodeQueryValue`, `AppendQueryString`) and path normalization (`EnsureTrailingSlash`, `CombinePathSegments`).

### Secure cookies (`ICookieManager`)
- Encrypts values via `IEncryptionService` and stores them as `HttpOnly`, `Secure`, `SameSite=Strict` cookies.
- Requires an active `HttpContext`; use inside controllers or middleware.
- Provides typed helpers such as `SetEncryptedObjectCookie` and `TryGetDecryptedObjectCookie`.

```csharp
_cookieManager.SetEncryptedCookie("refresh-token", refreshToken, DateTimeOffset.UtcNow.AddDays(7));
if (_cookieManager.TryGetDecryptedCookie("refresh-token", out var token))
{
    // token holds the decrypted refresh token
}
```

### Sessions (`ISessionManager`)
- Wraps ASP.NET Core `ISession`; ensure `AddSession` is called and `app.UseSession()` is in the middleware pipeline.
- Can store raw strings, typed objects, or encrypted values (backed by `IEncryptionService`).
- `GetOrCreateSessionToken` produces a persistent, random session token.

```csharp
_sessionManager.SetEncrypted("cart", "123-456");
string? cartId = _sessionManager.GetDecrypted("cart");
```

### JWT tokens (`IJwtTokenService`)
- Issues and validates JWTs using the configured `JwtOptions` (`JwtTokenService`).
- `CreateTokenFromDictionary` converts a dictionary to claims; `CreateRefreshToken` emits a random Base64Url token.
- `ValidateToken` returns a `ClaimsPrincipal` when the token is valid.

```csharp
var claims = new Dictionary<string, string?>
{
    [JwtRegisteredClaimNames.Sub] = userId,
    [JwtRegisteredClaimNames.Email] = email
};
string accessToken = jwtTokenService.CreateTokenFromDictionary(claims);
ClaimsPrincipal? principal = jwtTokenService.ValidateToken(accessToken);
```

### Exception handling (`IExceptionHandlingService`)
- Produces `ExceptionDescriptor` instances that align with the configured `ExceptionHandlingOptions`.
- Useful for consistent API error shapes and structured logging.

```csharp
var descriptor = exceptionHandlingService.CreateDescriptor(exception, new { Path = context.Request.Path });
var logMessage = exceptionHandlingService.BuildLogMessage(descriptor);
```

## Sample Web API template

A ready-to-run example lives under [`Samples/WebApiQuickstart`](Samples/WebApiQuickstart). It demonstrates issuing JWT access tokens, storing encrypted refresh tokens in secure cookies, hashing passwords, persisting encrypted session data, and encoding URL-safe values.

Run it with `dotnet run` from the sample directory after restoring packages.
