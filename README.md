# SyntaxCircus.AspNetCore.Authentication

[![Build](https://github.com/Syntax-Circus/SyntaxCircus.AspNetCore.Authentication/actions/workflows/build.yml/badge.svg)](https://github.com/Syntax-Circus/SyntaxCircus.AspNetCore.Authentication/actions/workflows/build.yml)
[![NuGet](https://img.shields.io/nuget/v/SyntaxCircus.AspNetCore.Authentication.svg)](https://www.nuget.org/packages/SyntaxCircus.AspNetCore.Authentication)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.txt)

JWT bearer authentication setup and pluggable API-key authentication for ASP.NET Core APIs — the server side of validating incoming requests. (For a Blazor Server app forwarding its own user's OIDC tokens to a backend API, see [SyntaxCircus.Blazor.Auth](https://github.com/Syntax-Circus/SyntaxCircus.Blazor.Auth) instead — that's a different concern.)

> **No support guaranteed.** Published as-is and maintained on a best-effort basis. Issues and PRs are welcome, but there's no SLA — fork it or vendor what you need if that's not enough.

## JWT bearer

```csharp
builder.Services.AddSyntaxCircusJwtBearer(builder.Configuration); // binds "Authentication:JwtBearer"

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
```

```json
{
  "Authentication": {
    "JwtBearer": {
      "Authority": "https://auth.example.com/application/o/my-web/",
      "Audiences": ["my-api"],
      "TrustedIssuers": [
        "https://auth.example.com/application/o/my-admin/",
        "https://auth.example.com/application/o/my-mobile/"
      ],
      "RequireHttpsMetadata": true,
      "MapInboundClaims": false,
      "RoleClaimType": "roles",
      "LogAuthenticationFailuresInDevelopment": true,
      "DeviceToken": {
        "Enabled": true,
        "SigningKey": "a long random symmetric key",
        "Issuer": "my-api",
        "Audience": "my-api-devices"
      }
    }
  }
}
```

Registers a primary scheme that validates tokens against OIDC-discovered signing keys from `Authority`. When `DeviceToken:Enabled` is set, a second symmetric-key scheme is also registered for self-issued device/M2M tokens, and a policy scheme picks between the two automatically per request by sniffing the incoming JWT's `alg` header (`HS256` → device scheme, anything else → the primary OIDC scheme) — callers don't need to know or specify which scheme applies.

`TrustedIssuers` accepts additional issuers beyond `Authority`. Entries that are genuinely distinct OIDC applications — e.g. separate Web/Admin/Mobile registrations against the same identity provider, each with its own signing keys — get their own OIDC discovery (`/.well-known/openid-configuration` + JWKS) so their tokens validate too, not just tokens whose issuer claim happens to differ while sharing `Authority`'s keys. There's no extra discovery round-trip when `TrustedIssuers` is empty or only repeats `Authority`.

A few more optional settings, all of which leave ASP.NET Core's own default untouched when unset:
- `RequireHttpsMetadata` (bool) — whether OIDC discovery endpoints must be served over HTTPS.
- `MapInboundClaims` (bool) — set to `false` to preserve raw claim types (e.g. a custom `"roles"` claim) instead of ASP.NET Core's default `ClaimTypes.*` remapping.
- `RoleClaimType` / `NameClaimType` (string) — override which claim type role-based authorization (`IsInRole`) and `Identity.Name` read from, for tokens using non-default claim names.
- `LogAuthenticationFailuresInDevelopment` (bool, default `false`) — opt-in dev-only logging of the validation exception on authentication failure, via `OnAuthenticationFailed`.

## API key

```csharp
builder.Services.AddSyntaxCircusApiKey(builder.Configuration); // binds "Authentication:ApiKey"
```

```json
{ "Authentication": { "ApiKey": { "HeaderName": "X-Api-Key", "StaticKey": "..." } } }
```

By default, validates the `X-Api-Key` header against a single configured `StaticKey` using a constant-time comparison. For per-caller or DB-backed/hashed-key validation, register your own `IApiKeyValidator` before calling `AddSyntaxCircusApiKey`:

```csharp
builder.Services.AddSingleton<IApiKeyValidator, MyDatabaseBackedApiKeyValidator>();
builder.Services.AddSyntaxCircusApiKey(builder.Configuration);
```

Your validator returns `ApiKeyValidationResult.Valid(claims)` or `ApiKeyValidationResult.Invalid` — whatever claims you supply become the resulting `ClaimsPrincipal`, so you can carry caller identity, scopes, or partition keys through to your endpoints.

## Contributing

Issues and pull requests are welcome:
- Keep changes focused, with a clear description of the behavior change.
- Match the existing code style (see `.editorconfig`).
- Call out any breaking changes to the public API in your PR description.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
