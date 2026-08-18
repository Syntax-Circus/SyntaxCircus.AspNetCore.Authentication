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

Registers a primary scheme (`JwtBearerDefaults.AuthenticationScheme`) that validates tokens against OIDC-discovered signing keys from `Authority`. When `DeviceToken:Enabled` is set, a second symmetric-key scheme (`SyntaxCircusJwtBearerExtensions.DeviceScheme`, `"SyntaxCircusDevice"`) is also registered for self-issued device/M2M tokens, plus a policy scheme (`SyntaxCircusJwtBearerExtensions.PolicyScheme`, `"SyntaxCircusJwt"`, and the app's default scheme in that case) that picks between the two automatically per request by sniffing the incoming JWT's `alg` header (`HS256` → device scheme, anything else → the primary OIDC scheme) — callers don't need to know or specify which scheme applies. `[Authorize]` with no explicit scheme uses the policy scheme automatically; target `DeviceScheme` explicitly (`[Authorize(AuthenticationSchemes = SyntaxCircusJwtBearerExtensions.DeviceScheme)]`) if you need to require a device token specifically.

`TrustedIssuers` accepts additional issuers beyond `Authority`. Entries that are genuinely distinct OIDC applications — e.g. separate Web/Admin/Mobile registrations against the same identity provider, each with its own signing keys — get their own OIDC discovery (`/.well-known/openid-configuration` + JWKS) so their tokens validate too, not just tokens whose issuer claim happens to differ while sharing `Authority`'s keys. There's no extra discovery round-trip when `TrustedIssuers` is empty or only repeats `Authority`.

A few more optional settings, all of which leave ASP.NET Core's own default untouched when unset:
- `RequireHttpsMetadata` (bool) — whether OIDC discovery endpoints must be served over HTTPS.
- `MapInboundClaims` (bool) — set to `false` to preserve raw claim types (e.g. a custom `"roles"` claim) instead of ASP.NET Core's default `ClaimTypes.*` remapping.
- `RoleClaimType` / `NameClaimType` (string) — override which claim type role-based authorization (`IsInRole`) and `Identity.Name` read from, for tokens using non-default claim names.
- `LogAuthenticationFailuresInDevelopment` (bool, default `false`) — opt-in dev-only logging of the validation exception on authentication failure, via `OnAuthenticationFailed`.

## API key

```csharp
builder.Services.AddSyntaxCircusApiKey(builder.Configuration); // binds "Authentication:ApiKey", scheme "ApiKey"
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

### Multiple independent API-key schemes

`AddSyntaxCircusApiKey` accepts an optional `schemeName` (defaulting to `ApiKeyAuthenticationHandler.SchemeName`, i.e. `"ApiKey"`), alongside the existing `sectionName`. Call it more than once with distinct pairs to register genuinely independent API-key concerns in the same app — e.g. a worker-to-worker key and an external-agent key, each with its own header name and its own validator:

```csharp
builder.Services.AddKeyedSingleton<IApiKeyValidator, WorkerApiKeyValidator>("WorkerApiKey");
builder.Services.AddSyntaxCircusApiKey(builder.Configuration, "Authentication:WorkerApiKey", "WorkerApiKey");

builder.Services.AddKeyedSingleton<IApiKeyValidator, AgentApiKeyValidator>("AgentApiKey");
builder.Services.AddSyntaxCircusApiKey(builder.Configuration, "Authentication:AgentApiKey", "AgentApiKey");
```

```json
{
  "Authentication": {
    "WorkerApiKey": { "HeaderName": "X-Worker-Api-Key" },
    "AgentApiKey": { "HeaderName": "X-Agent-Api-Key" }
  }
}
```

Register each scheme's validator **keyed by its scheme name** (`AddKeyedSingleton<IApiKeyValidator, T>(schemeName)`) before calling `AddSyntaxCircusApiKey` for that scheme — the handler looks up a keyed validator for its own scheme first, falling back to the plain (unkeyed) `IApiKeyValidator` registration only when no keyed match exists. This means a single-scheme app needs no changes at all: with only one scheme registered, there's nothing keyed to find, so it falls straight through to the unkeyed validator exactly as before.

Wire each scheme into authorization separately, e.g.:

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Worker", p => p.AddAuthenticationSchemes("WorkerApiKey").RequireAuthenticatedUser());
    options.AddPolicy("Agent", p => p.AddAuthenticationSchemes("AgentApiKey").RequireAuthenticatedUser());
});
```

**Caveat:** the built-in `ConstantApiKeyValidator` (used when you don't register your own `IApiKeyValidator`) is only ever wired up *unkeyed*, for exactly one scheme — the first `AddSyntaxCircusApiKey` call in your app. Every additional scheme must supply its own validator (custom, or your own keyed `ConstantApiKeyValidator`-style implementation reading `IOptionsMonitor<ApiKeyAuthenticationOptions>.Get(schemeName)`). Relatedly, if a custom validator injects unnamed `IOptions<ApiKeyAuthenticationOptions>` to read shared config, remember that in a multi-scheme app that unnamed instance reflects whichever scheme's `sectionName` was registered *last* — inject `IOptionsMonitor<ApiKeyAuthenticationOptions>` and call `.Get(schemeName)` instead so you read the config for the right scheme.

## Contributing

Issues and pull requests are welcome:
- Keep changes focused, with a clear description of the behavior change.
- Match the existing code style (see `.editorconfig`).
- Call out any breaking changes to the public API in your PR description.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
