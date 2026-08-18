# AGENTS.md

Guidance for coding agents (and humans skimming for the same info) working in this repository.

## What this is

`SyntaxCircus.AspNetCore.Authentication` is a small ASP.NET Core library providing the *server-side* request-authentication pieces for APIs:

- **JWT bearer** (`SyntaxCircusJwtBearerExtensions.AddSyntaxCircusJwtBearer`) — a primary scheme validating OIDC-discovered signing keys (with multi-issuer fan-out for genuinely distinct OIDC applications), plus an optional self-issued symmetric-key "device"/M2M scheme auto-selected by JWT `alg` header.
- **API key** (`ApiKeyAuthenticationExtensions.AddSyntaxCircusApiKey`) — header-based API-key auth with a pluggable `IApiKeyValidator`, supporting multiple independent schemes in the same app.

See `README.md` for consumer-facing usage and config examples — read that first for "how do I use this package," this file is about working *on* the package.

Sibling package: [`SyntaxCircus.Blazor.Auth`](https://github.com/Syntax-Circus/SyntaxCircus.Blazor.Auth) covers a different concern (a Blazor Server app forwarding its own user's OIDC tokens to a backend API) and lives in a separate repo — don't conflate the two.

## Repo layout

```
src/SyntaxCircus.AspNetCore.Authentication/    the library (single project, net10.0)
tests/SyntaxCircus.AspNetCore.Authentication.Tests/   xunit.v3 + NSubstitute + Shouldly
docs/enhancements/                             dated proposal docs for non-trivial changes (see below)
README.md                                      consumer-facing docs, packed into the NuGet package
```

Key files in `src/`:
- `ApiKeyAuthenticationHandler.cs`, `ApiKeyAuthenticationExtensions.cs`, `ApiKeyAuthenticationOptions.cs`, `ConstantApiKeyValidator.cs`, `IApiKeyValidator.cs` — the API-key feature.
- `SyntaxCircusJwtBearerExtensions.cs`, `JwtBearerAuthenticationOptions.cs`, `JwtSchemeSelector.cs` — the JWT bearer feature.
- `OidcClientOptions.cs` — a shared OIDC-client options shape (`Authority`/`ClientId`/`ClientSecret`/`Scopes`); currently a standalone public type not consumed by any extension method in this package — don't assume it's wired into `AddSyntaxCircusJwtBearer` just because it's present.
- `GlobalUsings.cs` — global usings for the library; add new BCL/ASP.NET Core namespaces here rather than per-file `using`s when they're used broadly.
- `AssemblyInfo.cs` — `[InternalsVisibleTo("SyntaxCircus.AspNetCore.Authentication.Tests")]`.

## Build & test

```
dotnet build
dotnet test
```

`Directory.Build.props` sets `TreatWarningsAsErrors = true` with `AnalysisLevel = latest-recommended` (a few analyzer rules suppressed: `CA1305`, `CA1707`, `CA1848`) — **any new public API needs XML doc comments and nullable-clean, analyzer-clean code, or the build fails.** `global.json` pins the SDK (`10.0.400`, `rollForward: latestFeature`) and uses the `Microsoft.Testing.Platform` test runner.

Versioning is GitVersion-driven (`GitVersion.MsBuild`, trunk-based workflow, `next-version: 0.1.0`) — never hand-set a `<Version>` in the `.csproj`.

## Conventions worth knowing before you pattern-match

- **Per-scheme options resolution.** `AuthenticationBuilder.AddScheme(schemeName, configureOptions)` binds *named* options under `schemeName` — that's what `AuthenticationHandler<TOptions>.Options` resolves via `IOptionsMonitor<TOptions>.Get(Scheme.Name)` at request time. Don't rely on unnamed `IOptions<TOptions>` for anything that needs to vary per scheme; it only reflects whichever `services.Configure<TOptions>(...)` call (without a name) ran *last*, which breaks down the moment more than one scheme shares an options type (see `ConstantApiKeyValidator`'s two-constructor design for the pattern: a public `IOptions<T>`-based ctor for standalone/back-compat use, and an internal `IOptionsMonitor<T>` + `schemeName` ctor that the package's own DI registration uses).
- **Keyed services for per-scheme overrides.** The API-key handler resolves an optional keyed `IApiKeyValidator` (`services.AddKeyedSingleton<IApiKeyValidator, T>(schemeName)`) at request time via `Context.RequestServices`, falling back to the constructor-injected unkeyed validator when no keyed match exists. Always guard a `GetKeyedService` call with `is IKeyedServiceProvider` first — not every `IServiceProvider` implementation supports keying, and a blind call throws for consumers on such a container even when they never use keyed registrations.
- **`InternalsVisibleTo`** is set up for `...Tests` — prefer an `internal` test seam (see `ConstantApiKeyValidator`'s internal constructor, or `SyntaxCircusJwtBearerExtensions`'s internal `configurationManagerFactory` overload used to stub OIDC discovery in tests) over making something public just to make it testable.
- **Primary-constructor style.** Handler/validator classes capture DI dependencies via primary constructors (no explicit backing fields) — match this style for new classes in this vein (`ApiKeyAuthenticationHandler`, `ConstantApiKeyValidator`).
- **Backward compatibility bar.** This is a published NuGet package (`SyntaxCircus.AspNetCore.Authentication`) with unknown external consumers. Prefer additive changes (new optional trailing parameters with defaults, new internal-only constructor overloads, new extension method overloads) over changing existing public signatures. When a fix would otherwise require a breaking signature change, look for a non-breaking alternative first (e.g. resolving something lazily at request time instead of at construction time) before accepting the breakage — and if you do accept one, call it out explicitly in the PR description per the Contributing guidance in `README.md`.

## `docs/enhancements/` convention

Non-trivial proposed changes get a dated markdown doc here before implementation: `YYYY-MM-DD-short-slug.md`, with `Status` (`proposed` → `resolved`), `Found via`, `Affects`, `Problem`, `Proposed fix`, optionally `Scope note` / `Related gaps`, and `How to verify`. See any file in `docs/enhancements/` for the exact shape. When you resolve one, update its `Status` line to point at what actually shipped (scheme name, options property, etc.) rather than deleting the doc — it's the historical record of why the change happened.
