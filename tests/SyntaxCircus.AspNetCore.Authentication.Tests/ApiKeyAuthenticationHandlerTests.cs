using System.Text.Encodings.Web;

namespace SyntaxCircus.AspNetCore.Authentication.Tests;

public class ApiKeyAuthenticationHandlerTests
{
    private static async Task<ApiKeyAuthenticationHandler> CreateHandlerAsync(HttpContext context, IApiKeyValidator validator)
    {
        var optionsMonitor = Substitute.For<IOptionsMonitor<ApiKeyAuthenticationOptions>>();
        optionsMonitor.CurrentValue.Returns(new ApiKeyAuthenticationOptions());
        optionsMonitor.Get(Arg.Any<string>()).Returns(new ApiKeyAuthenticationOptions());

        var handler = new ApiKeyAuthenticationHandler(optionsMonitor, NullLoggerFactory.Instance, UrlEncoder.Default, validator);
        var scheme = new AuthenticationScheme(ApiKeyAuthenticationHandler.SchemeName, null, typeof(ApiKeyAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);
        return handler;
    }

    private static DefaultHttpContext ContextWithHeader(string? headerValue)
    {
        var context = new DefaultHttpContext();
        context.RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider();
        if (headerValue is not null)
        {
            context.Request.Headers["X-Api-Key"] = headerValue;
        }

        return context;
    }

    [Fact]
    public async Task AuthenticateAsync_HeaderAbsent_ReturnsNoResult()
    {
        var context = ContextWithHeader(null);
        var validator = Substitute.For<IApiKeyValidator>();
        var handler = await CreateHandlerAsync(context, validator);

        var result = await handler.AuthenticateAsync();

        result.None.ShouldBeTrue();
        await validator.DidNotReceive().ValidateAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AuthenticateAsync_HeaderBlank_ReturnsNoResult()
    {
        var context = ContextWithHeader("   ");
        var validator = Substitute.For<IApiKeyValidator>();
        var handler = await CreateHandlerAsync(context, validator);

        var result = await handler.AuthenticateAsync();

        result.None.ShouldBeTrue();
    }

    [Fact]
    public async Task AuthenticateAsync_ValidatorReturnsInvalid_ReturnsFail()
    {
        var context = ContextWithHeader("bad-key");
        var validator = Substitute.For<IApiKeyValidator>();
        validator.ValidateAsync("bad-key", Arg.Any<CancellationToken>()).Returns(ApiKeyValidationResult.Invalid);
        var handler = await CreateHandlerAsync(context, validator);

        var result = await handler.AuthenticateAsync();

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldNotBeNull();
    }

    [Fact]
    public async Task AuthenticateAsync_ValidatorReturnsValidWithClaims_ReturnsSuccessWithClaims()
    {
        var context = ContextWithHeader("good-key");
        var validator = Substitute.For<IApiKeyValidator>();
        var claims = new List<Claim> { new(ClaimTypes.Name, "caller") };
        validator.ValidateAsync("good-key", Arg.Any<CancellationToken>()).Returns(ApiKeyValidationResult.Valid(claims));
        var handler = await CreateHandlerAsync(context, validator);

        var result = await handler.AuthenticateAsync();

        result.Succeeded.ShouldBeTrue();
        result.Principal.ShouldNotBeNull();
        result.Principal!.Identity!.AuthenticationType.ShouldBe(ApiKeyAuthenticationHandler.SchemeName);
        result.Principal.FindFirst(ClaimTypes.Name)?.Value.ShouldBe("caller");
    }

    [Fact]
    public async Task AuthenticateAsync_ValidatorReturnsValidWithNullClaims_ReturnsSuccessWithEmptyClaims()
    {
        var context = ContextWithHeader("good-key");
        var validator = Substitute.For<IApiKeyValidator>();
        validator.ValidateAsync("good-key", Arg.Any<CancellationToken>()).Returns(new ApiKeyValidationResult(true, null));
        var handler = await CreateHandlerAsync(context, validator);

        var result = await handler.AuthenticateAsync();

        result.Succeeded.ShouldBeTrue();
        result.Principal!.Claims.ShouldBeEmpty();
    }

    [Fact]
    public async Task AuthenticateAsync_MultipleHeaderValues_UsesFirst()
    {
        var context = ContextWithHeader(null);
        context.Request.Headers["X-Api-Key"] = new Microsoft.Extensions.Primitives.StringValues(["first", "second"]);
        var validator = Substitute.For<IApiKeyValidator>();
        validator.ValidateAsync("first", Arg.Any<CancellationToken>()).Returns(ApiKeyValidationResult.Invalid);
        var handler = await CreateHandlerAsync(context, validator);

        await handler.AuthenticateAsync();

        await validator.Received(1).ValidateAsync("first", Arg.Any<CancellationToken>());
    }
}
