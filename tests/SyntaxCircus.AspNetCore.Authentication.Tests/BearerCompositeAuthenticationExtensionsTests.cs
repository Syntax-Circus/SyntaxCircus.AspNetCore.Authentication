namespace SyntaxCircus.AspNetCore.Authentication.Tests;

public sealed class BearerCompositeAuthenticationExtensionsTests
{
    [Fact]
    public void SelectScheme_OpaqueBearerCredential_UsesOpaqueScheme()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Bearer cmsify_local_session";

        var scheme = BearerCompositeAuthenticationExtensions.SelectScheme(context, "CmsifyOpaque", "CmsifyJwt");

        scheme.ShouldBe("CmsifyOpaque");
    }

    [Fact]
    public void SelectScheme_JwtBearerCredential_UsesJwtScheme()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature";

        var scheme = BearerCompositeAuthenticationExtensions.SelectScheme(context, "CmsifyOpaque", "CmsifyJwt");

        scheme.ShouldBe("CmsifyJwt");
    }
}
