using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace front_gestionnaire_mot_de_passe.Utils;

internal static class LoginLogoutEndpointRouteBuilderExtensions
{
    internal static IEndpointConventionBuilder MapLoginAndLogout(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup(string.Empty);

        group.MapGet("/login", (string? returnUrl, ILogger<object> logger) =>
        {
            logger.LogInformation("Tentative de connexion");
            return TypedResults.Challenge(GetAuthProperties(returnUrl));
        })
        .AllowAnonymous();
        
        group.MapPost("/logout", (
            [FromForm] string? returnUrl,
            ILogger<object> logger,
            HttpContext httpContext) =>
        {
            string username = httpContext.User.Identity?.Name ?? "utilisateur inconnu";
            logger.LogInformation("Déconnexion de l'utilisateur {Username}", username);
            
            // Le cache de tokens est automatiquement nettoyé par le middleware OIDC
            // lors du SignOut, garantissant qu'aucun token ne persiste en mémoire
            return TypedResults.SignOut(
                GetAuthProperties(returnUrl),
                [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]);
        });

        return group;
    }

    // Prevent open redirects. Non-empty returnUrls are absolute URIs provided by NavigationManager.Uri.
    private static AuthenticationProperties GetAuthProperties(string? returnUrl) =>
        new()
        {
            RedirectUri = returnUrl is not null
                ? new Uri(returnUrl, UriKind.Absolute).PathAndQuery
                : "/"
        };
}