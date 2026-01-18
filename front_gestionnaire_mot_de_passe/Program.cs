using front_gestionnaire_mot_de_passe.Components;
using front_gestionnaire_mot_de_passe.Interop;
using front_gestionnaire_mot_de_passe.Services;
using front_gestionnaire_mot_de_passe.Utils;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.AspNetCore.Components;

var builder = WebApplication.CreateBuilder(args);

// Lecture des informations de la WebAPI depuis le fichier de configuration.
string apiEndpoint = builder.Configuration.GetValue<string>("DownstreamApi:BaseUrl")
                     ?? throw new InvalidOperationException("API BaseUrl missing");
string[] scopes = builder.Configuration.GetSection("DownstreamApi:Scopes").Get<string[]>()
             ?? throw new InvalidOperationException("API Scopes missing");

string frontUrl = builder.Configuration.GetValue<string>("Cors:AllowedOrigins")
                      ?? throw new InvalidOperationException("FrontUrl missing");

// Service pour lire la configuration de l'application.
builder.Services.AddSingleton<AppConfig>();

// Authentification via EntraID et configuration de l'appel à la WebAPI via DownStreamApi.
builder.Services
    .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"))
    .EnableTokenAcquisitionToCallDownstreamApi(scopes)
    .AddDownstreamApi("DownstreamApi", options =>
    {
        options.BaseUrl = apiEndpoint;
        options.Scopes = scopes;
    })
    .AddInMemoryTokenCaches();
builder.Services.AddAuthorization(o => o.FallbackPolicy = o.DefaultPolicy);
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddScoped<CryptoInterop>();
builder.Services.AddScoped<VaultState>();

builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<IVaultService, VaultService>();
builder.Services.AddScoped<IUsersService, UsersService>();
builder.Services.AddScoped<IEntryService, EntryService>();

// CORS pour le dev local
builder.Services.AddCors(opt =>
{
    opt.AddPolicy("Dev", p =>
        p.WithOrigins(frontUrl)
            .AllowAnyHeader()
            .AllowAnyMethod());
});

builder.Services.AddRazorPages().AddMicrosoftIdentityUI();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();

builder.Services.AddHttpClient();

builder.Services.AddScoped(sp =>
{
    var nav = sp.GetRequiredService<NavigationManager>();
    return new HttpClient { BaseAddress = new Uri(nav.BaseUri) };
});

var app = builder.Build();

app.UseHttpsRedirection();

// Middleware de sécurité : Content Security Policy (CSP)
// La CSP permet de limiter les sources autorisées pour charger/exécuter des ressources
// et de réduire les risques d'attaques XSS ou d'injection de scripts.
app.Use(async (context, next) =>
{
    // Blazor Server utilise SignalR pour la communication client/serveur,
    // ce qui passe par WebSocket. Il faut donc l'autoriser explicitement
    var csp =
        // Par défaut, aucune ressource n'est autorisée
        // Tout doit être explicitement déclaré
        "default-src 'none'; " +

        // Autorise la balise <base> uniquement vers l'origine courante
        // Empêche la redéfinition de base URL vers un domaine malveillant
        "base-uri 'self'; " +

        // Interdit complètement les objets embarqués (Flash, plugins, etc.)
        "object-src 'none'; " +

        // Empêche l'application d'être intégrée dans une iframe
        // (protection contre le clickjacking)
        "frame-ancestors 'none'; " +

        // Autorise l'envoi de formulaires uniquement :
        // - vers l'application elle-même
        // - vers Microsoft Entra ID
        "form-action 'self' https://login.microsoftonline.com; " +

        // Autorise les images depuis l'application
        // et les data URLs
        "img-src 'self' data:; " +

        // Autorise les polices uniquement depuis l'application
        "font-src 'self'; " +

        // Autorise les styles depuis l'application
        // 'unsafe-inline' est nécessaire car Blazor génère certains styles inline
        "style-src 'self' 'unsafe-inline'; " +

        // Autorise les scripts uniquement depuis l'application
        // Aucun script inline n'est autorisé → protection contre XSS
        "script-src 'self'; " +

        // Autorise les connexions réseau :
        // - vers l'application
        // - en HTTPS
        // - en WebSocket sécurisé (SignalR / Blazor Server)
        $"connect-src 'self' {apiEndpoint} wss:;";

    // Application de la CSP en mode bloquant
    // (les violations sont bloquées par le navigateur)
    context.Response.Headers["Content-Security-Policy"] = csp;

    // Header de sécurité complémentaire :
    // Empêche le navigateur d'interpréter un fichier avec un mauvais type MIME
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";

    // Empêche l'envoi du header Referer vers des sites externes
    // Limite les fuites d'information
    context.Response.Headers["Referrer-Policy"] = "no-referrer";

    await next();
});

app.UseCors("Dev");
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapControllers();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.MapGroup("/authentication").MapLoginAndLogout();

app.Run();