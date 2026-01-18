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
var scopes = builder.Configuration.GetSection("DownstreamApi:Scopes").Get<string[]>()
             ?? throw new InvalidOperationException("API Scopes missing");

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
        p.WithOrigins("https://localhost:7093")
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
app.UseCors("Dev");
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapControllers();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.MapGroup("/authentication").MapLoginAndLogout();

app.Run();