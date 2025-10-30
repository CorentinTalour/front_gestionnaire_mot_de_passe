using front_gestionnaire_mot_de_passe.Components;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;

var builder = WebApplication.CreateBuilder(args);

string apiEndpoint = builder.Configuration.GetValue<string>("DownstreamApi:BaseUrl")
                     ?? throw new InvalidOperationException("API BaseUrl missing");
string apiScope = builder.Configuration.GetValue<string>("DownstreamApi:Scopes")
                  ?? throw new InvalidOperationException("API Scope missing");

builder.Services
    .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"))
    .EnableTokenAcquisitionToCallDownstreamApi([apiScope])
    .AddDownstreamApi("DownstreamApi", options =>
    {
        options.BaseUrl = apiEndpoint;
        options.Scopes = [apiScope];
    })
    .AddInMemoryTokenCaches();

builder.Services.AddAuthorization(o => o.FallbackPolicy = o.DefaultPolicy);
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddRazorPages().AddMicrosoftIdentityUI();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapControllers();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();