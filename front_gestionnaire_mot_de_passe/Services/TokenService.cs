using Microsoft.Identity.Web;

namespace front_gestionnaire_mot_de_passe.Services;

public class TokenService
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IConfiguration _configuration;
    private string? _cachedToken;

    public TokenService(ITokenAcquisition tokenAcquisition, IConfiguration configuration)
    {
        _tokenAcquisition = tokenAcquisition;
        _configuration = configuration;
    }

    public async Task<string> GetApiAccessTokenAsync()
    {
        if (!string.IsNullOrEmpty(_cachedToken))
            return _cachedToken;

        var scopes = _configuration.GetSection("DownstreamApi:Scopes").Get<string[]>();
        if (scopes == null || scopes.Length == 0)
            throw new InvalidOperationException("Aucun scope configuré dans DownstreamApi:Scopes");

        _cachedToken = await _tokenAcquisition.GetAccessTokenForUserAsync(scopes);
        return _cachedToken;
    }
}