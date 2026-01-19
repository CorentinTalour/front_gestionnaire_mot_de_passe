using Microsoft.Identity.Web;

namespace front_gestionnaire_mot_de_passe.Services;

/// <summary>
/// Service de gestion sécurisée des tokens d'accès API.
/// Utilise le cache géré par Microsoft.Identity.Web avec expiration automatique.
/// </summary>
public class TokenService
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IConfiguration _configuration;
    private readonly ILogger<TokenService> _logger;

    public TokenService(
        ITokenAcquisition tokenAcquisition, 
        IConfiguration configuration,
        ILogger<TokenService> logger)
    {
        _tokenAcquisition = tokenAcquisition;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Récupère un token d'accès API valide.
    /// Le cache et la gestion de l'expiration sont gérés automatiquement par ITokenAcquisition.
    /// </summary>
    /// <returns>Token d'accès Bearer valide</returns>
    /// <exception cref="InvalidOperationException">Si les scopes ne sont pas configurés</exception>
    /// <exception cref="MicrosoftIdentityWebChallengeUserException">Si le token est expiré et nécessite une réauthentification</exception>
    public async Task<string> GetApiAccessTokenAsync()
    {
        try
        {
            string[]? scopes = _configuration.GetSection("DownstreamApi:Scopes").Get<string[]>();
            if (scopes == null || scopes.Length == 0)
            {
                _logger.LogError("Aucun scope configuré dans DownstreamApi:Scopes");
                throw new InvalidOperationException("Aucun scope configuré dans DownstreamApi:Scopes");
            }

            // ITokenAcquisition gère automatiquement :
            // - Le cache en mémoire avec AddInMemoryTokenCaches()
            // - La validation de l'expiration du token
            // - Le refresh automatique si possible
            // - L'invalidation au logout via les mécanismes standard OIDC
            string token = await _tokenAcquisition.GetAccessTokenForUserAsync(scopes);
            
            _logger.LogDebug("Token d'accès API récupéré avec succès");
            return token;
        }
        catch (MicrosoftIdentityWebChallengeUserException ex)
        {
            // Le token est expiré et l'utilisateur doit se réauthentifier
            _logger.LogWarning(ex, "Token expiré, réauthentification requise");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération du token d'accès API");
            throw;
        }
    }
}