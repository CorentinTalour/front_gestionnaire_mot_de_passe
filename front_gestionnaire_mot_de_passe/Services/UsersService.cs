using front_gestionnaire_mot_de_passe.Models.VaultMembers;
using Microsoft.Identity.Abstractions;

namespace front_gestionnaire_mot_de_passe.Services;

public interface IUsersService
{
    Task<GetUserObj?> GetCurrentUserAsync();
}

public class UsersService : IUsersService
{
    private readonly IDownstreamApi _api;
    private readonly ILogger<VaultService> _logger;
    
    public async Task<GetUserObj?> GetCurrentUserAsync()
    {
        try
        {
            var user = await _api.GetForUserAsync<GetUserObj>(
                "DownstreamApi",
                o => o.RelativePath = "/Users/Me"
            );
            
            if (user != null)
            {
                _logger.LogInformation("Utilisateur connecté trouvé - ID: {UserId}, Email: {Email}", user.Id, user.Email);
            }
            else
            {
                _logger.LogWarning("Aucun utilisateur retourné par /Users/Me");
            }
            
            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération de l'utilisateur connecté");
            return null;
        }
    }
}