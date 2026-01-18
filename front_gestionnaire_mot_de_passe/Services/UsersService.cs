using front_gestionnaire_mot_de_passe.Models;
using front_gestionnaire_mot_de_passe.Models.VaultMembers;
using Microsoft.Identity.Abstractions;

namespace front_gestionnaire_mot_de_passe.Services;

public interface IUsersService
{
    Task<User?> GetCurrentUserAsync();
}

public class UsersService : IUsersService
{
    private readonly IDownstreamApi _api;
    private readonly ILogger<UsersService> _logger;

    public UsersService(IDownstreamApi api, ILogger<UsersService> logger)
    {
        _api = api;
        _logger = logger;
    }
    
    public async Task<User?> GetCurrentUserAsync()
    {
        try
        {
            GetUserObj? userDto = await _api.GetForUserAsync<GetUserObj>(
                "DownstreamApi",
                o => o.RelativePath = "/Users/Me"
            );
            
            User? user = null;
            
            if (userDto != null)
            {
                user = MapDtoToUser(userDto);
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
    
    private User MapDtoToUser(GetUserObj dto)
    {
        return new User
        {
            Id = dto.Id,
            Email = dto.Email,
        };
    }
}