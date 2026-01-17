using front_gestionnaire_mot_de_passe.Models;
using Microsoft.Identity.Abstractions;

namespace front_gestionnaire_mot_de_passe.Services;

public interface IVaultService
{
    Task<List<Vault>> GetAllVaultsAsync();
    Task<Vault?> GetVaultByIdAsync(int vaultId, int? currentUserId);
    Task DeleteVaultAsync(int vaultId);
    Task<List<Log>> GetVaultLogsAsync(int vaultId);
}

public class VaultService : IVaultService
{
    private readonly IDownstreamApi _api;
    private readonly ILogger<VaultService> _logger;

    public VaultService(IDownstreamApi api, ILogger<VaultService> logger)
    {
        _api = api;
        _logger = logger;
    }

    public async Task<List<Vault>> GetAllVaultsAsync()
    {
        try
        {
            var vaults = await _api.GetForUserAsync<List<Vault>>(
                "DownstreamApi",
                o => o.RelativePath = "/Vault/All"
            ) ?? new();
            
            _logger.LogInformation("Nombre de coffres récupérés : {Count}", vaults.Count);
            return vaults;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération des coffres");
            return new List<Vault>();
        }
    }

    public async Task<Vault?> GetVaultByIdAsync(int vaultId, int? currentUserId)
    {
        try
        {
            var allVaults = await GetAllVaultsAsync();
            var vault = allVaults.FirstOrDefault(v => v.Id == vaultId);
            
            if (vault == null)
            {
                _logger.LogWarning("Aucun coffre trouvé avec l'ID {VaultId}", vaultId);
                return null;
            }

            _logger.LogInformation(
                "Coffre trouvé - ID: {VaultId}, Nom: {VaultName}, UserId (propriétaire): {OwnerId}",
                vault.Id, vault.Name, vault.UserId
            );

            if (currentUserId.HasValue)
            {
                vault.IsOwner = vault.UserId == currentUserId.Value;
                
                _logger.LogInformation(
                    "Comparaison des IDs - VaultData.UserId: {VaultUserId}, CurrentUserId: {CurrentUserId}, IsOwner: {IsOwner}",
                    vault.UserId, currentUserId.Value, vault.IsOwner
                );
            }
            else
            {
                vault.IsOwner = false;
                _logger.LogWarning("Impossible de déterminer IsOwner - currentUserId est null");
            }
            
            return vault;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération du coffre {VaultId}", vaultId);
            return null;
        }
    }


    public async Task DeleteVaultAsync(int vaultId)
    {
        try
        {
            await _api.CallApiForUserAsync(
                "DownstreamApi",
                options =>
                {
                    options.HttpMethod = HttpMethod.Delete.ToString();
                    options.RelativePath = $"/Vault/{vaultId}";
                });
            
            _logger.LogInformation("Coffre {VaultId} supprimé avec succès", vaultId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la suppression du coffre {VaultId}", vaultId);
            throw;
        }
    }

    public async Task<List<Log>> GetVaultLogsAsync(int vaultId)
    {
        try
        {
            var logs = await _api.GetForUserAsync<List<Log>>(
                "DownstreamApi",
                o => o.RelativePath = $"/Vault/GetLogVault/{vaultId}"
            ) ?? new();
            
            _logger.LogInformation("Nombre de logs récupérés pour le coffre {VaultId} : {Count}", vaultId, logs.Count);
            return logs;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération des logs du coffre {VaultId}", vaultId);
            return new List<Log>();
        }
    }
}

