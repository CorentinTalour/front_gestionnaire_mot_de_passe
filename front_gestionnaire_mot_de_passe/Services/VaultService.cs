using front_gestionnaire_mot_de_passe.Models;
using Microsoft.Identity.Abstractions;

namespace front_gestionnaire_mot_de_passe.Services;

public interface IVaultService
{
    Task<List<Vault>> GetAllVaultsAsync();
    Task<Vault?> GetVaultByIdAsync(int vaultId, int? currentUserId);
    Task<List<VaultEntry>> GetVaultEntriesAsync(int vaultId);
    Task DeleteVaultAsync(int vaultId);
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

    public async Task<List<VaultEntry>> GetVaultEntriesAsync(int vaultId)
    {
        try
        {
            var entries = await _api.GetForUserAsync<List<VaultEntry>>(
                "DownstreamApi",
                o => o.RelativePath = $"/Entry/VaultId?vaultId={vaultId}"
            ) ?? new();
            
            _logger.LogInformation("Nombre d'entrées récupérées pour le coffre {VaultId} : {Count}", vaultId, entries.Count);
            return entries;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération des entrées du coffre {VaultId}", vaultId);
            return new List<VaultEntry>();
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
}

