using front_gestionnaire_mot_de_passe.Models;
using Microsoft.Identity.Abstractions;
using DtoLib.Objet.Vault;

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
            List<GetVaultObj> vaultsDto = await _api.GetForUserAsync<List<GetVaultObj>>(
                "DownstreamApi",
                o => o.RelativePath = "/Vault/All"
            ) ?? new();

            List<Vault> vaults = vaultsDto.Select(MapDtoToVault).ToList();
            
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
            List<Vault> allVaults = await GetAllVaultsAsync();
            Vault? vault = allVaults.FirstOrDefault(v => v.Id == vaultId);

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
            List<GetVaultLogObj> logsDto = await _api.GetForUserAsync<List<GetVaultLogObj>>(
                "DownstreamApi",
                o => o.RelativePath = $"/Vault/GetLogVault/{vaultId}"
            ) ?? new();

            List<Log> logs = logsDto.Select(MapDtoToLog).ToList();
            
            _logger.LogInformation("Nombre de logs récupérés pour le coffre {VaultId} : {Count}", vaultId, logs.Count);
            return logs;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération des logs du coffre {VaultId}", vaultId);
            return new List<Log>();
        }
    }
    
    private Vault MapDtoToVault(GetVaultObj dto)
    {
        return new Vault
        {
            Id = dto.Id,
            Name = dto.Name,
            Salt = dto.Salt,
            NbIteration = dto.NbIteration,
            Iterations = dto.Iterations,
            Argon2Iterations = dto.Argon2Iterations,
            Argon2MemoryKB = dto.Argon2MemoryKb,
            Argon2Parallelism = dto.Argon2Parallelism,
            WrappedDekB64 = dto.WrappedDekB64,
            DekIvB64 = dto.DekIvB64,
            DekTagB64 = dto.DekTagB64,
            KekSaltB64 = dto.KekSaltB64,
            KekIterations = dto.KekIterations,
            CreatedAt = dto.CreatedAt,
            UpdatedAt = dto.UpdatedAt,
            Password = dto.Password,
            UserId = dto.UserId
        };
    }
    
    private Log MapDtoToLog(GetVaultLogObj dto)
    {
        return new Log
        {
            Id = dto.Id,
            Url = dto.Url,
            Message = dto.Message,
            Duration = dto.Duration,
            ExecutedAt = dto.ExecutedAt,
            EntraId = dto.EntraId,
            VaultId = dto.VaultId
        };
    }
}