using front_gestionnaire_mot_de_passe.Models;
using Microsoft.Identity.Abstractions;

namespace front_gestionnaire_mot_de_passe.Services;

public interface IEntryService
{
    Task<VaultEntry?> GetEntryByIdAsync(int entryId);
    Task<List<VaultEntry>> GetEntriesByVaultIdAsync(int vaultId);
    Task<List<VaultEntryHistory>> GetEntryHistoryAsync(int entryId);
}

public class EntryService : IEntryService
{
    private readonly IDownstreamApi _api;
    private readonly ILogger<EntryService> _logger;

    public EntryService(IDownstreamApi api, ILogger<EntryService> logger)
    {
        _api = api;
        _logger = logger;
    }

    public async Task<VaultEntry?> GetEntryByIdAsync(int entryId)
    {
        try
        {
            // Note: Cet endpoint pourrait ne pas exister côté backend
            // Il faudrait récupérer l'entrée depuis GetEntriesByVaultIdAsync
            var entry = await _api.GetForUserAsync<VaultEntry>(
                "DownstreamApi",
                o => o.RelativePath = $"/Entry/{entryId}"
            );

            if (entry != null)
            {
                _logger.LogInformation("Entrée trouvée - ID: {EntryId}", entryId);
            }
            else
            {
                _logger.LogWarning("Aucune entrée trouvée avec l'ID {EntryId}", entryId);
            }

            return entry;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération de l'entrée {EntryId}", entryId);
            return null;
        }
    }

    public async Task<List<VaultEntryHistory>> GetEntryHistoryAsync(int entryId)
    {
        try
        {
            var history = await _api.GetForUserAsync<List<VaultEntryHistory>>(
                "DownstreamApi",
                o => o.RelativePath = $"/Entry/{entryId}"
            ) ?? new();

            _logger.LogInformation("Historique récupéré pour l'entrée {EntryId} : {Count} versions", entryId, history.Count);
            return history;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération de l'historique de l'entrée {EntryId}", entryId);
            return new List<VaultEntryHistory>();
        }
    }

    public async Task<List<VaultEntry>> GetEntriesByVaultIdAsync(int vaultId)
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
}

