using front_gestionnaire_mot_de_passe.Models;
using Microsoft.Identity.Abstractions;

namespace front_gestionnaire_mot_de_passe.Services;

public interface IEntryService
{
    Task<VaultEntry?> GetEntryByIdAsync(int entryId);
    Task<List<VaultEntry>> GetEntriesByVaultIdAsync(int vaultId);
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

