using DtoLib.Objet.Cypher;
using DtoLib.Objet.Entry;
using front_gestionnaire_mot_de_passe.Models;
using Microsoft.Identity.Abstractions;

namespace front_gestionnaire_mot_de_passe.Services;

public interface IEntryService
{
    Task<VaultEntry?> GetEntryByIdAsync(int entryId);
    Task<List<VaultEntry>> GetEntriesByVaultIdAsync(int vaultId);
    Task<List<VaultEntry>> GetEntryHistoryAsync(int entryId);
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

    // Plus utilisé
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

    public async Task<List<VaultEntry>> GetEntryHistoryAsync(int entryId)
    {
        try
        {
            List<GetEntryObj> historyDto = await _api.GetForUserAsync<List<GetEntryObj>>(
                "DownstreamApi",
                o => o.RelativePath = $"/Entry/{entryId}"
            ) ?? new();

            List<VaultEntry> history = historyDto.Select(MapDtoToVaultEntry).ToList();
            
            _logger.LogInformation("Historique récupéré pour l'entrée {EntryId} : {Count} versions", entryId, history.Count);
            return history;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération de l'historique de l'entrée {EntryId}", entryId);
            return new List<VaultEntry>();
        }
    }

    public async Task<List<VaultEntry>> GetEntriesByVaultIdAsync(int vaultId)
    {
        try
        {
            List<GetEntryObj> entriesDto = await _api.GetForUserAsync<List<GetEntryObj>>(
                "DownstreamApi",
                o => o.RelativePath = $"/Entry/VaultId?vaultId={vaultId}"
            ) ?? new();
            
            List<VaultEntry> entries = entriesDto.Select(MapDtoToVaultEntry).ToList();

            _logger.LogInformation("Nombre d'entrées récupérées pour le coffre {VaultId} : {Count}", vaultId, entries.Count);
            return entries;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de la récupération des entrées du coffre {VaultId}", vaultId);
            return new List<VaultEntry>();
        }
    }
    
    private VaultEntry MapDtoToVaultEntry(GetEntryObj dto)
    {
        return new VaultEntry
        {
            Id = dto.Id,
            VaultId = dto.VaultId,
            UserNameCypherId = dto.UserNameCypherId,
            UserNameCypher = dto.UserNameCypherObj != null ? MapDtoToCypherData(dto.UserNameCypherObj) : null,
            PasswordCypherId = dto.PasswordCypherId,
            PasswordCypher = dto.PasswordCypherObj != null ? MapDtoToCypherData(dto.PasswordCypherObj) : null,
            UrlCypherId = dto.UrlCypherId,
            UrlCypher = dto.UrlCypherObj != null ? MapDtoToCypherData(dto.UrlCypherObj) : null,
            NoteCypherId = dto.NoteCypherId,
            NoteCypher = dto.NoteCypherObj != null ? MapDtoToCypherData(dto.NoteCypherObj) : null,
            NomCypherId = dto.NomCypherId,
            NomCypher = dto.NomCypherObj != null ? MapDtoToCypherData(dto.NomCypherObj) : null,
            CreatedAt = dto.CreatedAt,
            UpdatedAt = dto.UpdatedAt
        };
    }

    private CypherData? MapDtoToCypherData(GetCypherObj? dto)
    {
        if (dto == null) return null;

        return new CypherData
        {
            Cypher = dto.Cypher,
            CypherIv = dto.CypherIv,
            CypherTag = dto.CypherTag
        };
    }

}

