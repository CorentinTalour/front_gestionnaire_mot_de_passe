using front_gestionnaire_mot_de_passe.Models;
using Microsoft.AspNetCore.Components;
using Microsoft.Identity.Abstractions;

namespace front_gestionnaire_mot_de_passe.Components.Pages;

public partial class Home : ComponentBase
{
    [Inject] 
    private IDownstreamApi DownstreamApi { get; set; } = null!;
    
    private string _searchText = string.Empty;
    private bool _isModalVisibleCreateVault;
    
    private List<Vault> _vaults = new();

    private IEnumerable<Vault> FilteredVaults =>
        _vaults.Where(v => string.IsNullOrWhiteSpace(_searchText)
                           || v.Name.Contains(_searchText, StringComparison.OrdinalIgnoreCase));

    private void ClearSearch() => _searchText = string.Empty;
    private void ShowModal() => _isModalVisibleCreateVault = true;
    private void HideModal() => _isModalVisibleCreateVault = false;

    protected override async Task OnInitializedAsync()
    {
        try
        {
            await RefreshingVaults();
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"❌ Erreur HTTP: {ex.StatusCode} — {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Erreur lors du chargement des coffres : {ex.Message}");
        }
    }
    
    private Vault? _selectedVault;
    private bool _isOpenVaultVisible;

    private void OpenVault(Vault vault)
    {
        _selectedVault = vault;
        _isOpenVaultVisible = true;
    }

    private async Task HideModalCreateVault()
    {
        HideModal();
        await RefreshingVaults();
    }

    private async Task RefreshingVaults()
    {
        _vaults = await DownstreamApi.GetForUserAsync<List<Vault>>(
            "DownstreamApi",
            options => options.RelativePath = "/Vault"
        ) ?? new List<Vault>();

        Console.WriteLine($"✅ {_vaults.Count} coffres chargés.");
        // foreach (var v in _vaults)
        // {
        //     Console.WriteLine($"Id: {v.Id}, Name: {v.Name}, Salt: {v.Salt}, Password: ********, CreatedAt: {v.CreatedAt}, UpdatedAt: {v.UpdatedAt}, UserId: {v.UserId}");
        // }
    }

    private void CloseVault()
    {
        _isOpenVaultVisible = false;
        _selectedVault = null;
    }
    
    
}