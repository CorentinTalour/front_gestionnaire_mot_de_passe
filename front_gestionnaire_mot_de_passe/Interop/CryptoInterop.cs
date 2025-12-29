using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;
using System.Text.Json;


namespace front_gestionnaire_mot_de_passe.Interop;

public class CryptoInterop
{
    private readonly IJSRuntime _js;
    private readonly NavigationManager _nav;
    private IJSObjectReference?  _mod;

    public CryptoInterop(IJSRuntime js, NavigationManager nav)
    {
        _js = js;
        _nav = nav;
    }

    private async Task<IJSObjectReference> Mod()
    {
        var url = new Uri(new Uri(_nav.BaseUri), "js/crypto.js?v=23").ToString(); // ⭐ Incrémenté v=23
        return _mod ??= await _js.InvokeAsync<IJSObjectReference>("import", url);
    }
    
    public async Task SetApiAccessTokenAsync(string token) =>
        await (await Mod()).InvokeVoidAsync("setApiAccessToken", token);
    
    // ⭐ ANCIEN : Création de vault sans DEK (à garder pour compatibilité ou remplacer)
    public async Task<JsonElement> CreateVaultFromModalAsync(int iterations = 600_000, string apiBase = "https://localhost:7115") =>
        await (await Mod()).InvokeAsync<JsonElement>("createVaultFromModal", iterations, apiBase);
    
    // ⭐ NOUVEAU : Création de vault AVEC DEK
    public async Task<JsonElement> CreateVaultWithDEKAsync(int iterations = 600_000, string apiBase = "https://localhost:7115") =>
        await (await Mod()).InvokeAsync<JsonElement>("createVaultWithDEK", iterations, apiBase);
    
    public async Task<JsonElement> UpdateVaultFromModalAsync(int iterations = 600_000, string apiBase = "https://localhost:7115") =>
        await (await Mod()).InvokeAsync<JsonElement>("updateVaultFromModal");

    public async Task<object> OpenVaultFromInputAsync(int vaultId, string inputId, int autoLockMs = 300_000)
        => await (await Mod()).InvokeAsync<object>("openVaultFromInput", vaultId, inputId, autoLockMs);

    public async Task<object> EncryptEntryForOpenVaultAsync()
        => await (await Mod()).InvokeAsync<object>("encryptEntryForOpenVault");

    public async Task RenderVaultEntriesAsync(object records)
        => await (await Mod()).InvokeVoidAsync("renderVaultEntries", records);

    public async Task ClearVaultListAsync()
        => await (await Mod()).InvokeVoidAsync("clearVaultList");

    public async Task LockNowAsync()
        => await (await Mod()).InvokeVoidAsync("lockNow");

    public async Task TouchVaultAsync()
        => await (await Mod()).InvokeVoidAsync("touchVault");
    
    public async Task FillUpdateModalAsync(int vaultId, object entry)
        => await (await Mod()).InvokeVoidAsync("fillUpdateModal", vaultId, entry);

    public async Task GenerateAndFillPasswordAsync(string elementId, int length)
        => await (await Mod()).InvokeVoidAsync("generateAndFillPassword", elementId, length);

    public async Task<bool> UpdateEntryFromModalAsync(int entryId, string apiBase = "https://localhost:7115")
        => await (await Mod()).InvokeAsync<bool>("updateEntryFromModal", entryId, apiBase);

    public async Task<bool> CreateEntryFromModalAsync(int vaultId, string apiBase = "https://localhost:7115")
        => await (await Mod()).InvokeAsync<bool>("createEntryFromModal", vaultId, apiBase);

    public async Task<bool> IsVaultOpenAsync(int vaultId)
        => await (await Mod()).InvokeAsync<bool>("isVaultOpen", vaultId);

    public async Task DecryptEntryToDomAsync(int vaultId, object entry, object ids)
        => await (await Mod()).InvokeVoidAsync("decryptEntryToDom", vaultId, entry, ids);

    public async Task CopyDomTextToClipboardAsync(string elementId)
        => await (await Mod()).InvokeVoidAsync("copyDomTextToClipboard", elementId);

    public async Task TogglePasswordVisibilityAsync(string elementId)
        => await (await Mod()).InvokeVoidAsync("togglePasswordVisibility", elementId);

    // ⭐ ANCIEN : Ouverture sans DEK (à garder pour compatibilité ou remplacer)
    public async Task<bool> OpenVaultFromModalAsync(int vaultId, string inputId, string vaultSaltB64, int iterations, string apiBase = "https://localhost:7115")
        => await (await Mod()).InvokeAsync<bool>("openVaultFromModal", vaultId, inputId, vaultSaltB64, iterations, apiBase);
    
    // ⭐ NOUVEAU : Ouverture AVEC DEK
    public async Task<bool> OpenVaultWithDEKFromModalAsync(int vaultId, string inputId, string vaultSaltB64, int iterations, string apiBase = "https://localhost:7115")
        => await (await Mod()).InvokeAsync<bool>("openVaultWithDEKFromModal", vaultId, inputId, vaultSaltB64, iterations, apiBase);
    
    // ⭐ NOUVEAU :  Changement de mot de passe avec re-wrapping DEK
    public async Task<bool> ChangeVaultPasswordFromModalAsync(int vaultId, string apiBase = "https://localhost:7115")
        => await (await Mod()).InvokeAsync<bool>("changeVaultPasswordFromModal", vaultId, apiBase);
    
    public async Task InitPasswordStrengthMeterAsync(ElementReference inputRef)
        => await (await Mod()).InvokeVoidAsync("PasswordStrengthMeter", inputRef);
}