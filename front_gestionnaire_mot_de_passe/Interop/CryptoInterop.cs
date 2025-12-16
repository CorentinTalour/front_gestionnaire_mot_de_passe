using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;
using System.Text.Json;

namespace front_gestionnaire_mot_de_passe.Interop;

public class CryptoInterop
{
    private readonly IJSRuntime _js;
    private readonly NavigationManager _nav;
    private IJSObjectReference? _mod;

    public CryptoInterop(IJSRuntime js, NavigationManager nav)
    {
        _js = js;
        _nav = nav;
    }

    private async Task<IJSObjectReference> Mod()
    {
        var url = new Uri(new Uri(_nav.BaseUri), "js/crypto.js?v=21").ToString();
        return _mod ??= await _js.InvokeAsync<IJSObjectReference>("import", url);
    }
    
    public async Task SetApiAccessTokenAsync(string token) =>
        await (await Mod()).InvokeVoidAsync("setApiAccessToken", token);
    
    public async Task<JsonElement> CreateVaultFromModalAsync(int iterations = 600_000, string apiBase = "https://localhost:7115") =>
        await (await Mod()).InvokeAsync<JsonElement>("createVaultFromModal", iterations, apiBase);

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
    
    public async Task<System.Text.Json.JsonElement> VerifyVaultPasswordAsync(int vaultId, string password, string apiBase = "https://localhost:7115")
        => await (await Mod()).InvokeAsync<System.Text.Json.JsonElement>("verifyVaultPassword", vaultId, password, apiBase);
    
    public async Task<bool> CreateEntryFromModalAsync(int vaultId, string apiBase)
        => await (await Mod()).InvokeAsync<bool>("createEntryFromModal", vaultId, apiBase);
    
    public async Task<System.Text.Json.JsonElement> VerifyVaultPasswordServerAsync(
        int? vaultId, string password, string apiBase = "https://localhost:7115") =>
        await (await Mod()).InvokeAsync<System.Text.Json.JsonElement>(
            "verifyVaultPasswordServer", vaultId, password, apiBase);

    public async Task ArmVaultSessionAsync(
        int? vaultId, string password, string vaultSaltB64, int? iterations) =>
        await (await Mod()).InvokeVoidAsync(
            "armVaultSession", vaultId, password, vaultSaltB64, iterations);
    
    public async Task DecryptEntryToDomAsync(int vaultId, object entry, object ids)
        => await (await Mod()).InvokeVoidAsync("decryptEntryToDom", vaultId, entry, ids);

    public async Task CopyDomTextToClipboardAsync(string elementId)
        => await (await Mod()).InvokeVoidAsync("copyDomTextToClipboard", elementId);
    
    public async Task TogglePasswordVisibilityAsync(string elementId)
        => await (await Mod()).InvokeVoidAsync("togglePasswordVisibility", elementId);

    public async Task<bool> IsVaultOpenAsync(int vaultId)
        => await (await Mod()).InvokeAsync<bool>("isVaultOpen", vaultId);
    
    public async Task<bool> OpenVaultFromModalAsync(
        int vaultId,
        string inputId,
        string vaultSaltB64,
        int iterations,
        string apiBase = "https://localhost:7115")
        => await (await Mod()).InvokeAsync<bool>(
            "openVaultFromModal",
            vaultId, inputId, vaultSaltB64, iterations, apiBase);
}