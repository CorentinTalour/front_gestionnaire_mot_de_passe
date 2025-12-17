using System.Text.Json.Serialization;

namespace front_gestionnaire_mot_de_passe.Models.VaultMembers;

public class PostVaultMemeberObj
{
    [JsonPropertyName("vaultId")]
    public int VaultId { get; set; }
    [JsonPropertyName("userId")]
    public int UserId { get; set; }
}