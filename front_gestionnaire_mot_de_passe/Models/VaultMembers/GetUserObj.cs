using System.Text.Json.Serialization;

namespace front_gestionnaire_mot_de_passe.Models.VaultMembers;

public class GetUserObj
{
    [JsonPropertyName("id")]
    public int Id { get; set; }
    [JsonPropertyName("email")]
    public required string Email { get; set; }
}