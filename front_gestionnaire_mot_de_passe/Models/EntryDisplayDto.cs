namespace front_gestionnaire_mot_de_passe.Models;

/// <summary>
/// DTO pour l'affichage des détails d'une entrée avec les données déchiffrées
/// </summary>
public class EntryDisplayDto
{
    public int Id { get; set; }
    public string NomCypher { get; set; } = "";
    public string UserNameCypher { get; set; } = "";
    public string PasswordCypher { get; set; } = "";
    public string NoteCypher { get; set; } = "";
    public string UrlCypher { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public int VaultId { get; set; }
}

