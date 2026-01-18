namespace front_gestionnaire_mot_de_passe.Models;

public class VaultEntryHistory
{
    public int Id { get; set; }
    
    public int EntryId { get; set; }
    
    public int UserNameCypherId { get; set; }

    public CypherData? UserNameCypher { get; set; }
    
    public int PasswordCypherId { get; set; }

    public CypherData? PasswordCypher { get; set; }
    
    public DateTime ModifiedAt { get; set; }
    
    public int NoteCypherId { get; set; }

    public CypherData? NoteCypher { get; set; }

    public int UrlCypherId { get; set; }
    
    public CypherData? UrlCypher { get; set; }
    
    public int NomCypherId { get; set; }
    
    public CypherData? NomCypher { get; set; }
}

