using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace front_gestionnaire_mot_de_passe.Models;

public class VaultEntryHistory
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }
    
    public int EntryId { get; set; }
    
    public int UserNameCypherId { get; set; }
    [ForeignKey(nameof(UserNameCypherId))]
    public CypherData? UserNameCypher { get; set; }
    
    public int PasswordCypherId { get; set; }
    [ForeignKey(nameof(PasswordCypherId))]
    public CypherData? PasswordCypher { get; set; }
    
    public DateTime ModifiedAt { get; set; }
    
    public int NoteCypherId { get; set; }
    [ForeignKey(nameof(NoteCypherId))]
    public CypherData? NoteCypher { get; set; }

    public int UrlCypherId { get; set; }
    [ForeignKey(nameof(UrlCypherId))]
    public CypherData? UrlCypher { get; set; }
    
    public int NomCypherId { get; set; }
    [ForeignKey(nameof(NomCypherId))]
    public CypherData? NomCypher { get; set; }
}

