using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace api_chiffrement_csharp.EF.Tables;

public class VaultEntry
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }
    
    public int UserNameCypherId { get; set; }
    [ForeignKey(nameof(UserNameCypherId))]
    public CypherData? UserNameCypher { get; set; }
    
    public int PasswordCypherId { get; set; }
    [ForeignKey(nameof(PasswordCypherId))]
    public CypherData? PasswordCypher { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    
    public DateTime? UpdatedAt { get; set; } 
    
    public int NoteCypherId { get; set; }
    [ForeignKey(nameof(NoteCypherId))]
    public CypherData? NoteCypher { get; set; }

    public int UrlCypherId { get; set; }
    [ForeignKey(nameof(UrlCypherId))]
    public CypherData? UrlCypher { get; set; }
    
    public int NomCypherId { get; set; }
    [ForeignKey(nameof(NomCypherId))]
    public CypherData? NomCypher { get; set; }

    public int VaultId { get; set; }

    [ForeignKey(nameof(VaultId))]
    public Vault Vault { get; set; }
}