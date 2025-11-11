using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using api_chiffrement_csharp.EF.Tables;

namespace front_gestionnaire_mot_de_passe.Models;

[Table("Vault")]
public class Vault
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }
    [MaxLength(100)]
    public string Name { get; set; } 
    [MaxLength(1000)]
    public string Salt { get; set; } 
    public int NbIteration { get; set; }
    public DateTime CreatedAt { get; set; }
    
    public DateTime? UpdatedAt { get; set; } 
    [MaxLength(1000)]
    public string Password { get; set; } 

    public int UserId { get; set; }
    [ForeignKey(nameof(UserId))]
    public User? User { get; set; }
}