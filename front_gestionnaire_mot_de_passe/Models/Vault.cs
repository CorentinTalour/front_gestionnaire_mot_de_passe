using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace api_chiffrement_csharp.EF.Tables;

[Table("Vault")]
public class Vault
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }
    [MaxLength(100)]
    public required string Name { get; set; } 
    [MaxLength(1000)]
    public required string Salt { get; set; } 
    public int NbIteration { get; set; }
    public DateTime CreatedAt { get; set; }
    
    public DateTime? UpdatedAt { get; set; } 
    [MaxLength(1000)]
    public required string Password { get; set; } 

    public int UserId { get; set; }
    [ForeignKey(nameof(UserId))]
    public User? User { get; set; }
}