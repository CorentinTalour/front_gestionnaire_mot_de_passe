using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace api_chiffrement_csharp.EF.Tables;

[Table("EntraUser")]
public class User
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    public required Guid EntraId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.Now;
}