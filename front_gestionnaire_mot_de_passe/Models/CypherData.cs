using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace api_chiffrement_csharp.EF.Tables;

[Table("CypherData")]
public class CypherData
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }
    
    [Column(TypeName = "varbinary(max)")]
    public required byte[] CypherIv { get; set; }

    [Column(TypeName = "varbinary(max)")]
    public required byte[] CypherTag { get; set; }

    [Column(TypeName = "varbinary(max)")]
    public required byte[] Cypher { get; set; }
}