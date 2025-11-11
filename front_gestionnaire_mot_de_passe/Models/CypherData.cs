using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace front_gestionnaire_mot_de_passe.Models;

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