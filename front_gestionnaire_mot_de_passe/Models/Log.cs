using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace front_gestionnaire_mot_de_passe.Models;

public class Log
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }
    
    public required string Url { get; set; }
    
    public float Duration { get; set; }
    
    public DateTime ExecutedAt { get; set; }
    
    public required string Message { get; set; }
    
    public int? EntraId { get; set; }


    public int? VaultId { get; set; }
    
    
}