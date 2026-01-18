using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace front_gestionnaire_mot_de_passe.Models;

public class Log
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }
    
    public string Url { get; set; } = string.Empty;
    
    public float Duration { get; set; }
    
    public DateTime ExecutedAt { get; set; }
    
    public string Message { get; set; } = string.Empty;
    
    public int? EntraId { get; set; }
    
    public int? VaultId { get; set; }
}