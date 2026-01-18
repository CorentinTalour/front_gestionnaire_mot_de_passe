using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

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
    
    // Propriétés Argon2 supplémentaires
    [JsonPropertyName("iterations")]
    public int? Iterations { get; set; }
    
    [JsonPropertyName("argon2Iterations")]
    public int? Argon2Iterations { get; set; }
    
    [JsonPropertyName("argon2MemoryKB")]
    public int? Argon2MemoryKB { get; set; }
    
    [JsonPropertyName("argon2Parallelism")]
    public int? Argon2Parallelism { get; set; }
    
    // Propriétés DEK (Data Encryption Key)
    [JsonPropertyName("wrappedDekB64")]
    [MaxLength(1000)]
    public string? WrappedDekB64 { get; set; }
    
    [JsonPropertyName("dekIvB64")]
    [MaxLength(1000)]
    public string? DekIvB64 { get; set; }
    
    [JsonPropertyName("dekTagB64")]
    [MaxLength(1000)]
    public string? DekTagB64 { get; set; }
    
    // Paramètres PBKDF2 pour la dérivation de la KEK côté client
    [JsonPropertyName("kekSaltB64")]
    [MaxLength(1000)]
    public string? KekSaltB64 { get; set; }
    
    [JsonPropertyName("kekIterations")]
    public int? KekIterations { get; set; }
    
    public DateTime CreatedAt { get; set; }
    
    public DateTime? UpdatedAt { get; set; } 
    [MaxLength(1000)]
    public string? Password { get; set; } 

    public int UserId { get; set; }
    [ForeignKey(nameof(UserId))]
    
    [NotMapped]
    public bool IsOwner { get; set; } = false;
}