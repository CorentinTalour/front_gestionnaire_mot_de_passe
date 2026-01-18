namespace front_gestionnaire_mot_de_passe.Services;

public class AppConfig
{
    public string ApiUrl { get; }
    
    public AppConfig(IConfiguration config)
    {
        ApiUrl = config["ApiSettings:ApiUrl"]
                 ?? throw new InvalidOperationException("ApiSettings:ApiUrl manquant dans appsettings.json");
    }
}