using front_gestionnaire_mot_de_passe.Models;

namespace front_gestionnaire_mot_de_passe.Services;

public class VaultState
{
    public Vault? CurrentVault { get; private set; }

    public void Set(Vault vault)
    {
        CurrentVault = vault;
    }

    public void Clear()
    {
        CurrentVault = null;
    }
}