# Gestionnaire de Mots de Passe - Frontend

Application web Blazor Server pour la gestion sécurisée de coffres-forts de mots de passe avec authentification Microsoft Entra ID (Azure AD).

## Prérequis

### Logiciels requis
- **.NET 8.0 SDK** ou ultérieur
- **IDE** : Visual Studio 2022, JetBrains Rider ou Visual Studio Code
- **Navigateur web** moderne (Chrome, Edge, Firefox)

### Services externes
- **Microsoft Entra ID (Azure AD)** : Une application doit être enregistrée dans Azure
- **API Backend** : L'API de chiffrement doit être déployée et accessible sur `https://localhost:7115` (en développement)

### Dépendances du projet

> [!WARNING]
> Le projet référence également :
> - **DtoLib** : Bibliothèque de DTO située dans `../../api_chiffrement_scharp/DtoLib/`

## Installation

### 1. Cloner le dépôt
```bash
git clone <https://github.com/CorentinTalour/front_gestionnaire_mot_de_passe.git>
cd front_gestionnaire_mot_de_passe
```

### 2. Vérifier la version .NET
```bash
dotnet --version
```
Assurez-vous que la version est 8.0.0 ou supérieure.

### 3. Restaurer les dépendances
```bash
dotnet restore
```

## Configuration

### 1. Configuration Azure AD

Avant de lancer l'application, vous devez configurer le fichier `appsettings.Development.json` avec vos propres identifiants Azure AD :

```json
{
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "VOTRE_TENANT_ID",
    "ClientId": "VOTRE_CLIENT_ID",
    "ClientSecret": "VOTRE_CLIENT_SECRET",
    "CallbackPath": "/signin-oidc"
  }
}
```

**⚠️ IMPORTANT** : Ne commitez JAMAIS vos secrets réels dans le dépôt Git.

### 2. Configuration de l'API Backend

Dans `appsettings.Development.json`, configurez l'URL de votre API :

```json
{
  "DownstreamApi": {
    "BaseUrl": "https://localhost:7115",
    "Scopes": [
      "api://VOTRE_API_APP_ID/access_as_user"
    ]
  },
  "ApiSettings": {
    "ApiUrl": "https://localhost:7115"
  }
}
```

### 3. Configuration CORS

Assurez-vous que l'URL du frontend correspond à celle configurée :

```json
{
  "Cors": {
    "AllowedOrigins": "https://localhost:7093"
  }
}
```

### 4. Certificat HTTPS de développement

Si ce n'est pas déjà fait, installez le certificat de développement HTTPS :

```bash
dotnet dev-certs https --trust
```

## Lancement de l'application

### Option 1 : Ligne de commande

#### En mode développement
```bash
cd front_gestionnaire_mot_de_passe
dotnet run
```

L'application sera accessible sur :
- **HTTPS** : https://localhost:7093
- **HTTP** : http://localhost:5166

#### En mode production
```bash
dotnet run --configuration Release
```

### Option 2 : Avec JetBrains Rider
1. Ouvrir le fichier solution `.sln`
2. Sélectionner le profil de lancement "https"
3. Cliquer sur le bouton "Run" ou appuyer sur `Shift + F10`

### Option 3 : Avec Visual Studio
1. Ouvrir le fichier solution `.sln`
2. Appuyer sur `F5` pour lancer en mode debug ou `Ctrl + F5` pour lancer sans debug

## Architecture du projet

```
front_gestionnaire_mot_de_passe/
├── Components/              # Composants Blazor
│   ├── Pages/              # Pages de l'application
│   ├── Layout/             # Layouts
│   ├── CreateVaultModal/   # Modal de création de coffre
│   ├── VaultDisplay/       # Affichage des coffres
│   └── ...                 # Autres composants
├── Services/               # Services métier
│   ├── VaultService.cs     # Service de gestion des coffres
│   ├── EntryService.cs     # Service de gestion des entrées
│   ├── UsersService.cs     # Service de gestion des utilisateurs
│   └── TokenService.cs     # Service de gestion des tokens
├── Models/                 # Modèles de données
├── Interop/               # Interopérabilité JavaScript
├── Utils/                 # Utilitaires
└── wwwroot/               # Fichiers statiques

```

## Dépendances principales

- **Microsoft.Identity.Web** : Authentification Azure AD
- **Microsoft.AspNetCore.Authentication.OpenIdConnect** : Authentification OpenID Connect
- **Blazor Server** : Framework pour l'interface utilisateur interactive
