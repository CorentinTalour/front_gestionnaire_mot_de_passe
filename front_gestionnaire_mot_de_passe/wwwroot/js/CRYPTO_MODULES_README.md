# Structure Modulaire Crypto.js

Ce document explique la nouvelle organisation modulaire du code cryptographique.

## 📁 Structure des fichiers

### Fichiers principaux

- **`crypto-main.js`** - Point d'entrée principal qui réexporte toutes les fonctions
- **`crypto.js`** - Fichier original (conservé pour compatibilité descendante)

### Modules fonctionnels

#### 1. `crypto-utils.js` - Utilitaires de base
Fonctions de conversion et d'encodage :
- `enc` - Encodeur de texte
- `b64()` - Conversion ArrayBuffer vers base64
- `b64d()` - Conversion base64 vers Uint8Array
- `asU8()` - Conversion universelle vers Uint8Array
- `TAG_BYTES` - Constante pour la taille du tag GCM

#### 2. `crypto-auth.js` - Authentification API
Gestion du token d'authentification :
- `setApiAccessToken()` - Définit le token Bearer
- `authHeaders()` - Génère les headers d'authentification

#### 3. `crypto-vault-session.js` - Session du vault en mémoire
Gestion de l'état du vault et auto-lock :
- `currentVault` - Objet contenant l'ID et la clé du vault ouvert
- `isVaultOpen()` - Vérifie si un vault est ouvert
- `touchVault()` - Réinitialise le timer d'auto-lock
- `lockNow()` - Verrouille immédiatement le vault
- `clearVaultList()` - Vide l'affichage des entrées

#### 4. `crypto-encryption.js` - Chiffrement/Déchiffrement
Opérations cryptographiques de base :
- `splitCtAndTag()` - Sépare cipher et tag GCM
- `joinCtAndTag()` - Joint cipher et tag GCM
- `encFieldWithVaultKey()` - Chiffre un champ avec AES-GCM
- `decFieldWithVaultKey()` - Déchiffre un champ avec AES-GCM
- `makeCypherObj()` - Crée un objet chiffré pour l'API

#### 5. `crypto-vault-management.js` - Gestion des vaults
Création, ouverture et modification des vaults :
- `openVault()` - Ouvre un vault avec mot de passe
- `openVaultFromInput()` - Ouvre depuis un champ input
- `verifyVaultPasswordServer()` - Vérifie le mot de passe auprès du serveur
- `armVaultSession()` - Dérive et stocke la clé en RAM
- `openVaultAfterVerify()` - Combine vérification + armement
- `openVaultFromModal()` - Ouvre depuis une modale
- `createVaultVerifierFromInput()` - Crée un vault (ancien flux)
- `createVaultFromModal()` - Crée un vault depuis une modale
- `updateVaultFromModal()` - Met à jour un vault

#### 6. `crypto-entry-management.js` - Gestion des entrées
Création, modification et affichage des entrées :
- `encryptEntryForOpenVault()` - Chiffre une entrée (ancien flux)
- `createEntryFromModal()` - Crée une entrée depuis une modale
- `updateEntryFromModal()` - Met à jour une entrée
- `fillUpdateModal()` - Remplit la modale de modification
- `decryptVaultEntry()` - Déchiffre une entrée
- `renderVaultEntries()` - Affiche les entrées dans le DOM
- `decryptEntryToDom()` - Déchiffre et affiche une entrée

#### 7. `crypto-password-tools.js` - Outils de mots de passe
Génération et gestion de la visibilité :
- `maskPassword()` - Masque un mot de passe avec des points
- `togglePasswordVisibility()` - Bascule affichage clair/masqué
- `copyDomTextToClipboard()` - Copie dans le presse-papiers
- `generateSecurePassword()` - Génère un mot de passe sécurisé
- `generateAndFillPassword()` - Génère et remplit un champ

#### 8. `crypto-dek-kek.js` - Système de clé magique
Gestion avancée avec DEK (Data Encryption Key) et KEK (Key Encryption Key) :
- `createVaultWithDEK()` - Crée un vault avec système DEK/KEK
- `openVaultWithDEKFromModal()` - Ouvre un vault avec DEK
- `changeVaultPassword()` - Change le mot de passe en re-wrappant la DEK
- `changeVaultPasswordFromModal()` - Change depuis une modale

## 🔄 Migration et compatibilité

### Pour le code existant

Le fichier `crypto.js` original peut être remplacé par `crypto-main.js` qui réexporte toutes les fonctions :

```javascript
// Ancien import (toujours fonctionnel)
import { openVault, createEntryFromModal } from './crypto.js';

// Nouveau import (recommandé)
import { openVault, createEntryFromModal } from './crypto-main.js';
```

### Imports spécifiques recommandés

Pour de meilleures performances et une meilleure lisibilité, importez uniquement ce dont vous avez besoin :

```javascript
// Import spécifique d'un module
import { openVault, armVaultSession } from './crypto-vault-management.js';
import { createEntryFromModal } from './crypto-entry-management.js';
import { generateSecurePassword } from './crypto-password-tools.js';
```

## 🎯 Avantages de cette structure

1. **Maintenabilité** - Chaque module a une responsabilité claire
2. **Testabilité** - Les modules peuvent être testés indépendamment
3. **Lisibilité** - Plus facile de trouver et comprendre le code
4. **Réutilisabilité** - Les modules peuvent être utilisés séparément
5. **Performance** - Possibilité d'importer uniquement ce qui est nécessaire
6. **Évolutivité** - Facilite l'ajout de nouvelles fonctionnalités

## 📝 Conventions de code

- Les fonctions exportées sont en camelCase
- Les fonctions privées commencent par `_`
- Les constantes sont en UPPER_SNAKE_CASE
- Chaque fonction est documentée avec JSDoc
- Les imports sont regroupés par module en début de fichier

## 🔒 Sécurité

Cette refactorisation ne modifie **aucune** logique cryptographique :
- Même algorithmes (AES-GCM, PBKDF2)
- Mêmes paramètres de sécurité
- Même gestion des clés en mémoire
- Même système d'auto-lock

Seule l'organisation du code a changé pour améliorer la maintenabilité.

