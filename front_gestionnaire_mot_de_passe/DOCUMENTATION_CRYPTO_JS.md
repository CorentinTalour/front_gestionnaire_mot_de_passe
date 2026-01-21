# Documentation Cryptographie JavaScript
## Gestionnaire de Mots de Passe

**Date:** 21 janvier 2026  
**Auteur:** Projet Front Gestionnaire Mot de Passe  

---

## 📁 Architecture des fichiers cryptographiques

Tous les fichiers se trouvent dans : `/front_gestionnaire_mot_de_passe/wwwroot/js/`

### Fichiers principaux :

1. **`crypto-vault-management.js`** - Gestion des vaults (création, ouverture)
2. **`crypto-dek-kek.js`** - Système de clés DEK/KEK
3. **`crypto-encryption.js`** - Chiffrement/déchiffrement des données
4. **`crypto-entry-management.js`** - Gestion des entrées (création, modification)
5. **`crypto-utils.js`** - Utilitaires (encodage base64, conversions)
6. **`crypto-vault-session.js`** - Gestion de la session et auto-lock
7. **`crypto-auth.js`** - Headers d'authentification
8. **`crypto-password-tools.js`** - Outils pour les mots de passe

---

## 🔐 1. Dérivation de clés avec PBKDF2

### 📍 Localisation : `crypto-dek-kek.js` - Lignes 19-41

**Fonction :** `deriveKEK(password, kekSaltB64, iterations, extractable)`

**Rôle :** Transforme un mot de passe en clé cryptographique AES-256

**Paramètres de sécurité :**
- **Algorithme :** PBKDF2
- **Hash :** SHA-256
- **Itérations :** 600 000 (défaut)
- **Salt :** 32 bytes aléatoires (unique par vault)
- **Extractable :** `false` (clé non-extractable via DevTools)

**Code clé :**
```javascript
const pwKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), 
    { name: "PBKDF2" }, false, ["deriveKey"]
);

return await crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: b64d(kekSaltB64), iterations },
    pwKey,
    { name: "AES-GCM", length: 256 },
    false,  // NON-EXTRACTABLE
    ["encrypt", "decrypt"]
);
```

### 📍 Autres utilisations de PBKDF2 :

- **`crypto-vault-management.js`** - Ligne 27 : `openVault()` - Ouverture d'un vault
- **`crypto-vault-management.js`** - Ligne 109 : `armVaultSession()` - Armer la session

---

## 🔒 2. Chiffrement avec AES-GCM

### 📍 Localisation : `crypto-encryption.js` - Lignes 35-47

**Fonction :** `encFieldWithVaultKey(text, aad)`

**Rôle :** Chiffre un champ texte avec authentification

**Paramètres :**
- **Algorithme :** AES-GCM (mode authentifié)
- **Taille clé :** 256 bits
- **IV :** 12 bytes aléatoires (unique par chiffrement)
- **Tag :** 16 bytes (pour vérification d'intégrité)
- **AAD :** Données additionnelles authentifiées (ex: `vault:123|field:password`)

**Code clé :**
```javascript
const iv = crypto.getRandomValues(new Uint8Array(12));
const ctFull = await crypto.subtle.encrypt(
    {name: "AES-GCM", iv, additionalData: aad ? enc.encode(aad) : undefined},
    currentVault.key,
    enc.encode(text ?? "")
);
const {cipher, tag} = splitCtAndTag(ctFull);
return {cipher, tag, iv};
```

**Sortie :** Objet contenant `{cipher, tag, iv}` en Uint8Array

---

## 🔓 3. Déchiffrement avec AES-GCM

### 📍 Localisation : `crypto-encryption.js` - Lignes 56-68

**Fonction :** `decFieldWithVaultKey(cipherU8, tagU8, ivU8, aad)`

**Rôle :** Déchiffre et vérifie l'authenticité des données

**Code clé :**
```javascript
const full = joinCtAndTag(cipherU8, tagU8);
const pt = await crypto.subtle.decrypt(
    {name: "AES-GCM", iv: ivU8, additionalData: aad ? enc.encode(aad) : undefined},
    currentVault.key,
    full
);
return new TextDecoder().decode(pt);
```

**Sécurité :** Le tag GCM garantit que les données n'ont pas été modifiées

---

## 🗝️ 4. Système DEK/KEK (Data Encryption Key / Key Encryption Key)

### Architecture à deux niveaux de clés :

#### **KEK (Key Encryption Key)**
- **Fichier :** `crypto-dek-kek.js` - Ligne 19
- **Dérivée depuis :** Le mot de passe maître (PBKDF2)
- **Rôle :** Protège la DEK
- **Stockage :** Jamais stockée (recalculée à chaque ouverture)

#### **DEK (Data Encryption Key)**
- **Fichier :** `crypto-dek-kek.js` - Ligne 48
- **Générée :** Aléatoirement (32 bytes)
- **Rôle :** Chiffre/déchiffre toutes les entrées du vault
- **Stockage :** Chiffrée avec la KEK (`wrappedDekB64`)

### 📍 Wrapping de la DEK (Ligne 62-91)

**Fonction :** `wrapDEK(dekBytes, kek)`

**Rôle :** Chiffre la DEK avec la KEK pour la stocker en base de données

```javascript
const iv = crypto.getRandomValues(new Uint8Array(12));
const ctFull = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    kek,
    dekBytes
);
return { wrappedDek: b64(cipher), iv: b64(iv), tag: b64(tag) };
```

### 📍 Unwrapping de la DEK (Ligne 97-129)

**Fonction :** `unwrapDEK(wrappedDekB64, ivB64, tagB64, kek)`

**Rôle :** Déchiffre la DEK pour l'utiliser en mémoire

```javascript
const dekRaw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    kek,
    full
);

const dekKey = await crypto.subtle.importKey(
    "raw", dekRawArray,
    { name: "AES-GCM", length: 256 },
    false,  // NON-EXTRACTABLE
    ["encrypt", "decrypt"]
);

// Effacement sécurisé
dekRawArray.fill(0);
return dekKey;
```

---

## 📝 5. Création d'un vault

### 📍 Localisation : `crypto-dek-kek.js` - Lignes 139-204

**Fonction :** `createVaultWithDEK(iterations, apiBase)`

**Flux :**
1. Génération du salt KEK (32 bytes aléatoires)
2. Dérivation de la KEK avec PBKDF2
3. Génération de la DEK (32 bytes aléatoires)
4. Wrapping de la DEK avec la KEK
5. Envoi au serveur : `{wrappedDekB64, dekIvB64, dekTagB64, kekSaltB64}`
6. Effacement des bytes sensibles de la mémoire

**Code principal :**
```javascript
const kekSalt = crypto.getRandomValues(new Uint8Array(32));
const kek = await deriveKEK(password, b64(kekSalt), iterations);
const dekBytes = generateDEK();  // 32 bytes aléatoires
const { wrappedDek, iv, tag } = await wrapDEK(dekBytes, kek);
dekBytes.fill(0);  // Effacement sécurisé
```

---

## 🔓 6. Ouverture d'un vault

### 📍 Localisation : `crypto-dek-kek.js` - Lignes 212-278

**Fonction :** `openVaultWithDEKFromModal(vaultId, inputId, ...)`

**Flux :**
1. Vérification du mot de passe auprès du serveur
2. Récupération des données : `{wrappedDekB64, dekIvB64, dekTagB64, kekSaltB64}`
3. Dérivation de la KEK depuis le mot de passe
4. Unwrapping de la DEK
5. Stockage de la DEK en RAM (`currentVault.key`)

**Code principal :**
```javascript
const kek = await deriveKEK(password, kekSaltToUse, kekIterationsToUse);
const dek = await unwrapDEK(
    vault.wrappedDekB64,
    vault.dekIvB64,
    vault.dekTagB64,
    kek
);
setCurrentVault(vaultId, dek);
```

---

## 🔄 7. Changement de mot de passe

### 📍 Localisation : `crypto-dek-kek.js` - Lignes 286-393

**Fonction :** `changeVaultPassword(vaultId, oldPassword, newPassword, apiBase)`

**Flux :**
1. Dérivation de l'ancienne KEK
2. Unwrap de la DEK avec l'ancienne KEK
3. Dérivation de la nouvelle KEK
4. Re-wrap de la DEK avec la nouvelle KEK
5. Mise à jour en base de données
6. Effacement des bytes sensibles

**Particularité :** La DEK ne change pas, seule la KEK change

```javascript
const oldKek = await deriveKEK(oldPassword, kekSaltB64, kekIterations);
dekRawBytes = await crypto.subtle.decrypt({name: "AES-GCM", iv}, oldKek, full);

const newKek = await deriveKEK(newPassword, kekSaltB64, kekIterations);
const { wrappedDek: newWrappedDek, iv: newIv, tag: newTag } = 
    await wrapDEK(dekBytesArray, newKek);

dekBytesArray.fill(0);  // Effacement
```

---

## 📄 8. Création d'une entrée

### 📍 Localisation : `crypto-entry-management.js` - Lignes 40-120

**Fonction :** `createEntryFromModal(vaultId, apiBase)`

**Flux :**
1. Récupération des valeurs depuis les champs DOM
2. Vérification que la DEK est en mémoire
3. Chiffrement de chaque champ avec `makeCypherObj()`
4. Envoi au serveur des données chiffrées

**Code principal :**
```javascript
const ns = `vault:${vaultId}`;
const userNameCypherObj = await makeCypherObj(username, `${ns}|field:username`);
const passwordCypherObj = await makeCypherObj(password, `${ns}|field:password`);
const urlCypherObj = await makeCypherObj(url, `${ns}|field:url`);
const noteCypherObj = await makeCypherObj(notes, `${ns}|field:notes`);

const payload = {
    vaultId,
    userNameCypherObj,  // {baseCypher, baseCypherTag, baseCypherIv}
    passwordCypherObj,
    urlCypherObj,
    noteCypherObj
};
```

**AAD utilisés :**
- `vault:123|field:username`
- `vault:123|field:password`
- `vault:123|field:url`
- `vault:123|field:notes`

---

## 🔍 9. Déchiffrement d'une entrée

### 📍 Localisation : `crypto-entry-management.js` - Lignes 214-273

**Fonction :** `decryptVaultEntry(entry)`

**Flux :**
1. Vérification que la DEK est en mémoire
2. Déchiffrement de chaque champ avec `decryptCypherObj()`
3. Retour d'un objet avec les valeurs en clair

**Code principal :**
```javascript
const ns = `vault:${currentVault.id}`;
const username = await decryptCypherObj(entry.userNameCypherObj, `${ns}|field:username`);
const password = await decryptCypherObj(entry.passwordCypherObj, `${ns}|field:password`);
const url = await decryptCypherObj(entry.urlCypherObj, `${ns}|field:url`);
const notes = await decryptCypherObj(entry.noteCypherObj, `${ns}|field:notes`);

return { id: entry.id, username, password, url, notes, ... };
```

---

## 📝 Note importante

**DEK/KEK :** Séparation entre la clé de données (DEK) et la clé de protection (KEK)

---