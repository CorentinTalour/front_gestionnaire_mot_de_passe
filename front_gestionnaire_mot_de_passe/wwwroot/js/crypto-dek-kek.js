// ==============================
// GESTION DE LA CLÉ (DEK/KEK)
// ==============================

import { enc, b64, b64d } from './crypto-utils.js';
import { authHeaders } from './crypto-auth.js';
import { setCurrentVault } from './crypto-vault-session.js';
import { splitCtAndTag, joinCtAndTag } from './crypto-encryption.js';
import { verifyVaultPasswordServer } from './crypto-vault-management.js';
import { apiBaseUrl } from "./crypto-config.js";

// Constante pour les itérations PBKDF2 (dérivation de la KEK)
const DEFAULT_PBKDF2_ITERATIONS = 600000;

/**
 * Dérive une KEK (Key Encryption Key) depuis un mot de passe avec PBKDF2
 * @param {string} password - Mot de passe maître
 * @param {string} kekSaltB64 - Salt en base64
 * @param {number} iterations - Nombre d'itérations PBKDF2
 * @param {boolean} extractable - Si la clé doit être extractable
 * @returns {Promise<CryptoKey>} KEK dérivée
 */
async function deriveKEK(password, kekSaltB64, iterations = DEFAULT_PBKDF2_ITERATIONS, extractable = false) {
    if (extractable === true) {
        console.error("SÉCURITÉ: Tentative de créer une KEK extractable bloquée!");
        extractable = false;
    }
    
    const pwKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return await crypto.subtle.deriveKey(
        { name: "PBKDF2", hash: "SHA-256", salt: b64d(kekSaltB64), iterations },
        pwKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

/**
 * Génère une nouvelle DEK (Data Encryption Key) aléatoire sous forme de bytes bruts
 * Les bytes peuvent être wrappés sans jamais créer de clé extractable
 * @returns {Uint8Array} 32 bytes aléatoires (256 bits) pour la DEK
 */
function generateDEK() {
    // SÉCURITÉ: Génération de 32 bytes aléatoires directement
    return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Chiffre (wrap) la DEK avec la KEK (clé dérivée du mot de passe)
 * SÉCURITÉ: Accepte UNIQUEMENT des bytes bruts (ArrayBuffer/Uint8Array)
 * @param {ArrayBuffer|Uint8Array} dekBytes - Les bytes bruts de la DEK (32 bytes)
 * @param {CryptoKey} kek - La clé dérivée du mot de passe (KEK non-extractable)
 * @returns {Promise<{wrappedDek: string, iv: string, tag: string}>}
 */
async function wrapDEK(dekBytes, kek) {
    // SÉCURITÉ: On n'accepte que des bytes bruts
    if (dekBytes instanceof CryptoKey) {
        throw new Error("SÉCURITÉ: wrapDEK n'accepte que des bytes bruts (Uint8Array/ArrayBuffer), pas de CryptoKey");
    }
    
    if (!(dekBytes instanceof ArrayBuffer || dekBytes instanceof Uint8Array)) {
        throw new Error("DEK doit être un ArrayBuffer ou Uint8Array");
    }

    // Chiffrement avec la KEK
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ctFull = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        kek,
        dekBytes
    );

    const { cipher, tag } = splitCtAndTag(ctFull);

    return {
        wrappedDek: b64(cipher),
        iv: b64(iv),
        tag: b64(tag)
    };
}

/**
 * Déchiffre (unwrap) la DEK avec la KEK
 * @param {string} wrappedDekB64 - DEK chiffrée en base64
 * @param {string} ivB64 - IV en base64
 * @param {string} tagB64 - Tag GCM en base64
 * @param {CryptoKey} kek - Clé dérivée du mot de passe
 * @returns {Promise<CryptoKey>} DEK déchiffrée (NON-EXTRACTABLE)
 */
async function unwrapDEK(wrappedDekB64, ivB64, tagB64, kek) {
    const cipher = b64d(wrappedDekB64);
    const tag = b64d(tagB64);
    const iv = b64d(ivB64);

    const full = joinCtAndTag(cipher, tag);

    const dekRaw = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        kek,
        full
    );

    // Convertir en Uint8Array pour permettre l'effacement
    const dekRawArray = new Uint8Array(dekRaw);

    // Import de la DEK
    const dekKey = await crypto.subtle.importKey(
        "raw",
        dekRawArray,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
    
    // Effacer les bytes bruts immédiatement après l'import
    dekRawArray.fill(0);
    
    return dekKey;
}

/**
 * Crée un nouveau vault avec système DEK/KEK
 * @param {number} iterations - Nombre d'itérations PBKDF2
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<Object>} Données du vault créé
 */
export async function createVaultWithDEK(iterations = 600000, apiBase) {
    apiBase ??= apiBaseUrl();

    const root = document.querySelector(".modal-content");
    if (!root) throw new Error("Modal introuvable (.modal-content)");

    const vaultNameEl = root.querySelector('input[type="text"]');
    const vaultPwdEl = root.querySelector('input[type="password"]');

    const name = (vaultNameEl?.value ?? "").trim();
    const password = vaultPwdEl?.value ?? "";

    if (!password) throw new Error("Mot de passe requis");

    // Génération du salt côté client pour PBKDF2 (dérivation KEK)
    const kekSalt = crypto.getRandomValues(new Uint8Array(32));
    const kekSaltB64 = b64(kekSalt);
    
    // Dérivation de la KEK depuis le mot de passe avec PBKDF2
    const kek = await deriveKEK(password, kekSaltB64, iterations);

    // Génération de bytes bruts
    const dekBytes = generateDEK();

    // Wrapping de la DEK avec la KEK
    const { wrappedDek, iv, tag } = await wrapDEK(dekBytes, kek);

    // Effacement des bytes bruts de la mémoire
    dekBytes.fill(0);

    // Appel API
    // Envoi des paramètres PBKDF2 séparés pour la KEK
    const res = await fetch(`${apiBase}/Vault`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({
            name,
            salt: "",  // L'API génère son propre salt pour Argon2
            hashedPassword: password,
            wrappedDekB64: wrappedDek,
            dekIvB64: iv,
            dekTagB64: tag,
            kekSaltB64: kekSaltB64,
            kekIterations: iterations
        })
    });

    if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`Création vault échouée: ${res.status} ${text}`);
    }

    const json = await res.json();
    
    // Nettoyage
    if (vaultNameEl) vaultNameEl.value = "";
    if (vaultPwdEl) vaultPwdEl.value = "";

    return json;
}

/**
 * Ouvre un vault avec système DEK/KEK en utilisant les données fournies directement
 * @param {number} vaultId - ID du vault
 * @param {string} inputId - ID du champ input
 * @param {string} vaultSaltB64 - Salt en base64
 * @param {number} iterations - Itérations PBKDF2
 * @param {Object} vaultData - Données complètes du vault (optionnel)
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<boolean>} True si succès
 */
export async function openVaultWithDEKFromModal(vaultId, inputId, vaultSaltB64, iterations, vaultData, apiBase) {
    apiBase ??= apiBaseUrl();
    const el = document.getElementById(inputId);
    if (!(el instanceof HTMLInputElement)) throw new Error("Input mot de passe introuvable");

    const password = el.value ?? "";
    if (!password) return false;

    try {
        // Vérification du mot de passe
        const check = await verifyVaultPasswordServer(vaultId, password, apiBase);
        if (!check.ok) {
            el.value = "";
            return false;
        }

        let vault;
        
        // Si les données du vault sont fournies et contiennent les données DEK, les utiliser
        if (vaultData && vaultData.wrappedDekB64 && vaultData.dekIvB64 && vaultData.dekTagB64) {
            vault = vaultData;
            console.log("Utilisation des données DEK fournies directement");
        } else {
            // Sinon, récupération des données du vault via API
            console.log("Récupération des données DEK via API");
            const vaultRes = await fetch(`${apiBase}/Vault/${vaultId}`, {
                headers: authHeaders()
            });

            if (!vaultRes.ok) {
                const errorText = await vaultRes.text().catch(() => "");
                console.error("Erreur récupération vault:", vaultRes.status, vaultRes.statusText, errorText);
                throw new Error(`Impossible de récupérer le vault (HTTP ${vaultRes.status})`);
            }

            vault = await vaultRes.json();
            
            // Vérifier que les données DEK sont présentes
            if (!vault.wrappedDekB64 || !vault.dekIvB64 || !vault.dekTagB64) {
                console.error("Données DEK manquantes dans la réponse:", vault);
                throw new Error("Le vault ne contient pas les données de chiffrement nécessaires (DEK)");
            }
        }

        // Utilisation du kekSaltB64 du vault
        const kekSaltToUse = vault.kekSaltB64 || vaultSaltB64;
        const kekIterationsToUse = vault.kekIterations ?? iterations ?? DEFAULT_PBKDF2_ITERATIONS;

        // Dérivation de la KEK
        const kek = await deriveKEK(password, kekSaltToUse, kekIterationsToUse);

        // Unwrap de la DEK
        const dek = await unwrapDEK(
            vault.wrappedDekB64,
            vault.dekIvB64,
            vault.dekTagB64,
            kek,
            false
        );

        // Stockage de la DEK en mémoire
        setCurrentVault(vaultId, dek);

        el.value = "";
        return true;

    } catch (e) {
        console.error("Erreur ouverture vault avec DEK:", e);
        el.value = "";
        return false;
    }
}

/**
 * Change le mot de passe maître en re-wrappant la DEK
 * @param {number} vaultId - ID du vault
 * @param {string} oldPassword - Ancien mot de passe
 * @param {string} newPassword - Nouveau mot de passe
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
export async function changeVaultPassword(vaultId, oldPassword, newPassword, apiBase) {
    apiBase ??= apiBaseUrl();
    
    // Récupération des données actuelles du vault
    const vaultRes = await fetch(`${apiBase}/Vault/${vaultId}`, {
        headers: authHeaders()
    });

    if (!vaultRes.ok) {
        throw new Error("Impossible de récupérer les données du vault");
    }

    const vault = await vaultRes.json();
    
    // Récupération des paramètres PBKDF2 pour la KEK
    const kekSaltB64 = vault.kekSaltB64;
    const kekIterations = vault.kekIterations ?? DEFAULT_PBKDF2_ITERATIONS;
    const { wrappedDekB64, dekIvB64, dekTagB64 } = vault;

    // Dérivation de l'ANCIENNE KEK avec le salt KEK et les iterations PBKDF2
    const oldKek = await deriveKEK(oldPassword, kekSaltB64, kekIterations);

    // Déchiffrer la DEK en BYTES BRUTS
    // Cela permet de re-wrapper sans avoir besoin d'une clé extractable
    let dekRawBytes;
    try {
        const cipher = b64d(wrappedDekB64);
        const tag = b64d(dekTagB64);
        const iv = b64d(dekIvB64);
        const full = joinCtAndTag(cipher, tag);

        dekRawBytes = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            oldKek,
            full
        );
    } catch (e) {
        return { ok: false, error: "Ancien mot de passe incorrect (échec du déchiffrement local de la clé)" };
    }

    // Convertir en Uint8Array pour permettre l'effacement
    const dekBytesArray = new Uint8Array(dekRawBytes);

    // Dérivation de la nouvelle KEK avec les mêmes paramètres PBKDF2
    const newKek = await deriveKEK(newPassword, kekSaltB64, kekIterations);

    // Re-wrapping de la DEK
    const { wrappedDek: newWrappedDek, iv: newIv, tag: newTag } = await wrapDEK(dekBytesArray, newKek);

    // Préparation des données à envoyer à l'API
    const requestBody = {
        OldPassword: oldPassword,
        NewPassword: newPassword,
        WrappedDekB64: newWrappedDek,
        DekIvB64: newIv,
        DekTagB64: newTag,
        KekSaltB64: kekSaltB64,
        KekIterations: kekIterations
    };

    const updateRes = await fetch(`${apiBase}/Vault/${vaultId}/change-password`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(requestBody)
    });

    if (!updateRes.ok) {
        const text = await updateRes.text().catch(() => "");
        console.error("Erreur réponse API:", updateRes.status, text);
        
        // Effacer les bytes même en cas d'erreur
        dekBytesArray.fill(0);
        
        // Essayer de parser la réponse JSON
        try {
            const errorData = JSON.parse(text);
            console.error("Détails erreur:", errorData);
            return { ok: false, error: errorData.error || `Erreur API: ${updateRes.status}` };
        } catch {
            return { ok: false, error: `Erreur API: ${updateRes.status} ${text}` };
        }
    }

    // Mise à jour de la session en mémoire avec la DEK non-extractable
    // Les bytes bruts (dekBytesArray) sont réimportés
    const nonExtractableDek = await crypto.subtle.importKey(
        "raw",
        dekBytesArray,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
    
    // Effacer les bytes bruts immédiatement après l'import
    dekBytesArray.fill(0);
    
    setCurrentVault(vaultId, nonExtractableDek);

    return { ok: true };
}

/**
 * Change le mot de passe depuis une modale
 * @param {number} vaultId - ID du vault
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<boolean>} True si succès
 */
export async function changeVaultPasswordFromModal(vaultId, apiBase) {
    apiBase ??= apiBaseUrl();

    const oldPwdEl = document.getElementById("old-password");
    const newPwdEl = document.getElementById("new-password");
    const confirmPwdEl = document.getElementById("confirm-password");

    if (!(oldPwdEl instanceof HTMLInputElement) ||
        !(newPwdEl instanceof HTMLInputElement) ||
        !(confirmPwdEl instanceof HTMLInputElement)) {
        throw new Error("Champs de mot de passe introuvables");
    }

    const oldPassword = oldPwdEl.value;
    const newPassword = newPwdEl.value;
    const confirmPassword = confirmPwdEl.value;

    if (newPassword !== confirmPassword) {
        alert("Les nouveaux mots de passe ne correspondent pas");
        return false;
    }

    if (newPassword.length < 8) {
        alert("Le nouveau mot de passe doit contenir au moins 8 caractères");
        return false;
    }

    const result = await changeVaultPassword(vaultId, oldPassword, newPassword, apiBase);

    // Nettoyage
    oldPwdEl.value = "";
    newPwdEl.value = "";
    confirmPwdEl.value = "";

    if (!result.ok) {
        alert(result.error || "Erreur lors du changement de mot de passe");
        return false;
    }

    alert("Mot de passe changé avec succès !");
    return true;
}