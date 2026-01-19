// ==============================
// GESTION DE LA CLÉ MAGIQUE (DEK/KEK)
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
 * @param {boolean} extractable - Si la clé doit être extractable (false par défaut pour sécurité)
 * @returns {Promise<CryptoKey>} KEK dérivée
 */
async function deriveKEK(password, kekSaltB64, iterations = DEFAULT_PBKDF2_ITERATIONS, extractable = false) {
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
        extractable,
        ["encrypt", "decrypt"]
    );
}

/**
 * Génère une nouvelle DEK (Data Encryption Key) aléatoire
 * @param {boolean} extractable - Si la clé doit être extractable (true pour le wrapping initial)
 * @returns {Promise<CryptoKey>} Clé AES-GCM 256 bits
 */
async function generateDEK(extractable = true) {
    return await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        extractable,  // extractable UNIQUEMENT lors de la création pour le wrapping initial
        ["encrypt", "decrypt"]
    );
}

/**
 * Chiffre (wrap) la DEK avec la KEK (clé dérivée du mot de passe)
 * @param {CryptoKey} dek - La DEK à protéger
 * @param {CryptoKey} kek - La clé dérivée du mot de passe
 * @returns {Promise<{wrappedDek: string, iv: string, tag: string}>}
 */
async function wrapDEK(dek, kek) {
    // Export de la DEK en raw
    const dekRaw = await crypto.subtle.exportKey("raw", dek);

    // Chiffrement avec la KEK
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ctFull = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        kek,
        dekRaw
    );

    const { cipher, tag } = splitCtAndTag(ctFull);

    return {
        wrappedDek:  b64(cipher),
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
 * @returns {Promise<CryptoKey>} DEK déchiffrée
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

    // Import de la DEK
    return await crypto.subtle.importKey(
        "raw",
        dekRaw,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

/**
 * Crée un nouveau vault avec système DEK/KEK
 * REMPLACE createVaultFromModal
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

    // Génération de la DEK (clé magique)
    const dek = await generateDEK();

    // Wrapping de la DEK avec la KEK
    const { wrappedDek, iv, tag } = await wrapDEK(dek, kek);

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
            kekSaltB64: kekSaltB64,      // Salt pour PBKDF2
            kekIterations: iterations     // Iterations pour PBKDF2
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

        // Stockage de la DEK en mémoire (pas la KEK !)
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

    // Unwrap de la DEK avec l'ancienne KEK
    let dek;
    try {
        dek = await unwrapDEK(wrappedDekB64, dekIvB64, dekTagB64, oldKek);
    } catch (e) {
        return { ok: false, error: "Ancien mot de passe incorrect (échec du déchiffrement local de la clé)" };
    }

    // Dérivation de la NOUVELLE KEK avec les mêmes paramètres PBKDF2
    const newKek = await deriveKEK(newPassword, kekSaltB64, kekIterations);

    // Re-wrapping de la DEK avec la nouvelle KEK
    const { wrappedDek: newWrappedDek, iv: newIv, tag: newTag } = await wrapDEK(dek, newKek);

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

    // Envoi au serveur
    const updateRes = await fetch(`${apiBase}/Vault/${vaultId}/change-password`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(requestBody)
    });

    if (!updateRes.ok) {
        const text = await updateRes.text().catch(() => "");
        console.error("Erreur réponse API:", updateRes.status, text);
        
        // Essayer de parser la réponse JSON si possible
        try {
            const errorData = JSON.parse(text);
            console.error("Détails erreur:", errorData);
            return { ok: false, error: errorData.error || `Erreur API: ${updateRes.status}` };
        } catch {
            return { ok: false, error: `Erreur API: ${updateRes.status} ${text}` };
        }
    }

    // Mise à jour de la session en mémoire avec une DEK
    // On ré-unwrap la DEK avec la nouvelle KEK
    const nonExtractableDek = await unwrapDEK(newWrappedDek, newIv, newTag, newKek, false);
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

