// ==============================
// GESTION DE LA CLÉ MAGIQUE (DEK/KEK)
// ==============================

import { enc, b64, b64d } from './crypto-utils.js';
import { authHeaders } from './crypto-auth.js';
import { setCurrentVault } from './crypto-vault-session.js';
import { splitCtAndTag, joinCtAndTag } from './crypto-encryption.js';
import { verifyVaultPasswordServer } from './crypto-vault-management.js';

/**
 * Génère une nouvelle DEK (Data Encryption Key) aléatoire
 * @returns {Promise<CryptoKey>} Clé AES-GCM 256 bits
 */
async function generateDEK() {
    return await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,  // extractable pour pouvoir la wrapper
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
export async function createVaultWithDEK(iterations = 600000, apiBase = "https://localhost:7115") {
    const root = document.querySelector(".modal-content");
    if (!root) throw new Error("Modal introuvable (.modal-content)");

    const vaultNameEl = root.querySelector('input[type="text"]');
    const vaultPwdEl = root.querySelector('input[type="password"]');

    const name = (vaultNameEl?.value ?? "").trim();
    const password = vaultPwdEl?.value ?? "";

    if (!password) throw new Error("Mot de passe requis");

    // 1️⃣ Génération du salt côté client
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const saltB64 = b64(salt);

    // 2️⃣ Dérivation de la KEK depuis le mot de passe
    const pwKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const kek = await crypto.subtle.deriveKey(
        { name: "PBKDF2", hash: "SHA-256", salt, iterations },
        pwKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

    // 3️⃣ Génération de la DEK (clé magique)
    const dek = await generateDEK();

    // 4️⃣ Wrapping de la DEK avec la KEK
    const { wrappedDek, iv, tag } = await wrapDEK(dek, kek);

    // 5️⃣ Appel API
    const res = await fetch(`${apiBase}/Vault`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({
            name,
            salt: saltB64,
            hashedPassword: password,
            NbIteration: iterations,
            wrappedDekB64: wrappedDek,  // ⭐ Envoi de la DEK chiffrée
            dekIvB64: iv,
            dekTagB64: tag
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
 * Ouvre un vault avec système DEK/KEK
 * AMÉLIORE openVaultFromModal
 * @param {number} vaultId - ID du vault
 * @param {string} inputId - ID du champ input
 * @param {string} vaultSaltB64 - Salt en base64
 * @param {number} iterations - Itérations PBKDF2
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<boolean>} True si succès
 */
export async function openVaultWithDEKFromModal(vaultId, inputId, vaultSaltB64, iterations, apiBase = "https://localhost:7115") {
    const el = document.getElementById(inputId);
    if (!(el instanceof HTMLInputElement)) throw new Error("Input mot de passe introuvable");

    const password = el.value ?? "";
    if (!password) return false;

    try {
        // 1️⃣ Vérification du mot de passe
        const check = await verifyVaultPasswordServer(vaultId, password, apiBase);
        if (!check.ok) {
            el.value = "";
            return false;
        }

        // 2️⃣ Récupération des données du vault (avec DEK wrappée)
        const vaultRes = await fetch(`${apiBase}/Vault/${vaultId}`, {
            headers: authHeaders()
        });

        if (!vaultRes.ok) throw new Error("Impossible de récupérer le vault");

        const vault = await vaultRes.json();

        // 3️⃣ Dérivation de la KEK
        const pwKey = await crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        const kek = await crypto.subtle.deriveKey(
            { name: "PBKDF2", hash: "SHA-256", salt: b64d(vaultSaltB64), iterations },
            pwKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );

        // 4️⃣ Unwrap de la DEK
        const dek = await unwrapDEK(
            vault.wrappedDekB64,
            vault.dekIvB64,
            vault.dekTagB64,
            kek
        );

        // 5️⃣ Stockage de la DEK en mémoire (pas la KEK !)
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
export async function changeVaultPassword(vaultId, oldPassword, newPassword, apiBase = "https://localhost:7115") {

    // 1️⃣ Récupération des données du vault
    const vaultRes = await fetch(`${apiBase}/Vault/${vaultId}`, {
        headers: authHeaders()
    });

    if (!vaultRes.ok) {
        throw new Error("Impossible de récupérer les données du vault");
    }

    const vault = await vaultRes.json();
    const { salt, nbIteration, wrappedDekB64, dekIvB64, dekTagB64 } = vault;

    // 2️⃣ Dérivation de l'ANCIENNE KEK
    const oldPwKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(oldPassword),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const oldKek = await crypto.subtle.deriveKey(
        { name: "PBKDF2", hash: "SHA-256", salt: b64d(salt), iterations: nbIteration },
        oldPwKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

    // 3️⃣ Unwrap de la DEK avec l'ancienne KEK
    let dek;
    try {
        dek = await unwrapDEK(wrappedDekB64, dekIvB64, dekTagB64, oldKek);
    } catch (e) {
        return { ok: false, error: "Ancien mot de passe incorrect" };
    }

    // 4️⃣ Dérivation de la NOUVELLE KEK
    const newPwKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(newPassword),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const newKek = await crypto.subtle.deriveKey(
        { name: "PBKDF2", hash: "SHA-256", salt: b64d(salt), iterations: nbIteration },
        newPwKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

    // 5️⃣ Re-wrapping de la DEK avec la nouvelle KEK
    const { wrappedDek: newWrappedDek, iv: newIv, tag: newTag } = await wrapDEK(dek, newKek);

    // 6️⃣ Envoi au serveur
    const updateRes = await fetch(`${apiBase}/Vault/${vaultId}/change-password`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({
            oldPassword,
            newPassword,
            wrappedDekB64: newWrappedDek,
            dekIvB64: newIv,
            dekTagB64: newTag
        })
    });

    if (!updateRes.ok) {
        const text = await updateRes.text().catch(() => "");
        return { ok: false, error: `Erreur API: ${updateRes.status} ${text}` };
    }

    // 7️⃣ Mise à jour de la session en mémoire
    setCurrentVault(vaultId, dek);

    return { ok: true };
}

/**
 * Change le mot de passe depuis une modale
 * @param {number} vaultId - ID du vault
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<boolean>} True si succès
 */
export async function changeVaultPasswordFromModal(vaultId, apiBase = "https://localhost:7115") {
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

