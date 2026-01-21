// ==============================
// GESTION DES VAULTS - Création, Ouverture et Modification
// ==============================

import { enc, b64d } from './crypto-utils.js';
import { authHeaders } from './crypto-auth.js';
import { setCurrentVault, armAutoLock } from './crypto-vault-session.js';
import { apiBaseUrl } from "./crypto-config.js";

/**
 * Ouvre un vault avec vérification du mot de passe et dérivation de clé
 * @param {number} vaultId - ID du vault
 * @param {string} password - Mot de passe maître
 * @param {number} autoLockMs - Délai d'auto-lock en ms (défaut: 300000)
 * @returns {Promise<{ok: boolean, error?: string}>} Résultat de l'ouverture
 */
export async function openVault(vaultId, password, autoLockMs = 300000) {
    const p = await (await fetch(`/api/vaults/${vaultId}/params`, {headers: authHeaders()})).json();
    const check = await (await fetch(`/api/vaults/${vaultId}/check`, {
        method: "POST",
        headers: {"Content-Type": "application/json", ...authHeaders()},
        body: JSON.stringify({password})
    })).json();
    if (!check.ok) return {ok: false, error: "Mot de passe maître invalide."};

    const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey(
        {name: "PBKDF2", hash: "SHA-256", salt: b64d(p.vaultSaltB64), iterations: p.iterations},
        pwKey,
        {name: "AES-GCM", length: 256},
        false,
        ["encrypt", "decrypt"]
    );

    setCurrentVault(vaultId, aesKey);
    armAutoLock(autoLockMs || 300000);
    return {ok: true};
}

/**
 * Ouvre un vault en récupérant le mot de passe depuis un champ input
 * @param {number} vaultId - ID du vault
 * @param {string} inputId - ID de l'élément input contenant le mot de passe
 * @param {number} autoLockMs - Délai d'auto-lock en ms
 * @returns {Promise<{ok: boolean, error?: string}>} Résultat de l'ouverture
 */
export async function openVaultFromInput(vaultId, inputId, autoLockMs = 300000) {
    const pwd = document.getElementById(inputId)?.value ?? "";
    const res = await openVault(vaultId, pwd, autoLockMs);
    const el = document.getElementById(inputId);
    if (el) el.value = "";
    return res;
}

/**
 * Vérifie le mot de passe maître d'un vault auprès du serveur
 * N'ouvre pas le vault, uniquement validation
 * @param {number} vaultId - ID du vault
 * @param {string} password - Mot de passe à vérifier
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<{ok: boolean, error?: string}>} Résultat de la vérification
 */
export async function verifyVaultPasswordServer(vaultId, password, apiBase) {
    apiBase ??= apiBaseUrl();
    
    if (!vaultId || !password) return {ok: false, error: "Champs manquants"};

    try {
        const res = await fetch(`${apiBase}/Vault/${vaultId}/check`, {
            method: "POST",
            headers: {"Content-Type": "application/json", ...authHeaders()},
            body: JSON.stringify({passwordClear: password})
        });

        if (!res.ok) {
            const text = await res.text().catch(() => "");
            console.error("Erreur HTTP check:", res.status, res.statusText, text);
            return {ok: false, error: `HTTP ${res.status}`};
        }

        const json = await res.json(); // { ok: true/false }
        return json && json.ok ? {ok: true} : {ok: false, error: "Mot de passe incorrect"};
    } catch (e) {
        console.error("Erreur JS verifyVaultPasswordServer:", e);
        return {ok: false, error: e.message};
    }
}

/**
 * Dérive et stocke la clé AES en RAM à partir du salt et iterations
 * N'effectue pas de vérification serveur
 * @param {number} vaultId - ID du vault
 * @param {string} password - Mot de passe maître
 * @param {string} vaultSaltB64 - Salt en base64
 * @param {number} iterations - Nombre d'itérations PBKDF2
 * @returns {Promise<boolean>} True si succès
 */
export async function armVaultSession(vaultId, password, vaultSaltB64, iterations) {
    if (!vaultId || !password || !vaultSaltB64 || !iterations) {
        throw new Error("Paramètres manquants pour armer la session du coffre.");
    }

    const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey(
        {name: "PBKDF2", hash: "SHA-256", salt: b64d(vaultSaltB64), iterations},
        pwKey,
        {name: "AES-GCM", length: 256},
        false,
        ["encrypt", "decrypt"]
    );

    setCurrentVault(vaultId, aesKey);
    return true;
}

/**
 * Vérifie le mot de passe auprès du serveur puis arme la session locale
 * Combine verifyVaultPasswordServer et armVaultSession
 * @param {number} vaultId - ID du vault
 * @param {string} password - Mot de passe maître
 * @param {string} vaultSaltB64 - Salt en base64
 * @param {number} iterations - Nombre d'itérations PBKDF2
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<{ok: boolean, error?: string}>} Résultat de l'opération
 */
export async function openVaultAfterVerify(vaultId, password, vaultSaltB64, iterations, apiBase) {
    apiBase ??= apiBaseUrl();
    
    const check = await verifyVaultPasswordServer(vaultId, password, apiBase);
    if (!check.ok) return check;
    await armVaultSession(vaultId, password, vaultSaltB64, iterations);
    return {ok: true};
}

/**
 * Ouvre un vault depuis une modale avec vérification serveur
 * @param {number} vaultId - ID du vault
 * @param {string} inputId - ID du champ input contenant le mot de passe
 * @param {string} vaultSaltB64 - Salt en base64
 * @param {number} iterations - Nombre d'itérations PBKDF2
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<boolean>} True si ouverture réussie
 */
export async function openVaultFromModal(vaultId, inputId, vaultSaltB64, iterations, apiBase) {
    apiBase ??= apiBaseUrl();
    
    const el = document.getElementById(inputId);
    if (!(el instanceof HTMLInputElement)) throw new Error("Input mot de passe introuvable");

    const password = el.value ?? "";
    if (!password) return false;

    // 1) vérif serveur
    const check = await verifyVaultPasswordServer(vaultId, password, apiBase);
    if (!check.ok) {
        el.value = "";
        return false;
    }

    // 2) dérive et garde la clé AES en RAM JS
    await armVaultSession(vaultId, password, vaultSaltB64, iterations);

    // 3) hygiène
    el.value = "";
    return true;
}

/**
 * Crée un verifier de vault à partir d'un champ input (ancien flux)
 * @param {string} inputId - ID du champ input contenant le mot de passe
 * @param {number} iterations - Nombre d'itérations PBKDF2 (défaut: 600000)
 * @returns {Promise<Object>} Données du vault créé
 */
export async function createVaultVerifierFromInput(inputId, iterations = 600000) {
    const password = document.getElementById(inputId)?.value ?? "";
    const res = await fetch("/api/vaults", {
        method: "POST",
        headers: {"Content-Type": "application/json", ...authHeaders()},
        body: JSON.stringify({password, iterations})
    });
    if (!res.ok) throw new Error("Création du vault échouée");
    return await res.json();
}

/**
 * Crée un nouveau vault depuis une modale
 * Le mot de passe est envoyé au serveur pour génération du hash
 * @param {number} iterations - Nombre d'itérations PBKDF2
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<Object>} Données du vault créé
 */
export async function createVaultFromModal(iterations = 600000, apiBase) {
    apiBase ??= apiBaseUrl();
    
    const root = document.querySelector(".modal-content");
    if (!root) throw new Error("Modal introuvable (.modal-content)");

    const vaultNameEl = root.querySelector('input[type="text"]');
    const vaultPwdEl = root.querySelector('input[type="password"]');

    const name = (vaultNameEl?.value ?? "").trim();
    const password = vaultPwdEl?.value ?? "";

    let res;
    try {
        res = await fetch(`${apiBase}/Vault`, {
            method: "POST",
            headers: {"Content-Type": "application/json", ...authHeaders()},
            body: JSON.stringify({
                name,
                salt: "",
                hashedPassword: password,
                NbIteration: 600000
            })
        });
    } catch (e) {
        console.error("Fetch network error:", e);
        throw e;
    }

    if (!res.ok) {
        const text = await res.text().catch(() => "");
        console.error("Fetch HTTP error:", res.status, res.statusText, text);
        throw new Error(`Création du vault échouée: ${res.status} ${res.statusText}`);
    }

    const json = await res.json();

    // Vide les champs
    if (vaultNameEl) vaultNameEl.value = "";
    if (vaultPwdEl) vaultPwdEl.value = "";

    return json;
}

/**
 * Met à jour les informations d'un vault depuis une modale
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<Object>} Données du vault mis à jour
 */
export async function updateVaultFromModal(apiBase) {
    apiBase ??= apiBaseUrl();

    const root = document.querySelector(".modal-content");
    if (!root) throw new Error("Modal introuvable (.modal-content)");

    const vaultNameEl = root.querySelector('input[type="text"]');
    const name = (vaultNameEl?.value ?? "").trim();

    let res;
    try {
        res = await fetch(`${apiBase}/Vault`, {
            method: "PUT",
            headers: {"Content-Type": "application/json", ...authHeaders()},
            body: JSON.stringify({
                name,
            })
        });
    } catch (e) {
        console.error("Fetch network error:", e);
        throw e;
    }

    if (!res.ok) {
        const text = await res.text().catch(() => "");
        console.error("Fetch HTTP error:", res.status, res.statusText, text);
        throw new Error(`Création du vault échouée: ${res.status} ${res.statusText}`);
    }

    const json = await res.json();

    // Vide les champs
    if (vaultNameEl) vaultNameEl.value = "";

    return json;
}