// ==============================
// GESTION DES ENTRÉES - Chiffrement, Création et Affichage
// ==============================

import { b64, b64d, asU8 } from './crypto-utils.js';
import { authHeaders } from './crypto-auth.js';
import { currentVault, touchVault } from './crypto-vault-session.js';
import { encFieldWithVaultKey, decFieldWithVaultKey, makeCypherObj } from './crypto-encryption.js';
import { storePassword, maskPassword } from './crypto-password-tools.js';
import { apiBaseUrl } from "./crypto-config.js";

/**
 * Chiffre une entrée pour un vault ouvert (ancien flux)
 * Récupère les valeurs depuis les champs DOM name, pwd, url, notes
 * @returns {Promise<Object>} Objet contenant tous les champs chiffrés en base64
 */
export async function encryptEntryForOpenVault() {
    if (!currentVault.key) throw new Error("Vault non ouvert");
    const get = id => document.getElementById(id)?.value ?? "";
    const name = get("name"), pwd = get("pwd"), url = get("url"), notes = get("notes");
    const ns = `vault:${currentVault.id}`;

    const p = await encFieldWithVaultKey(pwd, `${ns}|field:password`);
    const n = await encFieldWithVaultKey(name, `${ns}|field:name`);
    const u = await encFieldWithVaultKey(url, `${ns}|field:url`);
    const no = await encFieldWithVaultKey(notes, `${ns}|field:notes`);

    return {
        cipherPasswordB64: b64(p.cipher), tagPasswordB64: b64(p.tag), ivPasswordB64: b64(p.iv),
        cipherNameB64: b64(n.cipher), tagNameB64: b64(n.tag), ivNameB64: b64(n.iv),
        cipherUrlB64: b64(u.cipher), tagUrlB64: b64(u.tag), ivUrlB64: b64(u.iv),
        cipherNotesB64: b64(no.cipher), tagNotesB64: b64(no.tag), ivNotesB64: b64(no.iv)
    };
}

/**
 * Crée une nouvelle entrée depuis une modale avec chiffrement côté client
 * @param {number} vaultId - ID du vault
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<boolean>} True si création réussie
 */
export async function createEntryFromModal(vaultId, apiBase) {
    apiBase ??= apiBaseUrl();
    
    // Récupération des champs DOM
    const userEl = document.getElementById("ce-username");
    const pwdEl = document.getElementById("ce-password");
    const urlEl = document.getElementById("ce-url");
    const notesEl = document.getElementById("ce-notes");

    if (!(userEl instanceof HTMLInputElement)) throw new Error("#ce-username introuvable");
    if (!(pwdEl instanceof HTMLInputElement)) throw new Error("#ce-password introuvable");
    if (!(urlEl instanceof HTMLInputElement)) throw new Error("#ce-url introuvable");
    if (!(notesEl instanceof HTMLTextAreaElement)) throw new Error("#ce-notes introuvable");

    const username = userEl.value ?? "";
    const password = pwdEl.value ?? "";
    const url = urlEl.value ?? "";
    const notes = notesEl.value ?? "";

    // Vérifie que la clé de vault est bien en RAM
    if (!currentVault?.key || currentVault.id == null) {
        throw new Error("Vault non ouvert : clé AES introuvable côté client.");
    }

    // Chiffrement côté client (AAD lie chaque champ au vault + type)
    const ns = `vault:${vaultId}`;
    const userNameCypherObj = await makeCypherObj(username, `${ns}|field:username`);
    const passwordCypherObj = await makeCypherObj(password, `${ns}|field:password`);
    const urlCypherObj = await makeCypherObj(url, `${ns}|field:url`);
    const noteCypherObj = await makeCypherObj(notes, `${ns}|field:notes`);


    const nomCypherObj = await makeCypherObj(username, `${ns}|field:name`);

    // Payload conforme à PostEntryObj
    const payload = {
        vaultId,
        userNameCypherObj,
        passwordCypherObj,
        urlCypherObj,
        noteCypherObj,
        nomCypherObj
    };

    // Appel API    
    const res = await fetch(`${apiBase}/Entry`, {
        method: "POST",
        headers: {"Content-Type": "application/json", ...authHeaders()},
        body: JSON.stringify(payload)
    });

    if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`Erreur API Entry: ${res.status} ${text}`);
    }

    // Nettoyage UI
    userEl.value = "";
    pwdEl.value = "";
    urlEl.value = "";
    notesEl.value = "";

    // touche le timer d'auto-lock
    touchVault();

    return true;
}

/**
 * Met à jour une entrée existante depuis une modale avec rechiffrement
 * @param {number} EntryId - ID de l'entrée à modifier
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<boolean>} True si modification réussie
 */
export async function updateEntryFromModal(EntryId, apiBase) {
    apiBase ??= apiBaseUrl();

    // Récupération des champs DOM
    const userEl = document.getElementById("ce-username");
    const pwdEl = document.getElementById("ce-password");
    const urlEl = document.getElementById("ce-url");
    const notesEl = document.getElementById("ce-notes");

    if (!(userEl instanceof HTMLInputElement)) throw new Error("#ce-username introuvable");
    if (!(pwdEl instanceof HTMLInputElement)) throw new Error("#ce-password introuvable");
    if (!(urlEl instanceof HTMLInputElement)) throw new Error("#ce-url introuvable");
    if (!(notesEl instanceof HTMLTextAreaElement)) throw new Error("#ce-notes introuvable");

    const username = userEl.value ?? "";
    const password = pwdEl.value ?? "";
    const url = urlEl.value ?? "";
    const notes = notesEl.value ?? "";

    // Vérifie que la clé de vault est bien en RAM
    if (!currentVault?.key || currentVault.id == null) {
        throw new Error("Vault non ouvert : clé AES introuvable côté client.");
    }

    // Chiffrement côté client (AAD lie chaque champ au vault + type)
    //const ns = `vault:${currentVault.id}|entry:${EntryId}`;
    const ns = `vault:${currentVault.id}`;
    const userNameCypherObj = await makeCypherObj(username, `${ns}|field:username`);
    const passwordCypherObj = await makeCypherObj(password, `${ns}|field:password`);
    const urlCypherObj = await makeCypherObj(url, `${ns}|field:url`);
    const noteCypherObj = await makeCypherObj(notes, `${ns}|field:notes`);

    const nomCypherObj = await makeCypherObj(username, `${ns}|field:name`);

    // Payload conforme à PostEntryObj
    const payload = {
        EntryId,
        userNameCypherObj,
        passwordCypherObj,
        urlCypherObj,
        noteCypherObj,
        nomCypherObj
    };

    // Appel API    
    const res = await fetch(`${apiBase}/Entry`, {
        method: "PUT",
        headers: {"Content-Type": "application/json", ...authHeaders()},
        body: JSON.stringify(payload)
    });

    if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`Erreur API Entry: ${res.status} ${text}`);
    }

    // Nettoyage UI
    userEl.value = "";
    pwdEl.value = "";
    urlEl.value = "";
    notesEl.value = "";

    // touche le timer d'auto-lock
    touchVault();

    return true;
}

/**
 * Remplit la modale de modification avec les données déchiffrées d'une entrée
 * @param {number} vaultId - ID du vault
 * @param {Object} entry - Objet entrée avec champs chiffrés
 * @returns {Promise<void>}
 */
export async function fillUpdateModal(vaultId, entry) {
    if (!currentVault?.key) throw new Error("Vault non ouvert (clé AES absente).");

    const ns = `vault:${vaultId}`;
    const setVal = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.value = value ?? "";
    };

    const dec = async (obj, aad) => {
        if (!obj) return "";
        const c  = asU8(obj.cypher ?? obj.baseCypher);
        const t  = asU8(obj.cypherTag ?? obj.baseCypherTag);
        const iv = asU8(obj.cypherIv ?? obj.baseCypherIv);
        return await decFieldWithVaultKey(c, t, iv, aad);
    };

    setVal("ce-username", await dec(entry.userNameCypher, `${ns}|field:username`));

    const clearPwd = await dec(entry.passwordCypher, `${ns}|field:password`);
    setVal("ce-password", clearPwd);

    setVal("ce-url",      await dec(entry.urlCypher,      `${ns}|field:url`));
    setVal("ce-notes",    await dec(entry.noteCypher,     `${ns}|field:notes`));

    touchVault();
}

/**
 * Déchiffre une entrée de vault (ancien flux)
 * @param {Object} record - Objet contenant les champs chiffrés en base64
 * @returns {Promise<Object>} Objet avec champs déchiffrés (password, name, url, notes)
 */
export async function decryptVaultEntry(record) {
    const ns = `vault:${currentVault.id}`;
    const out = {};
    out.password = await decFieldWithVaultKey(b64d(record.cipherPasswordB64), b64d(record.tagPasswordB64), b64d(record.ivPasswordB64), `${ns}|field:password`);
    out.name = await decFieldWithVaultKey(b64d(record.cipherNameB64), b64d(record.tagNameB64), b64d(record.ivNameB64), `${ns}|field:name`);
    out.url = await decFieldWithVaultKey(b64d(record.cipherUrlB64), b64d(record.tagUrlB64), b64d(record.ivUrlB64), `${ns}|field:url`);
    out.notes = await decFieldWithVaultKey(b64d(record.cipherNotesB64), b64d(record.tagNotesB64), b64d(record.ivNotesB64), `${ns}|field:notes`);
    return out;
}

/**
 * Affiche une liste d'entrées déchiffrées dans le DOM
 * @param {Array} records - Tableau d'objets entrées chiffrées
 * @returns {Promise<void>}
 */
export async function renderVaultEntries(records) {
    const list = document.getElementById("vault-list");
    if (!list) return;
    list.textContent = "";

    if (!records || records.length === 0) {
        const em = document.createElement("em");
        em.textContent = "Aucune entrée.";
        list.appendChild(em);
        return;
    }

    for (const rec of records) {
        const dec = await decryptVaultEntry(rec);
        const wrap = document.createElement("div");
        wrap.className = "entry";
        wrap.style.marginBottom = "1rem";

        const name = document.createElement("strong");
        name.textContent = dec.name;

        const pwd = document.createElement("div");
        pwd.textContent = `Mot de passe : ${dec.password}`;

        const url = document.createElement("div");
        url.textContent = `URL : ${dec.url}`;

        const notes = document.createElement("div");
        notes.textContent = `Notes : ${dec.notes}`;

        wrap.appendChild(name);
        wrap.appendChild(document.createElement("br"));
        wrap.appendChild(pwd);
        wrap.appendChild(url);
        wrap.appendChild(notes);
        list.appendChild(wrap);
    }

    touchVault();
}

/**
 * Déchiffre une entrée et affiche ses champs dans des éléments DOM spécifiques
 * Le mot de passe est masqué par défaut et stocké en RAM
 * @param {number} vaultId - ID du vault
 * @param {Object} entry - Objet entrée avec champs chiffrés
 * @param {Object} ids - Objet mappant les champs aux IDs DOM {nameId, usernameId, passwordId, urlId, notesId}
 * @returns {Promise<void>}
 */
export async function decryptEntryToDom(vaultId, entry, ids) {

    if (!currentVault?.key) throw new Error("Vault non ouvert (clé AES absente).");

    if (String(currentVault.id) !== String(vaultId)) {
        throw new Error(`Vault ouvert = ${currentVault.id}, mais on tente de déchiffrer vaultId = ${vaultId}`);
    }

    if (!currentVault?.key) {
        console.error("Vault non ouvert ou clé absente !");
        throw new Error("Vault non ouvert (clé AES absente).");
    }

    const ns = `vault:${vaultId}`;
    const setText = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value ?? "";
    };

    const dec = async (obj, aad) => {
        if (!obj) return "";
        const c  = asU8(obj.cypher ?? obj.baseCypher);
        const t  = asU8(obj.cypherTag ?? obj.baseCypherTag);
        const iv = asU8(obj.cypherIv ?? obj.baseCypherIv);
        return await decFieldWithVaultKey(c, t, iv, aad);
    };

    // tes propriétés sont en camelCase d'après ton log
    setText(ids.nameId,     await dec(entry.nomCypher,      `${ns}|field:name`));
    setText(ids.usernameId, await dec(entry.userNameCypher, `${ns}|field:username`));
    const clearPwd = await dec(entry.passwordCypher, `${ns}|field:password`);

    // on garde le clair en RAM JS (pas dans le DOM)
    storePassword(ids.passwordId, clearPwd);

    // affichage masqué par défaut
    setText(ids.passwordId, maskPassword(clearPwd));    
    setText(ids.urlId,      await dec(entry.urlCypher,      `${ns}|field:url`));
    setText(ids.notesId,    await dec(entry.noteCypher,     `${ns}|field:notes`));

    touchVault();
}

/**
 * Récupère le mot de passe chiffré depuis l'API et le déchiffre côté client
 * TOUT se passe côté client : le mot de passe clair ne transite JAMAIS côté serveur C#
 * @param {number} vaultId - ID du vault
 * @param {number} entryId - ID de l'entrée
 * @param {string} passwordId - ID de l'élément DOM où afficher le mot de passe
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<boolean>} True si réussi
 */
export async function fetchAndDecryptPassword(vaultId, entryId, passwordId, apiBase = "https://localhost:7115") {
    if (!currentVault?.key) {
        throw new Error("Vault non ouvert (clé AES absente).");
    }

    if (String(currentVault.id) !== String(vaultId)) {
        throw new Error(`Vault ouvert = ${currentVault.id}, mais on tente de déchiffrer vaultId = ${vaultId}`);
    }

    try {
        // Appel API pour récupérer le mot de passe chiffré
        const res = await fetch(`${apiBase}/Entry/Password/${entryId}`, {
            method: "GET",
            headers: { ...authHeaders() }
        });

        if (!res.ok) {
            const text = await res.text().catch(() => "");
            throw new Error(`Erreur API Password: ${res.status} ${text}`);
        }

        // Récupération de l'objet CypherData
        const passwordCypher = await res.json();

        if (!passwordCypher) {
            throw new Error("Mot de passe non trouvé");
        }

        // Déchiffrement côté client
        const ns = `vault:${vaultId}`;
        const c  = asU8(passwordCypher.cypher ?? passwordCypher.baseCypher);
        const t  = asU8(passwordCypher.cypherTag ?? passwordCypher.baseCypherTag);
        const iv = asU8(passwordCypher.cypherIv ?? passwordCypher.baseCypherIv);
        
        const clearPwd = await decFieldWithVaultKey(c, t, iv, `${ns}|field:password`);

        // Stockage en RAM JS (pas dans le DOM)
        storePassword(passwordId, clearPwd);

        // Affichage masqué par défaut
        const el = document.getElementById(passwordId);
        if (el) {
            el.textContent = maskPassword(clearPwd);
        }

        touchVault();
        return true;
    } catch (error) {
        console.error("Erreur lors de la récupération du mot de passe:", error);
        throw error;
    }
}
