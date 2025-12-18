// ==============================
// UTILITAIRES DE BASE - Encodage et conversion
// ==============================

/**
 * Encodeur de texte pour convertir des chaînes en Uint8Array
 */
const enc = new TextEncoder();

/**
 * Convertit un ArrayBuffer en chaîne base64
 * @param {ArrayBuffer} a - Le buffer à convertir
 * @returns {string} La chaîne encodée en base64
 */
const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));

/**
 * Convertit une chaîne base64 en Uint8Array
 * @param {string} s - La chaîne base64 à décoder
 * @returns {Uint8Array} Les données décodées
 */
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

/**
 * Taille du tag d'authentification GCM en octets
 */
const TAG_BYTES = 16;

/**
 * Convertit différents types de données en Uint8Array
 * Accepte Uint8Array, Array, ou string (base64)
 * @param {*} x - Données à convertir
 * @returns {Uint8Array} Les données converties
 */
function asU8(x) {
    if (!x) return new Uint8Array();
    if (x instanceof Uint8Array) return x;
    if (Array.isArray(x)) return new Uint8Array(x);
    if (typeof x === "string") return b64d(x);   // si un jour ça arrive en base64
    throw new Error("Type cypher invalide: " + typeof x);
}

// ==============================
// GESTION DU TOKEN D'AUTHENTIFICATION API
// ==============================

/**
 * Token Bearer pour l'authentification API, injecté depuis Blazor
 */
let _apiAccessToken = null;

/**
 * Définit le token d'accès API pour les appels authentifiés
 * @param {string} token - Le token Bearer à utiliser
 */
export function setApiAccessToken(token) {
    _apiAccessToken = token;
}

/**
 * Génère les headers d'authentification pour les requêtes API
 * @returns {Object} Headers avec Authorization si token disponible
 */
function authHeaders() {
    return _apiAccessToken ? {Authorization: `Bearer ${_apiAccessToken}`} : {};
}

// ==============================
// GESTION DU VAULT EN MÉMOIRE ET AUTO-LOCK
// ==============================

/**
 * Vault actuellement ouvert en mémoire
 * Contient l'ID du vault et la clé AES dérivée
 */
let currentVault = {id: null, key: /** @type {CryptoKey|null} */(null)};

/**
 * Timer pour le verrouillage automatique du vault
 */
let _autoLockTimer = /** @type {ReturnType<typeof setTimeout>|null} */ (null);

/**
 * Durée par défaut avant verrouillage automatique (5 minutes)
 */
let _autoLockMsDefault = 300000;

/**
 * Annule le timer de verrouillage automatique en cours
 */
function _clearAutoLock() {
    if (_autoLockTimer) {
        clearTimeout(_autoLockTimer);
        _autoLockTimer = null;
    }
}

/**
 * Active le timer de verrouillage automatique
 * @param {number} ms - Délai en millisecondes avant verrouillage
 */
function _armAutoLock(ms) {
    _clearAutoLock();
    _autoLockTimer = setTimeout(() => lockNow(), ms);
}

/**
 * Vérifie si un vault spécifique est actuellement ouvert
 * @param {number|string} vaultId - ID du vault à vérifier
 * @returns {boolean} True si le vault est ouvert
 */
export function isVaultOpen(vaultId) {
    // On vérifie si l'ID correspond (si on veut être strict) et si la clé existe
    // Note : vaultId vient souvent en string ou int, attention au type. "==" gère ça.
    return (currentVault.id == vaultId) && !!currentVault.key;
}

/**
 * Réinitialise le timer d'auto-lock (à appeler lors de chaque opération)
 */
export function touchVault() {
    if (currentVault.key) _armAutoLock(_autoLockMsDefault);
}

/**
 * Verrouille immédiatement le vault
 * Efface la clé de la mémoire et nettoie l'interface
 */
export function lockNow() {
    currentVault = {id: null, key: null};
    _clearAutoLock();
    clearVaultList();
}

// ==============================
// UTILITAIRES CRYPTOGRAPHIQUES - Chiffrement/Déchiffrement
// ==============================

/**
 * Sépare les données chiffrées du tag d'authentification GCM
 * @param {ArrayBuffer} buf - Buffer contenant données + tag
 * @returns {{cipher: Uint8Array, tag: Uint8Array}} Données et tag séparés
 */
function splitCtAndTag(buf) {
    const u = new Uint8Array(buf);
    return {cipher: u.slice(0, u.length - TAG_BYTES), tag: u.slice(u.length - TAG_BYTES)};
}

/**
 * Joint les données chiffrées et le tag d'authentification
 * @param {Uint8Array} cipherU8 - Données chiffrées
 * @param {Uint8Array} tagU8 - Tag d'authentification
 * @returns {ArrayBuffer} Buffer combiné
 */
function joinCtAndTag(cipherU8, tagU8) {
    const out = new Uint8Array(cipherU8.length + tagU8.length);
    out.set(cipherU8, 0);
    out.set(tagU8, cipherU8.length);
    return out.buffer;
}

/**
 * Chiffre un champ texte avec la clé du vault en RAM
 * Utilise AES-GCM avec données authentifiées additionnelles (AAD)
 * @param {string} text - Texte à chiffrer
 * @param {string} aad - Données additionnelles pour l'authentification
 * @returns {Promise<{cipher: Uint8Array, tag: Uint8Array, iv: Uint8Array}>} Données chiffrées
 */
async function encFieldWithVaultKey(text, aad) {
    if (!currentVault.key) throw new Error("Vault non ouvert");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ctFull = await crypto.subtle.encrypt(
        {name: "AES-GCM", iv, additionalData: aad ? enc.encode(aad) : undefined},
        currentVault.key,
        enc.encode(text ?? "")
    );
    const {cipher, tag} = splitCtAndTag(ctFull);
    touchVault();
    return {cipher, tag, iv};
}

/**
 * Déchiffre un champ avec la clé du vault en RAM
 * Utilise AES-GCM avec vérification AAD
 * @param {Uint8Array} cipherU8 - Données chiffrées
 * @param {Uint8Array} tagU8 - Tag d'authentification
 * @param {Uint8Array} ivU8 - Vecteur d'initialisation
 * @param {string} aad - Données additionnelles pour vérification
 * @returns {Promise<string>} Texte déchiffré
 */
async function decFieldWithVaultKey(cipherU8, tagU8, ivU8, aad) {
    if (!currentVault.key) throw new Error("Vault non ouvert");
    const full = joinCtAndTag(cipherU8, tagU8);
    const pt = await crypto.subtle.decrypt(
        {name: "AES-GCM", iv: ivU8, additionalData: aad ? enc.encode(aad) : undefined},
        currentVault.key,
        full
    );
    touchVault();
    return new TextDecoder().decode(pt);
}

/**
 * Crée un objet cypher compatible avec l'API à partir d'un texte clair
 * @param {string} value - Valeur à chiffrer
 * @param {string} aad - Données d'authentification additionnelles
 * @returns {Promise<Object>} Objet avec baseCypher, baseCypherTag, baseCypherIv en base64
 */
async function makeCypherObj(value, aad) {
    const {cipher, tag, iv} = await encFieldWithVaultKey(value ?? "", aad);
    return {
        baseCypher: b64(cipher),
        baseCypherTag: b64(tag),
        baseCypherIv: b64(iv)
        // ne pas envoyer "aad" si ton modèle C# ne le prévoit pas
    };
}

// ==============================
// OUVERTURE ET DÉRIVATION DE CLÉ VAULT
// ==============================

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

    currentVault = {id: vaultId, key: aesKey};
    _autoLockMsDefault = autoLockMs || 300000;
    _armAutoLock(_autoLockMsDefault);
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
 * N'ouvre PAS le vault, uniquement validation
 * @param {number} vaultId - ID du vault
 * @param {string} password - Mot de passe à vérifier
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<{ok: boolean, error?: string}>} Résultat de la vérification
 */
export async function verifyVaultPasswordServer(vaultId, password, apiBase = "https://localhost:7115") {
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

        const json = await res.json();               // <-- { ok: true/false }
        return json && json.ok ? {ok: true} : {ok: false, error: "Mot de passe incorrect"};
    } catch (e) {
        console.error("Erreur JS verifyVaultPasswordServer:", e);
        return {ok: false, error: e.message};
    }
}

/**
 * Dérive et stocke la clé AES en RAM à partir du salt et iterations
 * N'effectue PAS de vérification serveur
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

    currentVault = {id: vaultId, key: aesKey};
    touchVault();
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
export async function openVaultAfterVerify(vaultId, password, vaultSaltB64, iterations, apiBase = "https://localhost:7115") {
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
export async function openVaultFromModal(vaultId, inputId, vaultSaltB64, iterations, apiBase = "https://localhost:7115") {
    const el = document.getElementById(inputId);
    if (!(el instanceof HTMLInputElement)) throw new Error("Input mot de passe introuvable");

    const password = el.value ?? "";
    if (!password) return false;

    // 1) vérif serveur (avec mot de passe clair, mais depuis le navigateur)
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

// ==============================
// GESTION DES VAULTS - Création et Modification
// ==============================

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
 * Crée un nouveau vault depuis une modale (approche zéro-knowledge)
 * Le mot de passe est envoyé au serveur pour génération du hash
 * @param {number} iterations - Nombre d'itérations PBKDF2
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<Object>} Données du vault créé
 */
export async function createVaultFromModal(iterations = 600000, apiBase = "https://localhost:7115") {
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
export async function updateVaultFromModal(apiBase = "https://localhost:7115") {
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

// ==============================
// GESTION DES ENTRÉES - Chiffrement et Création
// ==============================

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
export async function createEntryFromModal(vaultId, apiBase = "https://localhost:7115") {
    // 1) Récupération des champs DOM
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

    // 2) Vérifie que la clé de vault est bien en RAM
    if (!currentVault?.key || currentVault.id == null) {
        throw new Error("Vault non ouvert : clé AES introuvable côté client.");
    }

    // 3) Chiffrement côté client (AAD lie chaque champ au vault + type)
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
export async function updateEntryFromModal(EntryId, apiBase = "https://localhost:7115") {
    // 1) Récupération des champs DOM
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

    // 2) Vérifie que la clé de vault est bien en RAM
    if (!currentVault?.key || currentVault.id == null) {
        throw new Error("Vault non ouvert : clé AES introuvable côté client.");
    }

    // 3) Chiffrement côté client (AAD lie chaque champ au vault + type)
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

// ==============================
// AFFICHAGE ET DÉCHIFFREMENT D'ENTRÉES
// ==============================

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
 * Vide l'affichage de la liste des entrées
 */
export function clearVaultList() {
    const list = document.getElementById("vault-list");
    if (list) list.textContent = "";
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

    if (currentVault.id != vaultId) {
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
    _plainSecretsByElementId.set(ids.passwordId, clearPwd);
    _visibleByElementId.set(ids.passwordId, false);

    const nameClear = await dec(entry.nomCypher, `${ns}|field:name`);
    const usernameClear = await dec(entry.userNameCypher, `${ns}|field:username`);
    const passwordClear = await dec(entry.passwordCypher, `${ns}|field:password`);
    const urlClear = await dec(entry.urlCypher, `${ns}|field:url`);
    const notesClear = await dec(entry.noteCypher, `${ns}|field:notes`);

    // affichage masqué par défaut
    setText(ids.passwordId, maskPassword(clearPwd));    setText(ids.urlId,      await dec(entry.urlCypher,      `${ns}|field:url`));
    setText(ids.notesId,    await dec(entry.noteCypher,     `${ns}|field:notes`));

    touchVault();
}

// ==============================
// GESTION DE LA VISIBILITÉ DES MOTS DE PASSE
// ==============================

/**
 * Stockage en RAM des mots de passe en clair (elementId -> texte clair)
 */
const _plainSecretsByElementId = new Map();

/**
 * État de visibilité des mots de passe (elementId -> boolean)
 */
const _visibleByElementId = new Map();

/**
 * Masque un mot de passe avec des points
 * @param {string} pwd - Mot de passe à masquer
 * @returns {string} Chaîne de points de même longueur (min 8)
 */
function maskPassword(pwd) {
    if (!pwd) return "";
    // même longueur que le mdp (optionnel), sinon fixe
    return "•".repeat(Math.max(8, pwd.length));
}

/**
 * Bascule la visibilité d'un mot de passe entre clair et masqué
 * @param {string} elementId - ID de l'élément DOM contenant le mot de passe
 */
export function togglePasswordVisibility(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const clearPwd = _plainSecretsByElementId.get(elementId) ?? "";
    const visible = _visibleByElementId.get(elementId) ?? false;

    if (!visible) {
        el.textContent = clearPwd;
        _visibleByElementId.set(elementId, true);
    } else {
        el.textContent = maskPassword(clearPwd);
        _visibleByElementId.set(elementId, false);
    }

    touchVault();
}

// ==============================
// COPIE DANS LE PRESSE-PAPIERS
// ==============================

/**
 * Copie le contenu d'un élément DOM dans le presse-papiers
 * Si l'élément contient un mot de passe stocké en RAM, copie la version claire
 * @param {string} elementId - ID de l'élément à copier
 * @returns {Promise<void>}
 */
export async function copyDomTextToClipboard(elementId) {
    const clearPwd = _plainSecretsByElementId.get(elementId);

    const textToCopy = (typeof clearPwd === "string" && clearPwd.length > 0)
        ? clearPwd
        : (document.getElementById(elementId)?.textContent ?? "");

    if (!textToCopy) return;

    await navigator.clipboard.writeText(textToCopy);
    touchVault();
}

// ==============================
// GÉNÉRATION DE MOTS DE PASSE SÉCURISÉS
// ==============================

/**
 * Génère un mot de passe aléatoire sécurisé
 * Utilise crypto.getRandomValues pour génération cryptographiquement sûre
 * @param {number} length - Longueur du mot de passe à générer
 * @returns {string} Mot de passe généré avec majuscules, minuscules, chiffres et caractères spéciaux
 */
export function generateSecurePassword(length) {

    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const digits = "0123456789";
    const special = "!@#$%^&*()-_=+[]{}<>?";
    const all = upper + lower + digits + special;

    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);

    let password = "";
    for (let i = 0; i < length; i++) {
        password += all[randomValues[i] % all.length];
    }

    return password;
}

/**
 * Génère un mot de passe sécurisé et le place dans un champ input
 * @param {string} elementId - ID de l'élément input à remplir
 * @param {number} length - Longueur du mot de passe à générer
 */
export function generateAndFillPassword(elementId, length) {
    const pwd = generateSecurePassword(length);
    const el = document.getElementById(elementId);
    if (el) el.value = pwd;
}


















// ==============================
// GESTION DE LA CLÉ MAGIQUE (DEK/KEK)
// ==============================

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
    const dekRaw = await crypto.subtle. exportKey("raw", dek);

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

// ==============================
// CRÉATION DE VAULT AVEC DEK
// ==============================

/**
 * Crée un nouveau vault avec système DEK/KEK
 * REMPLACE createVaultFromModal
 * @param {number} iterations - Nombre d'itérations PBKDF2
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<Object>} Données du vault créé
 */
export async function createVaultWithDEK(iterations = 600000, apiBase = "https://localhost:7115") {
    const root = document.querySelector(". modal-content");
    if (!root) throw new Error("Modal introuvable (. modal-content)");

    const vaultNameEl = root.querySelector('input[type="text"]');
    const vaultPwdEl = root.querySelector('input[type="password"]');

    const name = (vaultNameEl?. value ??  "").trim();
    const password = vaultPwdEl?.value ??  "";

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
        headers: { "Content-Type": "application/json", ... authHeaders() },
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

// ==============================
// OUVERTURE DE VAULT AVEC DEK
// ==============================

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

    const password = el.value ??  "";
    if (!password) return false;

    try {
        // 1️⃣ Vérification du mot de passe
        const check = await verifyVaultPasswordServer(vaultId, password, apiBase);
        if (!check. ok) {
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
        currentVault = { id: vaultId, key: dek };
        touchVault();

        el.value = "";
        return true;

    } catch (e) {
        console.error("Erreur ouverture vault avec DEK:", e);
        el.value = "";
        return false;
    }
}

// ==============================
// CHANGEMENT DE MOT DE PASSE
// ==============================

/**
 * Change le mot de passe maître en re-wrappant la DEK
 * @param {number} vaultId - ID du vault
 * @param {string} oldPassword - Ancien mot de passe
 * @param {string} newPassword - Nouveau mot de passe
 * @param {string} apiBase - URL de base de l'API
 * @returns {Promise<{ok: boolean, error?:  string}>}
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
    const oldPwKey = await crypto.subtle. importKey(
        "raw",
        enc.encode(oldPassword),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const oldKek = await crypto.subtle.deriveKey(
        { name:  "PBKDF2", hash: "SHA-256", salt:  b64d(salt), iterations: nbIteration },
        oldPwKey,
        { name:  "AES-GCM", length: 256 },
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
    const newPwKey = await crypto.subtle. importKey(
        "raw",
        enc.encode(newPassword),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const newKek = await crypto.subtle. deriveKey(
        { name: "PBKDF2", hash: "SHA-256", salt: b64d(salt), iterations: nbIteration },
        newPwKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

    // 5️⃣ Re-wrapping de la DEK avec la nouvelle KEK
    const { wrappedDek:  newWrappedDek, iv:  newIv, tag: newTag } = await wrapDEK(dek, newKek);

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

    if (!updateRes. ok) {
        const text = await updateRes.text().catch(() => "");
        return { ok: false, error: `Erreur API: ${updateRes.status} ${text}` };
    }

    // 7️⃣ Mise à jour de la session en mémoire
    currentVault = { id: vaultId, key: dek };
    touchVault();

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
    newPwdEl. value = "";
    confirmPwdEl.value = "";

    if (! result.ok) {
        alert(result.error || "Erreur lors du changement de mot de passe");
        return false;
    }

    alert("Mot de passe changé avec succès !");
    return true;
}