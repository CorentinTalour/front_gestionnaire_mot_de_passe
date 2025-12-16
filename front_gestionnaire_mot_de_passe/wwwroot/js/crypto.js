// ==============================
// Helpers généraux
// ==============================
const enc = new TextEncoder();
const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const TAG_BYTES = 16;

// Token Bearer injecté depuis Blazor
let _apiAccessToken = null;

export function setApiAccessToken(token) {
    _apiAccessToken = token;
}

function authHeaders() {
    return _apiAccessToken ? {Authorization: `Bearer ${_apiAccessToken}`} : {};
}

// ==============================
// Gestion du vault en RAM + auto-lock
// ==============================
let currentVault = {id: null, key: /** @type {CryptoKey|null} */(null)};
let _autoLockTimer = /** @type {ReturnType<typeof setTimeout>|null} */ (null);
let _autoLockMsDefault = 300000;

function _clearAutoLock() {
    if (_autoLockTimer) {
        clearTimeout(_autoLockTimer);
        _autoLockTimer = null;
    }
}

function _armAutoLock(ms) {
    _clearAutoLock();
    _autoLockTimer = setTimeout(() => lockNow(), ms);
}

export function lockNow() {
    currentVault = {id: null, key: null};
    _clearAutoLock();
    clearVaultList();
}

export function isVaultOpen(vaultId) {
    // On vérifie si l'ID correspond (si on veut être strict) et si la clé existe
    // Note : vaultId vient souvent en string ou int, attention au type. "==" gère ça.
    return (currentVault.id == vaultId) && !!currentVault.key;
}

export function touchVault() {
    if (currentVault.key) _armAutoLock(_autoLockMsDefault);
}

// ==============================
// Utilitaires chiffrement
// ==============================
function splitCtAndTag(buf) {
    const u = new Uint8Array(buf);
    return {cipher: u.slice(0, u.length - TAG_BYTES), tag: u.slice(u.length - TAG_BYTES)};
}

function joinCtAndTag(cipherU8, tagU8) {
    const out = new Uint8Array(cipherU8.length + tagU8.length);
    out.set(cipherU8, 0);
    out.set(tagU8, cipherU8.length);
    return out.buffer;
}

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

// ==============================
// Flux “cours” existant (si tu t’en sers encore)
// ==============================
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

export async function openVaultFromInput(vaultId, inputId, autoLockMs = 300000) {
    const pwd = document.getElementById(inputId)?.value ?? "";
    const res = await openVault(vaultId, pwd, autoLockMs);
    const el = document.getElementById(inputId);
    if (el) el.value = "";
    return res;
}

// ==============================
// Chiffrement/affichage d’entrées
// ==============================
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

export async function decryptVaultEntry(record) {
    const ns = `vault:${currentVault.id}`;
    const out = {};
    out.password = await decFieldWithVaultKey(b64d(record.cipherPasswordB64), b64d(record.tagPasswordB64), b64d(record.ivPasswordB64), `${ns}|field:password`);
    out.name = await decFieldWithVaultKey(b64d(record.cipherNameB64), b64d(record.tagNameB64), b64d(record.ivNameB64), `${ns}|field:name`);
    out.url = await decFieldWithVaultKey(b64d(record.cipherUrlB64), b64d(record.tagUrlB64), b64d(record.ivUrlB64), `${ns}|field:url`);
    out.notes = await decFieldWithVaultKey(b64d(record.cipherNotesB64), b64d(record.tagNotesB64), b64d(record.ivNotesB64), `${ns}|field:notes`);
    return out;
}

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

export function clearVaultList() {
    const list = document.getElementById("vault-list");
    if (list) list.textContent = "";
}

// ==============================
// Création “zéro mot de passe serveur” pour l'API
// ==============================
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
 * Vérifie le mot de passe maître d’un coffre existant.
 * Appelle l’API : POST https://localhost:7115/Vault/{id}/check
 * Corps JSON : { "passwordClear": "leMotDePasse" }
 * Retour attendu : { ok: true } ou { ok: false }
 */
// Vérifie uniquement auprès de l'API. Ne touche PAS à currentVault.
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

// Dérive et garde la clé AES en RAM (currentVault) à partir du salt+iterations déjà connus.
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

// Helper pratique : vérifie côté serveur puis arme la clé locale si OK.
export async function openVaultAfterVerify(vaultId, password, vaultSaltB64, iterations, apiBase = "https://localhost:7115") {
    const check = await verifyVaultPasswordServer(vaultId, password, apiBase);
    if (!check.ok) return check;
    await armVaultSession(vaultId, password, vaultSaltB64, iterations);
    return {ok: true};
}

// utilitaire: fabrique un PostCypherObj à partir d'un texte clair
async function makeCypherObj(value, aad) {
    const {cipher, tag, iv} = await encFieldWithVaultKey(value ?? "", aad);
    return {
        baseCypher: b64(cipher),
        baseCypherTag: b64(tag),
        baseCypherIv: b64(iv)
        // ne pas envoyer "aad" si ton modèle C# ne le prévoit pas
    };
}

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

    // touche le timer d’auto-lock
    touchVault();

    return true;
}








function asU8(x) {
    if (!x) return new Uint8Array();
    if (x instanceof Uint8Array) return x;
    if (Array.isArray(x)) return new Uint8Array(x);
    if (typeof x === "string") return b64d(x);   // si un jour ça arrive en base64
    throw new Error("Type cypher invalide: " + typeof x);
}

export async function decryptEntryToDom(vaultId, entry, ids) {
    if (!currentVault?.key) throw new Error("Vault non ouvert (clé AES absente).");

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

    // tes propriétés sont en camelCase d’après ton log
    setText(ids.nameId,     await dec(entry.nomCypher,      `${ns}|field:name`));
    setText(ids.usernameId, await dec(entry.userNameCypher, `${ns}|field:username`));
    const clearPwd = await dec(entry.passwordCypher, `${ns}|field:password`);

    // on garde le clair en RAM JS (pas dans le DOM)
    _plainSecretsByElementId.set(ids.passwordId, clearPwd);
    _visibleByElementId.set(ids.passwordId, false);

    // affichage masqué par défaut
    setText(ids.passwordId, maskPassword(clearPwd));    setText(ids.urlId,      await dec(entry.urlCypher,      `${ns}|field:url`));
    setText(ids.notesId,    await dec(entry.noteCypher,     `${ns}|field:notes`));

    touchVault();
}

// export async function copyDomTextToClipboard(elementId) {
//     const el = document.getElementById(elementId);
//     const text = el?.textContent ?? "";
//     if (text) await navigator.clipboard.writeText(text);
//     touchVault();
// }

const _plainSecretsByElementId = new Map(); // elementId -> cleartext password
const _visibleByElementId = new Map();      // elementId -> bool

function maskPassword(pwd) {
    if (!pwd) return "";
    // même longueur que le mdp (optionnel), sinon fixe
    return "•".repeat(Math.max(8, pwd.length));
}


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

export async function copyDomTextToClipboard(elementId) {
    const clearPwd = _plainSecretsByElementId.get(elementId);

    const textToCopy = (typeof clearPwd === "string" && clearPwd.length > 0)
        ? clearPwd
        : (document.getElementById(elementId)?.textContent ?? "");

    if (!textToCopy) return;

    await navigator.clipboard.writeText(textToCopy);
    touchVault();
}

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