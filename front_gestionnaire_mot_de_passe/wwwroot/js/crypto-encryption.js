// ==============================
// UTILITAIRES CRYPTOGRAPHIQUES - Chiffrement/Déchiffrement
// ==============================

import { enc, b64, b64d, TAG_BYTES } from './crypto-utils.js';
import { currentVault, touchVault } from './crypto-vault-session.js';

/**
 * Sépare les données chiffrées du tag d'authentification GCM
 * @param {ArrayBuffer} buf - Buffer contenant données + tag
 * @returns {{cipher: Uint8Array, tag: Uint8Array}} Données et tag séparés
 */
export function splitCtAndTag(buf) {
    const u = new Uint8Array(buf);
    return {cipher: u.slice(0, u.length - TAG_BYTES), tag: u.slice(u.length - TAG_BYTES)};
}

/**
 * Joint les données chiffrées et le tag d'authentification
 * @param {Uint8Array} cipherU8 - Données chiffrées
 * @param {Uint8Array} tagU8 - Tag d'authentification
 * @returns {ArrayBuffer} Buffer combiné
 */
export function joinCtAndTag(cipherU8, tagU8) {
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
export async function encFieldWithVaultKey(text, aad) {
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
export async function decFieldWithVaultKey(cipherU8, tagU8, ivU8, aad) {
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
export async function makeCypherObj(value, aad) {
    const {cipher, tag, iv} = await encFieldWithVaultKey(value ?? "", aad);
    return {
        baseCypher: b64(cipher),
        baseCypherTag: b64(tag),
        baseCypherIv: b64(iv)
    };
}

/**
 * Déchiffre un objet CypherData (structure avec cypher/baseCypher, cypherTag/baseCypherTag, cypherIv/baseCypherIv)
 * @param {Object} obj - Objet CypherData
 * @param {string} aad - Données d'authentification additionnelles
 * @returns {Promise<string>} Texte déchiffré
 */
export async function decryptCypherObj(obj, aad) {
    if (!obj) return "";
    const c  = typeof obj.cypher === 'string' ? b64d(obj.cypher) : (obj.cypher ?? obj.baseCypher);
    const t  = typeof obj.cypherTag === 'string' ? b64d(obj.cypherTag) : (obj.cypherTag ?? obj.baseCypherTag);
    const iv = typeof obj.cypherIv === 'string' ? b64d(obj.cypherIv) : (obj.cypherIv ?? obj.baseCypherIv);
    return await decFieldWithVaultKey(c, t, iv, aad);
}