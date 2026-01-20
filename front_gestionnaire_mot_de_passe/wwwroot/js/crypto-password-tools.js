// ==============================
// GESTION DES MOTS DE PASSE - Génération, Visibilité et Copie
// ==============================

import { touchVault } from './crypto-vault-session.js';

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
export function maskPassword(pwd) {
    if (!pwd) return "";
    // même longueur que le mdp (optionnel), sinon fixe
    return "•".repeat(Math.max(8, pwd.length));
}

/**
 * Stocke un mot de passe en RAM pour un élément DOM
 * @param {string} elementId - ID de l'élément
 * @param {string} password - Mot de passe en clair
 */
export function storePassword(elementId, password) {
    _plainSecretsByElementId.set(elementId, password);
    _visibleByElementId.set(elementId, false);
}

/**
 * Récupère un mot de passe du cache RAM
 * @param {string} elementId - ID de l'élément
 * @returns {string|null} Mot de passe en clair ou null si non trouvé
 */
export function retrievePassword(elementId) {
    return _plainSecretsByElementId.get(elementId) || null;
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

    if (!textToCopy) {
        console.error('Impossible de copier - aucun texte trouvé pour:', elementId);
        return;
    }

    try {
        await navigator.clipboard.writeText(textToCopy);
        touchVault();
    } catch (error) {
        console.error('Erreur lors de la copie dans le presse-papiers:', error);
        throw error;
    }
}

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

    el.dispatchEvent(new Event("input", { bubbles: true }));
}

