// ==============================
// GESTION DU VAULT EN MÉMOIRE ET AUTO-LOCK
// ==============================

/**
 * Vault actuellement ouvert en mémoire
 * Contient l'ID du vault et la clé AES dérivée
 */
export let currentVault = {id: null, key: /** @type {CryptoKey|null} */(null)};

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
    // On vérifie si l'ID correspond (conversion en string pour compatibilité)
    return (String(currentVault.id) === String(vaultId)) && !!currentVault.key;
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
    currentVault.id = null;
    currentVault.key = null;
    _clearAutoLock();
    clearVaultList();
}

/**
 * Vide l'affichage de la liste des entrées
 */
export function clearVaultList() {
    const list = document.getElementById("vault-list");
    if (list) list.textContent = "";
}

/**
 * Met à jour le délai d'auto-lock par défaut
 * @param {number} ms - Nouveau délai en millisecondes
 */
export function setAutoLockDelay(ms) {
    _autoLockMsDefault = ms;
}

/**
 * Met à jour currentVault (utilisé par d'autres modules)
 * @param {number} id - ID du vault
 * @param {CryptoKey} key - Clé AES du vault
 */
export function setCurrentVault(id, key) {
    currentVault.id = id;
    currentVault.key = key;
    touchVault();
}

/**
 * Arme le timer d'auto-lock (exposé pour les autres modules)
 * @param {number} ms - Délai en millisecondes
 */
export function armAutoLock(ms) {
    _armAutoLock(ms);
}

/**
 * Récupère le délai d'auto-lock par défaut
 * @returns {number} Délai en millisecondes
 */
export function getAutoLockDelay() {
    return _autoLockMsDefault;
}

