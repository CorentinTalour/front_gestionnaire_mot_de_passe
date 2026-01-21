// ==============================
// GESTION DU VAULT EN MÉMOIRE ET AUTO-LOCK
// ==============================

/**
 * Stockage sécurisé des clés cryptographiques
 * Utilise un Symbol privé et WeakMap pour empêcher l'accès direct aux clés
 */
const _vaultKeySymbol = Symbol('vaultKey');
const _vaultStore = new WeakMap();
let _currentVaultContainer = null;
let _currentVaultId = null;

/**
 * Vault actuellement ouvert en mémoire (lecture seule)
 * La clé AES n'est plus directement accessible
 */
export const currentVault = {
    get id() {
        return _currentVaultId;
    },
    get key() {
        if (!_currentVaultContainer) return null;
        const container = _vaultStore.get(_currentVaultContainer);
        return container ? container[_vaultKeySymbol] : null;
    },
    // Empêche la modification directe
    set id(value) {
        throw new Error("Modification directe interdite. Utilisez setCurrentVault()");
    },
    set key(value) {
        throw new Error("Modification directe interdite. Utilisez setCurrentVault()");
    }
};

/**
 * Timer pour le verrouillage automatique du vault
 */
let _autoLockTimer = /** @type {ReturnType<typeof setTimeout>|null} */ (null);

/**
 * Durée par défaut avant verrouillage automatique (5 minutes)
 */
let _autoLockMsDefault = 300000;

/**
 * Vérifie que le vault est ouvert et correspond au vaultId fourni
 * @param {number} [vaultId] - ID du vault attendu (optionnel)
 * @throws {Error} Si le vault n'est pas ouvert ou ne correspond pas
 */
export function ensureVaultOpen(vaultId) {
    if (!currentVault?.key) {
        throw new Error("Vault non ouvert (clé AES absente).");
    }
    
    if (vaultId != null && String(currentVault.id) !== String(vaultId)) {
        throw new Error(`Vault ouvert = ${currentVault.id}, mais on tente d'accéder au vaultId = ${vaultId}`);
    }
}

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
    // Effacement sécurisé de la clé cryptographique
    if (_currentVaultContainer) {
        const container = _vaultStore.get(_currentVaultContainer);
        if (container) {
            // Suppression de la clé du conteneur
            delete container[_vaultKeySymbol];
        }
        // Suppression du conteneur de la WeakMap
        _vaultStore.delete(_currentVaultContainer);
        _currentVaultContainer = null;
    }
    
    _currentVaultId = null;
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
 * Met à jour currentVault de manière sécurisée
 * @param {number} id - ID du vault
 * @param {CryptoKey} key - Clé AES du vault (DOIT être non-extractable)
 */
export function setCurrentVault(id, key) {
    // Validation : la clé ne doit PAS être extractable
    if (key && key.extractable === true) {
        console.error("SÉCURITÉ: Tentative de stockage d'une clé extractable détectée!");
        throw new Error("Les clés cryptographiques doivent être non-extractables (extractable=false)");
    }
    
    // Nettoyage de l'ancien vault si existant
    if (_currentVaultContainer) {
        lockNow();
    }
    
    // Création d'un nouveau conteneur sécurisé
    _currentVaultContainer = { id };
    const container = { [_vaultKeySymbol]: key };
    _vaultStore.set(_currentVaultContainer, container);
    _currentVaultId = id;
    
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