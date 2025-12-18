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
export function authHeaders() {
    return _apiAccessToken ? {Authorization: `Bearer ${_apiAccessToken}`} : {};
}

