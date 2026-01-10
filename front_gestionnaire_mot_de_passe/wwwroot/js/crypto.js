// ==============================
// FICHIER PRINCIPAL - Réexporte toutes les fonctionnalités crypto
// ==============================
// Ce fichier consolide tous les modules crypto pour maintenir la compatibilité
// avec le code existant tout en bénéficiant d'une structure modulaire

// Utilitaires de base
export { enc, b64, b64d, TAG_BYTES, asU8 } from './crypto-utils.js';

// Authentification API
export { setApiAccessToken, authHeaders } from './crypto-auth.js';

// Gestion du vault en mémoire
export { currentVault, isVaultOpen, touchVault, lockNow, clearVaultList } from './crypto-vault-session.js';

export { PasswordStrengthMeter } from "./crypto-utils.js";

export { setApiBaseUrl } from "./crypto-config.js";

// Utilitaires cryptographiques
export { 
    splitCtAndTag, 
    joinCtAndTag, 
    encFieldWithVaultKey, 
    decFieldWithVaultKey, 
    makeCypherObj 
} from './crypto-encryption.js';

// Gestion des vaults
export {
    openVault,
    openVaultFromInput,
    verifyVaultPasswordServer,
    armVaultSession,
    openVaultAfterVerify,
    openVaultFromModal,
    createVaultVerifierFromInput,
    createVaultFromModal,
    updateVaultFromModal
} from './crypto-vault-management.js';

// Gestion des entrées
export {
    encryptEntryForOpenVault,
    createEntryFromModal,
    updateEntryFromModal,
    fillUpdateModal,
    decryptVaultEntry,
    renderVaultEntries,
    decryptEntryToDom,
    fetchAndDecryptPassword
} from './crypto-entry-management.js';

// Outils de gestion des mots de passe
export {
    maskPassword,
    togglePasswordVisibility,
    copyDomTextToClipboard,
    generateSecurePassword,
    generateAndFillPassword
} from './crypto-password-tools.js';

// Système DEK/KEK (clé magique)
export {
    createVaultWithDEK,
    openVaultWithDEKFromModal,
    changeVaultPassword,
    changeVaultPasswordFromModal
} from './crypto-dek-kek.js';

