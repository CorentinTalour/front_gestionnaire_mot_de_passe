// ==============================
// UTILITAIRES DE BASE - Encodage et conversion
// ==============================

/**
 * Encodeur de texte pour convertir des chaînes en Uint8Array
 */
export const enc = new TextEncoder();

/**
 * Convertit un ArrayBuffer en chaîne base64
 * @param {ArrayBuffer} a - Le buffer à convertir
 * @returns {string} La chaîne encodée en base64
 */
export const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));

/**
 * Convertit une chaîne base64 en Uint8Array
 * @param {string} s - La chaîne base64 à décoder
 * @returns {Uint8Array} Les données décodées
 */
export const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

/**
 * Taille du tag d'authentification GCM en octets
 */
export const TAG_BYTES = 16;

/**
 * Convertit différents types de données en Uint8Array
 * Accepte Uint8Array, Array, ou string (base64)
 * @param {*} x - Données à convertir
 * @returns {Uint8Array} Les données converties
 */
export function asU8(x) {
    if (!x) return new Uint8Array();
    if (x instanceof Uint8Array) return x;
    if (Array.isArray(x)) return new Uint8Array(x);
    if (typeof x === "string") return b64d(x);   // si un jour ça arrive en base64
    throw new Error("Type cypher invalide: " + typeof x);
}


//////// Fonction qui calcule la force du mot de passe ////////////
export function PasswordStrengthMeter(inputElement) {
    const input = inputElement;

    if (!input) return;

    const container = input
        .closest(".form-group")
        ?.querySelector(".password-strength-container");

    if (!container) return;

    const bar = container.querySelector(".strength-bar");
    const text = container.querySelector(".strength-text");

    if (!bar || !text) return;

    // 🔒 Protection contre les doubles listeners
    if (input._strengthHandler) return;

    input._strengthHandler = () => {
        let score = 0;
        const pwd = input.value;

        if (pwd.length >= 8) score++;
        if (/[A-Z]/.test(pwd)) score++;
        if (/\d/.test(pwd)) score++;
        if (/[!@#$%^&*()_\-+=<>?/{}\[\]|]/.test(pwd)) score++;

        const states = [
            ["empty", ""],
            ["weak", "Faible"],
            ["medium", "Moyen"],
            ["strong", "Fort"],
            ["very-strong", "Très fort"]
        ];

        const [cls, label] = states[score];
        bar.className = `strength-bar ${cls}`;
        text.textContent = label;
    };

    input.addEventListener("input", input._strengthHandler);
}

