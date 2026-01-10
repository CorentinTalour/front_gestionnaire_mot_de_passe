let API_BASE = "";

export function setApiBaseUrl(url) {
    API_BASE = (url ?? "").replace(/\/+$/, ""); // enlève le trailing /
}

export function apiBaseUrl() {
    if (!API_BASE) throw new Error("API_BASE non initialisé. Appelle setApiBaseUrl depuis Blazor.");
    return API_BASE;
}