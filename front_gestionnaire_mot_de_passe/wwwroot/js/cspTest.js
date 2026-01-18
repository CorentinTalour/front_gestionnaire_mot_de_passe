// Script de test CSP - charge jQuery
(function() {
    function initCspTest() {
        window.cspTest_loadExternalScript = function() {
            const s = document.createElement("script");
            s.src = "https://code.jquery.com/jquery-3.6.0.min.js";
            document.head.appendChild(s);
        };
    }
    
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initCspTest);
    } else {
        initCspTest();
    }
})();

