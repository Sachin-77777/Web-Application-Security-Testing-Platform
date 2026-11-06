/* Shared behaviour for the signed-in pages.
   Kept in a static file because the app's Content-Security-Policy sets
   script-src 'self' with no 'unsafe-inline', which disables both inline
   <script> blocks and inline handlers such as onsubmit="return confirm(...)".
   Everything below is wired up from data-* attributes instead. */
(function () {
  "use strict";

  // Confirm destructive actions: forms carry data-confirm="Really delete?".
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });

  // Buttons that open the browser print dialog (e.g. "Print / Save as PDF").
  document.querySelectorAll("[data-print]").forEach(function (button) {
    button.addEventListener("click", function () {
      window.print();
    });
  });

  // Let success banners fade away on their own; errors stay until dismissed.
  document.querySelectorAll("[data-auto-dismiss]").forEach(function (alert) {
    window.setTimeout(function () {
      alert.classList.remove("show");
      window.setTimeout(function () {
        alert.remove();
      }, 300);
    }, 6000);
  });
})();
