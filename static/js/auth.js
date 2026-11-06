/* Sign-in page behaviour: show/hide password, Caps Lock hint, submit state.
   Kept in a static file because the app's Content-Security-Policy blocks
   inline <script>. */
(function () {
  "use strict";

  var ICON_EYE =
    '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<ellipse cx="12" cy="12" rx="9.5" ry="6"/><circle cx="12" cy="12" r="2.8"/></svg>';

  var ICON_EYE_OFF =
    '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<ellipse cx="12" cy="12" rx="9.5" ry="6"/><circle cx="12" cy="12" r="2.8"/><line x1="4" y1="20" x2="20" y2="4"/></svg>';

  function setupPasswordToggle(button) {
    var input = document.getElementById(button.getAttribute("data-password-toggle"));
    if (!input) {
      return;
    }

    button.addEventListener("click", function () {
      var reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      button.innerHTML = reveal ? ICON_EYE_OFF : ICON_EYE;
      button.setAttribute("aria-pressed", reveal ? "true" : "false");
      button.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
      button.setAttribute("title", reveal ? "Hide password" : "Show password");

      // Keep the caret where the user left it.
      input.focus();
      var end = input.value.length;
      input.setSelectionRange(end, end);
    });
  }

  function setupCapsLockHint(input) {
    // The hint is matched to the field by its own data-caps-hint attribute, so
    // a page with several password fields gets one hint per field.
    var hint = input.id
      ? document.querySelector('[data-caps-hint="' + input.id + '"]')
      : null;
    if (!hint) {
      return;
    }

    function sync(event) {
      var on = false;
      if (typeof event.getModifierState === "function") {
        on = event.getModifierState("CapsLock");
      }
      hint.classList.toggle("d-none", !on);
    }

    input.addEventListener("keydown", sync);
    input.addEventListener("keyup", sync);
    input.addEventListener("blur", function () {
      hint.classList.add("d-none");
    });
  }

  function setupSubmitState(form) {
    form.addEventListener("submit", function () {
      var button = form.querySelector("[data-loading-button]");
      if (!button) {
        return;
      }
      var text = form.getAttribute("data-loading-text") || "Please wait...";
      button.disabled = true;
      button.innerHTML =
        '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>' + text;
    });
  }

  document.querySelectorAll("[data-password-toggle]").forEach(setupPasswordToggle);
  document.querySelectorAll("[data-caps-watch]").forEach(setupCapsLockHint);
  document.querySelectorAll("[data-loading-form]").forEach(setupSubmitState);
})();
