/* Login and registration form behaviour.
 *
 * Shared by login.html and register.html. The rules are the same for both:
 *   - the password is read from the field, sent once, and the field is cleared
 *   - the submit button is disabled while the request is in flight, so a
 *     double-click or an impatient Enter cannot fire two logins
 *   - every message is written with textContent
 *   - the raw session token is never read, stored or displayed: it is in an
 *     HttpOnly cookie this script cannot see
 */
(function () {
  "use strict";

  function setMessage(el, text, kind) {
    if (!el) { return; }
    el.textContent = text;
    el.className = "form-message" + (kind ? " is-" + kind : "");
    el.hidden = !text;
  }

  function busy(form, button, on) {
    if (button) {
      button.disabled = on;
      button.setAttribute("aria-busy", on ? "true" : "false");
    }
    if (form) { form.setAttribute("aria-busy", on ? "true" : "false"); }
  }

  function init() {
    var form = document.getElementById("auth-form");
    if (!form) { return; }

    var mode = form.getAttribute("data-mode");           // "login" or "register"
    var button = form.querySelector('button[type="submit"]');
    var message = document.getElementById("auth-message");
    var username = document.getElementById("username");
    var password = document.getElementById("password");
    var confirmField = document.getElementById("confirm");

    /* Already signed in? Go straight through rather than making a student log
     * in twice on a shared lab machine. */
    window.LabAuth.me().then(function (user) {
      if (user && mode === "login") {
        window.location.replace(window.LabAuth.safeNext("index.html"));
      }
    });

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      setMessage(message, "", null);

      var name = username ? username.value.trim() : "";
      var secret = password ? password.value : "";

      if (!name || !secret) {
        setMessage(message, "Enter your username and password.", "error");
        return;
      }

      /* The two passwords must match before anything is sent. Checking here
       * saves a pointless round trip and keeps the mistake on the screen. */
      if (mode === "register" && confirmField && secret !== confirmField.value) {
        setMessage(message, "The two passwords do not match.", "error");
        return;
      }

      var pending = mode === "register"
        ? window.LabAuth.register(name, secret)
        : window.LabAuth.login(name, secret);

      busy(form, button, true);

      pending.then(function (result) {
        var data = result.data || {};

        if (result.status === 200 || result.status === 201) {
          /* Clear the password from the DOM as soon as it has been sent. */
          if (password) { password.value = ""; }
          if (confirmField) { confirmField.value = ""; }

          if (mode === "register") {
            /* Registration deliberately does not sign anyone in. Send them to
             * the login page with the username carried over, which is in a URL
             * so it is a *username*, never a credential. */
            setMessage(message, "Account created. You can sign in now.", "ok");
            busy(form, button, false);
            window.setTimeout(function () {
              window.location.replace("login.html?next=" +
                encodeURIComponent(window.LabAuth.safeNext("index.html")) +
                "&u=" + encodeURIComponent(name));
            }, 700);
            return;
          }

          setMessage(message, "Signed in. Loading the lab...", "ok");
          window.location.replace(window.LabAuth.safeNext("index.html"));
          return;
        }

        busy(form, button, false);
        if (password) { password.value = ""; }

        if (result.status === 429) {
          var wait = data.retry_after;
          setMessage(message,
            "Too many failed attempts. Wait " + (wait || 60) +
            " seconds and try again.", "error");
          return;
        }
        /* One message for every other failure, so a student cannot tell a
         * wrong password from a username that does not exist. */
        setMessage(message, data.error || "Sign in failed. Please try again.", "error");
      }).catch(function () {
        busy(form, button, false);
        setMessage(message, "Could not reach the lab server. Please try again.", "error");
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
