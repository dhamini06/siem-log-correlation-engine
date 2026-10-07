/* Shared authentication helper for the BlueCloud training platform.
 *
 * One rule governs this whole file: the session token is never handled here.
 * It lives in an HttpOnly cookie, which this script cannot read, and the
 * browser attaches it to every request on its own. So there is nothing to
 * store, nothing to refresh, and nothing to leak. No localStorage, no
 * sessionStorage, no token in a URL, no JWT.
 *
 * The only state this file keeps is the *identity* the server already chose to
 * return - an id, a username and a role. That is a display convenience, not a
 * credential, and it is re-fetched from /api/auth/me on every page load rather
 * than trusted from storage.
 *
 * Every value that came from the server is written with textContent. There is
 * no innerHTML in this file, so a hostile username cannot become markup.
 */
(function (global) {
  "use strict";

  var API = "/api/auth/";

  /* Perform an auth request. Resolves with {status, data}; never rejects on an
   * HTTP error, so callers only handle one failure shape. */
  function request(path, options) {
    var settings = options || {};
    return fetch(API + path, {
      method: settings.method || "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: settings.body === undefined ? undefined : JSON.stringify(settings.body)
    }).then(function (response) {
      return response.json().catch(function () {
        return {};
      }).then(function (data) {
        return { status: response.status, data: data };
      });
    });
  }

  /* Who am I? Resolves to null when anonymous. */
  function me() {
    return request("me").then(function (result) {
      return result.data && result.data.authenticated ? result.data.user : null;
    });
  }

  function register(username, password) {
    return request("register", {
      method: "POST",
      body: { username: username, password: password }
    });
  }

  function login(username, password) {
    return request("login", {
      method: "POST",
      body: { username: username, password: password }
    });
  }

  function logout() {
    return request("logout", { method: "POST" });
  }

  /* A safe place to send a student after signing in.
   *
   * The ?next= value is a convenience, never a trust decision: anything with a
   * scheme, a host, or a leading double slash is discarded and the student goes
   * to the homepage. Without this check, ?next=https://evil.example would make
   * the login page an open redirect that a student trusts because it is ours.
   */
  function safeNext(fallback) {
    var target = fallback || "index.html";
    try {
      var raw = new URLSearchParams(global.location.search).get("next");
      if (!raw) { return target; }
      if (raw.indexOf("//") !== -1 || raw.indexOf(":") !== -1 || raw.charAt(0) !== "/") {
        return target;
      }
      return raw;
    } catch (err) {
      return target;
    }
  }

  /* Show the signed-in identity, and leave exactly one of the two session
   * controls in front of the student.
   *
   * The two controls get separate arguments on purpose. They used to share
   * one ``linkEl`` slot, and the caller passed the sign-*out* element into
   * it, so the toggle was driven by the wrong control: signing in hid
   * "Sign out" and being anonymous revealed it. A signed-in student was
   * shown "Sign in" in the header and had no visible way to end their
   * session at all.
   *
   * Text only - no markup is built from a server value. */
  function paintIdentity(user, nameEl, signInEl, signOutEl) {
    var signedIn = !!(user && user.username);
    if (nameEl) {
      nameEl.textContent = signedIn ? "Signed in as " + user.username : "";
      nameEl.hidden = !signedIn;
    }
    if (signInEl) { signInEl.hidden = signedIn; }
    if (signOutEl) { signOutEl.hidden = !signedIn; }
  }

  /* Sign out, then leave the page. The server has already deleted the session
   * row, so the cookie is dead even if the browser were slow to drop it, and
   * the redirect lands on the login page rather than a portal page that would
   * immediately bounce back. */
  function signOut() {
    return logout().then(function () {
      global.location.replace("login.html");
    });
  }

  /* Wire the header identity slot and the session controls, if the page has
   * them. Idempotent, and a no-op on a page that has none of them, so this
   * can be loaded by every portal page without special-casing.
   *
   * A sign-in link is optional rather than required. The scenario and
   * instructor pages sit behind the portal gate, so an anonymous visitor
   * never reaches them and their nav carries no sign-in link at all. */
  function mountIdentity() {
    var nameEl = document.querySelector("[data-auth-identity]");
    var inEl = document.querySelector("[data-auth-signin]");
    var outEl = document.querySelector("[data-auth-signout]");

    if (outEl) {
      outEl.addEventListener("click", function (event) {
        event.preventDefault();
        outEl.setAttribute("aria-busy", "true");
        outEl.disabled = true;
        signOut();
      });
    }

    return me().then(function (user) {
      paintIdentity(user, nameEl, inEl, outEl);
      return user;
    });
  }

  global.LabAuth = {
    me: me,
    register: register,
    login: login,
    logout: logout,
    signOut: signOut,
    safeNext: safeNext,
    paintIdentity: paintIdentity,
    mountIdentity: mountIdentity
  };

  /* Auto-mount on any portal page that carries the slot. */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      if (document.querySelector(
            "[data-auth-identity], [data-auth-signin], [data-auth-signout]")) {
        mountIdentity();
      }
    });
  } else if (document.querySelector(
      "[data-auth-identity], [data-auth-signin], [data-auth-signout]")) {
    mountIdentity();
  }
})(window);
