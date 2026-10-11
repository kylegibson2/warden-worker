/**
 * Warden: build versions at the bottom of the account menu.
 *
 * Upstream Bitwarden's account menu (web-vault: src/app/layouts/header/
 * account-menu.component.html) ends at "Log out" with no build information, so
 * when self-hosting there is no way to tell which Worker deploy or which web
 * vault revision you are actually served. This overlay appends a divider plus a
 * muted line to the open menu:
 *
 *     Warden v0.7.2 · Web vault v2026.6.4
 *
 * Version sources (both fetched once, lazily, then cached in memory):
 * - Warden Worker release -> GET /api/config  `wardenVersion` (CARGO_PKG_VERSION)
 * - Vaultwarden web vault -> GET /version.json shipped by bw_web_builds
 *
 * The menu is an Angular CDK overlay that is created on open and destroyed on
 * close, so this injects into the freshly rendered DOM each time and does not
 * attempt to patch any component state.
 *
 * Applied at build time: copied into public/web-vault/js/ and injected into index.html.
 */
(function () {
  "use strict";

  var FOOTER_ID = "warden-version-footer";
  var DIVIDER_ID = "warden-version-divider";
  var CONFIG_URL = "/api/config";
  var WEB_VAULT_VERSION_URL = "/version.json";
  var SEPARATOR = " \u00b7 ";

  var versions = { warden: null, webVault: null };

  function fetchJson(url) {
    return fetch(url, {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    })
      .then(function (res) {
        if (!res || !res.ok) return null;
        return res.json().catch(function () {
          return null;
        });
      })
      .catch(function () {
        return null;
      });
  }

  function asText(value) {
    return typeof value === "string" && value.trim() ? value.trim() : null;
  }

  function withPrefixV(value) {
    if (!value) return null;
    return /^v/i.test(value) ? value : "v" + value;
  }

  function loadVersions() {
    fetchJson(CONFIG_URL).then(function (config) {
      if (config) {
        versions.warden = asText(config.wardenVersion);
      }
      scheduleRender();
    });

    fetchJson(WEB_VAULT_VERSION_URL).then(function (meta) {
      if (meta) {
        versions.webVault = asText(meta.version);
      }
      scheduleRender();
    });
  }

  function footerText() {
    var parts = [];
    var warden = withPrefixV(versions.warden);
    var webVault = withPrefixV(versions.webVault);
    if (warden) parts.push("Warden " + warden);
    if (webVault) parts.push("Web vault " + webVault);
    return parts.join(SEPARATOR);
  }

  function closestButton(element) {
    var node = element;
    while (node && node.tagName !== "BUTTON") {
      node = node.parentElement;
    }
    return node && node.tagName === "BUTTON" ? node : null;
  }

  /**
   * The account menu is the only CDK menu overlay containing a Log out item
   * (`<i class="bwi bwi-fw bwi-sign-out">`). Its template renders the menu items
   * as direct children of one flex column wrapper, so that wrapper is the
   * insertion point.
   */
  function findAccountMenuWrapper() {
    var panes = document.querySelectorAll(".cdk-overlay-pane");
    for (var i = 0; i < panes.length; i++) {
      var logoutIcon = panes[i].querySelector("i.bwi-sign-out");
      if (!logoutIcon) continue;
      var logoutItem = closestButton(logoutIcon);
      if (logoutItem && logoutItem.parentElement) {
        return logoutItem.parentElement;
      }
    }
    return null;
  }

  function removeFooter() {
    var ids = [FOOTER_ID, DIVIDER_ID];
    for (var i = 0; i < ids.length; i++) {
      var node = document.getElementById(ids[i]);
      if (node) node.remove();
    }
  }

  function render() {
    var text = footerText();
    var wrapper = findAccountMenuWrapper();

    // Menu is closed, or no version has resolved yet: drop any stale nodes.
    if (!wrapper || !text) {
      removeFooter();
      return;
    }

    var existing = document.getElementById(FOOTER_ID);
    if (existing && existing.parentElement === wrapper) {
      if (existing.textContent !== text) existing.textContent = text;
      return;
    }
    removeFooter();

    // Mirror bit-menu-divider + the self-hosted hostname line so the footer
    // inherits the vault's own theme (light/dark) without extra CSS.
    var divider = document.createElement("div");
    divider.id = DIVIDER_ID;
    divider.className = "tw-h-px tw-w-full tw-my-2 tw-bg-border-base";
    divider.setAttribute("role", "separator");

    var footer = document.createElement("div");
    footer.id = FOOTER_ID;
    footer.className = "warden-version tw-break-all tw-px-4 tw-py-1 tw-text-left tw-text-muted";
    footer.textContent = text;
    footer.title = text;

    wrapper.appendChild(divider);
    wrapper.appendChild(footer);
  }

  var renderTimer = null;
  function scheduleRender() {
    if (renderTimer) clearTimeout(renderTimer);
    renderTimer = setTimeout(render, 200);
  }

  // The overlay is transient, so re-check on any DOM change and on route changes.
  window.addEventListener("hashchange", scheduleRender);
  var observer = new MutationObserver(scheduleRender);
  if (document.documentElement) {
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  loadVersions();
})();
