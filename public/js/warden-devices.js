/**
 * Warden: per-device revoke on Settings → Devices.
 *
 * Upstream Bitwarden web vault ships device management without a remove button
 * (session de-auth was unfinished). Vaultwarden has no single-device API either.
 * This overlay adds a revoke control that calls DELETE /api/devices/{id}
 * (Bitwarden-compatible; also accepts POST .../deactivate).
 *
 * Applied at build time: copied into public/web-vault/js/ and injected into index.html.
 */
(function () {
  "use strict";

  var AUTH_HEADER = null;
  var DEVICES = [];
  var CURRENT_IDENTIFIER = null;
  var PANEL_ID = "warden-device-revoke-panel";
  var DEVICE_TYPES = {
    0: "Android",
    1: "iOS",
    2: "Chrome Extension",
    3: "Firefox Extension",
    4: "Opera Extension",
    5: "Edge Extension",
    6: "Windows",
    7: "macOS",
    8: "Linux",
    9: "Chrome",
    10: "Firefox",
    11: "Opera",
    12: "Edge",
    13: "Internet Explorer",
    14: "Unknown Browser",
    15: "Android",
    16: "UWP",
    17: "Safari",
    18: "Vivaldi",
    19: "Vivaldi Extension",
    20: "Safari Extension",
    21: "SDK",
    22: "Server",
    23: "Windows CLI",
    24: "macOS CLI",
    25: "Linux CLI",
    26: "DuckDuckGo",
  };

  function headerGet(headers, name) {
    if (!headers) return null;
    if (typeof headers.get === "function") {
      return headers.get(name) || headers.get(name.toLowerCase());
    }
    var key = Object.keys(headers).find(function (k) {
      return k.toLowerCase() === name.toLowerCase();
    });
    return key ? headers[key] : null;
  }

  function captureAuth(headers) {
    var auth = headerGet(headers, "Authorization");
    if (auth && /^Bearer\s+/i.test(auth)) {
      AUTH_HEADER = auth;
    }
    var deviceId = headerGet(headers, "Device-Identifier");
    if (deviceId) {
      CURRENT_IDENTIFIER = deviceId;
    }
  }

  function normalizeUrl(input) {
    try {
      if (typeof input === "string") return new URL(input, location.origin);
      if (input && input.url) return new URL(input.url, location.origin);
    } catch (_) {}
    return null;
  }

  function isDevicesListUrl(url) {
    if (!url) return false;
    var path = url.pathname.replace(/\/+$/, "");
    return path === "/api/devices" || path === "/devices";
  }

  function isDeviceManagementRoute() {
    var hash = location.hash || "";
    return /\/settings\/security\/device-management\/?$/.test(hash);
  }

  function deviceLabel(device) {
    var typeName = DEVICE_TYPES[device.type] || "Device";
    var name = (device.name || "").trim();
    if (name && name.toLowerCase() !== typeName.toLowerCase()) {
      return typeName + " — " + name;
    }
    return typeName;
  }

  function formatDate(iso) {
    if (!iso) return "";
    try {
      return new Date(iso).toLocaleString();
    } catch (_) {
      return String(iso);
    }
  }

  function rememberDevices(payload) {
    var list = Array.isArray(payload)
      ? payload
      : payload && Array.isArray(payload.data)
        ? payload.data
        : null;
    if (!list) return;
    DEVICES = list
      .map(function (d) {
        return {
          id: d.id || d.identifier,
          identifier: d.identifier || d.id,
          name: d.name,
          type: d.type,
          creationDate: d.creationDate,
        };
      })
      .filter(function (d) {
        return d.id;
      });
    scheduleRender();
  }

  async function revokeDevice(deviceId) {
    if (!AUTH_HEADER) {
      throw new Error("Not signed in (missing auth). Refresh the page and try again.");
    }
    var res = await fetch("/api/devices/" + encodeURIComponent(deviceId), {
      method: "DELETE",
      headers: {
        Authorization: AUTH_HEADER,
        Accept: "application/json",
      },
    });
    if (!res.ok) {
      var body = "";
      try {
        body = await res.text();
      } catch (_) {}
      throw new Error("Revoke failed (" + res.status + ")" + (body ? ": " + body : ""));
    }
  }

  var PANEL_VERSION = "";

  function panelSignature() {
    return (
      DEVICES.map(function (d) {
        return d.id;
      }).join(",") +
      "|" +
      (AUTH_HEADER ? "1" : "0") +
      "|" +
      (CURRENT_IDENTIFIER || "")
    );
  }

  function removePanel() {
    var existing = document.getElementById(PANEL_ID);
    if (existing) existing.remove();
    PANEL_VERSION = "";
  }

  function renderPanel() {
    if (!isDeviceManagementRoute()) {
      removePanel();
      return;
    }

    var host =
      document.querySelector("auth-device-management") ||
      document.querySelector("app-device-management");
    if (!host) return;

    var sig = panelSignature();
    var existing = document.getElementById(PANEL_ID);
    if (existing && PANEL_VERSION === sig) return;

    if (existing) existing.remove();

    var panel = document.createElement("section");
    panel.id = PANEL_ID;
    panel.className = "warden-device-revoke";
    panel.setAttribute("aria-label", "Revoke device sessions");

    var title = document.createElement("h2");
    title.className = "warden-device-revoke__title";
    title.textContent = "Revoke a device";
    panel.appendChild(title);

    var help = document.createElement("p");
    help.className = "warden-device-revoke__help";
    help.textContent =
      "Ends that device’s session (refresh token removed). Other devices stay signed in. Deauthorize sessions still logs out everywhere.";
    panel.appendChild(help);

    if (!DEVICES.length) {
      var empty = document.createElement("p");
      empty.className = "warden-device-revoke__empty";
      empty.textContent = AUTH_HEADER
        ? "No devices loaded yet. Wait for the list above, then reopen this page if needed."
        : "Waiting for an authenticated API call to capture your session…";
      panel.appendChild(empty);
      host.appendChild(panel);
      PANEL_VERSION = sig;
      return;
    }

    var list = document.createElement("ul");
    list.className = "warden-device-revoke__list";

    DEVICES.forEach(function (device) {
      var li = document.createElement("li");
      li.className = "warden-device-revoke__row";

      var meta = document.createElement("div");
      meta.className = "warden-device-revoke__meta";

      var nameEl = document.createElement("div");
      nameEl.className = "warden-device-revoke__name";
      nameEl.textContent = deviceLabel(device);
      if (
        CURRENT_IDENTIFIER &&
        (device.identifier === CURRENT_IDENTIFIER || device.id === CURRENT_IDENTIFIER)
      ) {
        var badge = document.createElement("span");
        badge.className = "warden-device-revoke__badge";
        badge.textContent = "This browser";
        nameEl.appendChild(document.createTextNode(" "));
        nameEl.appendChild(badge);
      }
      meta.appendChild(nameEl);

      var sub = document.createElement("div");
      sub.className = "warden-device-revoke__sub";
      sub.textContent = formatDate(device.creationDate) || device.id;
      meta.appendChild(sub);

      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "warden-device-revoke__btn";
      btn.textContent = "Revoke";
      btn.addEventListener("click", function () {
        var isSelf =
          CURRENT_IDENTIFIER &&
          (device.identifier === CURRENT_IDENTIFIER || device.id === CURRENT_IDENTIFIER);
        var msg = isSelf
          ? "Revoke this browser’s session? You will be signed out here."
          : "Revoke “" + deviceLabel(device) + "”? That device will need to sign in again.";
        if (!window.confirm(msg)) return;
        btn.disabled = true;
        btn.textContent = "Revoking…";
        revokeDevice(device.id)
          .then(function () {
            DEVICES = DEVICES.filter(function (d) {
              return d.id !== device.id;
            });
            if (isSelf) {
              location.href = "/#/login";
              location.reload();
              return;
            }
            location.reload();
          })
          .catch(function (err) {
            btn.disabled = false;
            btn.textContent = "Revoke";
            window.alert(err && err.message ? err.message : String(err));
          });
      });

      li.appendChild(meta);
      li.appendChild(btn);
      list.appendChild(li);
    });

    panel.appendChild(list);
    host.appendChild(panel);
    PANEL_VERSION = sig;
  }

  var renderTimer = null;
  function scheduleRender() {
    if (renderTimer) clearTimeout(renderTimer);
    renderTimer = setTimeout(renderPanel, 200);
  }

  // Capture Authorization + device list from the vault’s own API traffic.
  if (typeof window.fetch === "function") {
    var origFetch = window.fetch;
    window.fetch = function () {
      var args = arguments;
      var input = args[0];
      var init = args[1] || {};
      var url = normalizeUrl(input);
      try {
        captureAuth(init.headers);
        if (input && typeof input === "object" && input.headers) {
          captureAuth(input.headers);
        }
      } catch (_) {}

      return origFetch.apply(this, args).then(function (res) {
        try {
          if (url && isDevicesListUrl(url) && res.ok) {
            res
              .clone()
              .json()
              .then(rememberDevices)
              .catch(function () {});
          }
        } catch (_) {}
        return res;
      });
    };
  }

  window.addEventListener("hashchange", scheduleRender);
  var observer = new MutationObserver(scheduleRender);
  if (document.documentElement) {
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }
  scheduleRender();
})();
