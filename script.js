// script.js

const STORAGE_KEY = "easyOtpSavedKeys";

const form = document.getElementById("totpForm");
const input = document.getElementById("totpInput");
const labelInput = document.getElementById("labelInput");
const saveCheckbox = document.getElementById("saveCheckbox");
const otpList = document.getElementById("otpList");
const emptyState = document.getElementById("emptyState");
const messageBox = document.getElementById("messageBox");

let savedEntries = [];
let tempEntries = [];

try {
  savedEntries = JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
} catch {
  savedEntries = [];
}

function saveEntries() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(savedEntries));
}

function showMessage(message, type = "success") {
  messageBox.innerHTML = `
    <div class="message message-${type}">
      ${message}
    </div>
  `;
}

function clearMessage() {
  messageBox.innerHTML = "";
}

function getNextLabel() {
  const all = [...savedEntries, ...tempEntries];

  let highest = 0;

  all.forEach(item => {
    const match = /^totp(\d+)$/i.exec(item.label || "");
    if (match) {
      highest = Math.max(highest, Number(match[1]));
    }
  });

  return `totp${highest + 1}`;
}

function parseInput(raw) {
  const value = raw.trim();

  // Plain Base32 secret
  if (
    !value.toLowerCase().startsWith("otpauth://") &&
    /^[A-Z2-7\s=]{16,}$/i.test(value)
  ) {
    return {
      secret: value.replace(/\s+/g, "").toUpperCase(),
      issuer: "",
      label: "",
      digits: 6,
      period: 30,
      algorithm: "SHA-1"
    };
  }

  let url;

  try {
    url = new URL(value);
  } catch {
    throw new Error("Enter a valid otpauth://totp/... string or Base32 secret.");
  }

  if (url.protocol !== "otpauth:") {
    throw new Error("The URI must start with otpauth://");
  }

  if (url.hostname.toLowerCase() !== "totp") {
    throw new Error("Only TOTP entries are supported.");
  }

  const secret = url.searchParams.get("secret");

  if (!secret) {
    throw new Error("No secret key was found.");
  }

  const rawPath = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
  const issuerParam = url.searchParams.get("issuer") || "";

  let issuer = issuerParam;
  let label = rawPath;

  if (rawPath.includes(":")) {
    const parts = rawPath.split(":");

    if (!issuer) {
      issuer = parts[0].trim();
    }

    label = parts.slice(1).join(":").trim();
  }

  const algorithmRaw = (url.searchParams.get("algorithm") || "SHA1")
    .toUpperCase()
    .replace("-", "");

  let algorithm = "SHA-1";

  if (algorithmRaw === "SHA256") {
    algorithm = "SHA-256";
  } else if (algorithmRaw === "SHA512") {
    algorithm = "SHA-512";
  }

  return {
    secret: secret.replace(/\s+/g, "").toUpperCase(),
    issuer,
    label,
    digits: Number(url.searchParams.get("digits") || 6),
    period: Number(url.searchParams.get("period") || 30),
    algorithm
  };
}

function base32ToBytes(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  const cleaned = secret
    .replace(/\s+/g, "")
    .replace(/=+$/g, "")
    .toUpperCase();

  if (!cleaned.length) {
    throw new Error("Secret key is empty.");
  }

  let bits = "";

  for (const char of cleaned) {
    const value = alphabet.indexOf(char);

    if (value === -1) {
      throw new Error(`Invalid character in secret: ${char}`);
    }

    bits += value.toString(2).padStart(5, "0");
  }

  const bytes = [];

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }

  return new Uint8Array(bytes);
}

async function generateOTP(entry) {
  const keyBytes = base32ToBytes(entry.secret);

  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / entry.period);

  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);

  view.setUint32(0, Math.floor(counter / 4294967296), false);
  view.setUint32(4, counter >>> 0, false);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    {
      name: "HMAC",
      hash: { name: entry.algorithm }
    },
    false,
    ["sign"]
  );

  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", cryptoKey, buffer)
  );

  const offset = signature[signature.length - 1] & 0x0f;

  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);

  const otp = binary % (10 ** entry.digits);

  return otp.toString().padStart(entry.digits, "0");
}

function secondsRemaining(period) {
  return period - (Math.floor(Date.now() / 1000) % period);
}

async function render() {
  const allEntries = [
    ...savedEntries.map(item => ({ ...item, saved: true })),
    ...tempEntries.map(item => ({ ...item, saved: false }))
  ];

  if (!allEntries.length) {
    emptyState.style.display = "block";
    otpList.innerHTML = "";
    return;
  }

  emptyState.style.display = "none";

  const html = await Promise.all(
    allEntries.map(async entry => {
      let code = "INVALID";

      try {
        code = await generateOTP(entry);
      } catch (err) {
        console.error("OTP error:", err, entry);
      }

      const remaining = secondsRemaining(entry.period);
      const progress = (remaining / entry.period) * 100;

      return `
        <div class="col-12 col-md-6">
          <div class="otp-card">
            <div class="otp-card-inner">

              <div class="d-flex justify-content-between gap-3">
                <div>
                  <div class="otp-title">${escapeHtml(entry.label)}</div>
                  <div class="otp-subtitle">
                    ${escapeHtml(entry.issuer || "No issuer")}
                  </div>
                </div>

                <div class="status-pill ${entry.saved ? "status-saved" : "status-temp"}">
                  ${entry.saved ? "Saved" : "Temporary"}
                </div>
              </div>

              <div class="otp-meta">
                <div class="meta-pill">${entry.digits} digits</div>
                <div class="meta-pill">${entry.period}s</div>
                <div class="meta-pill">${entry.algorithm}</div>
              </div>

              <div class="otp-code-wrap">
                <div class="otp-code ${code === "INVALID" ? "text-danger" : ""}">
                  ${code}
                </div>

                <div class="progress-bar-wrap">
                  <div class="progress-bar-inner" style="width:${progress}%"></div>
                </div>

                <div class="otp-timer">
                  Refreshes in ${remaining}s
                </div>
              </div>

              <div class="otp-actions">
                <button
                  class="btn btn-primary btn-sm"
                  onclick="copyCode('${code}')"
                  ${code === "INVALID" ? "disabled" : ""}
                >
                  <i class="fa-solid fa-copy me-1"></i>
                  Copy
                </button>

                <button
                  class="btn btn-outline-danger btn-sm"
                  onclick="deleteEntry('${entry.id}', ${entry.saved})"
                >
                  <i class="fa-solid fa-trash me-1"></i>
                  Delete
                </button>
              </div>

            </div>
          </div>
        </div>
      `;
    })
  );

  otpList.innerHTML = html.join("");
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

window.copyCode = async function(code) {
  try {
    await navigator.clipboard.writeText(code);
    showMessage(`Copied: <strong>${code}</strong>`);
  } catch {
    showMessage("Could not copy the OTP code.", "error");
  }
};

window.deleteEntry = function(id, saved) {
  if (saved) {
    savedEntries = savedEntries.filter(item => item.id !== id);
    saveEntries();
  } else {
    tempEntries = tempEntries.filter(item => item.id !== id);
  }

  render();
};

form.addEventListener("submit", async e => {
  e.preventDefault();
  clearMessage();

  try {
    const parsed = parseInput(input.value);

    const entry = {
      id: crypto.randomUUID(),
      label:
        labelInput.value.trim() ||
        parsed.label ||
        getNextLabel(),
      issuer: parsed.issuer,
      secret: parsed.secret,
      digits: parsed.digits || 6,
      period: parsed.period || 30,
      algorithm: parsed.algorithm || "SHA-1"
    };

    // Test immediately before saving
    await generateOTP(entry);

    if (saveCheckbox.checked) {
      savedEntries.push(entry);
      saveEntries();
    } else {
      tempEntries.push(entry);
    }

    form.reset();
    saveCheckbox.checked = true;

    showMessage(`Added <strong>${escapeHtml(entry.label)}</strong>.`);
    render();
  } catch (err) {
    console.error(err);
    showMessage(err.message || "Could not add this TOTP.", "error");
  }
});

document.getElementById("clearFormBtn").addEventListener("click", () => {
  form.reset();
  saveCheckbox.checked = true;
  clearMessage();
});

document.getElementById("refreshBtn").addEventListener("click", render);

document.getElementById("clearSavedBtn").addEventListener("click", () => {
  if (!confirm("Delete all saved entries from browser storage?")) {
    return;
  }

  savedEntries = [];
  saveEntries();
  render();
  showMessage("All saved entries were deleted.");
});

setInterval(render, 1000);

render();