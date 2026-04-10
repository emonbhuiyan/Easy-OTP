// script.js
const STORAGE_KEY = "easyOtpSavedKeys";

const form = document.getElementById("totpForm");
const input = document.getElementById("totpInput");
const labelInput = document.getElementById("labelInput");
const saveCheckbox = document.getElementById("saveCheckbox");
const otpList = document.getElementById("otpList");
const emptyState = document.getElementById("emptyState");
const messageBox = document.getElementById("messageBox");

let savedEntries = loadSavedEntries();
let temporaryEntries = [];

function loadSavedEntries() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
  } catch {
    return [];
  }
}

function saveEntries() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(savedEntries));
}

function showMessage(text, type = "success") {
  messageBox.innerHTML = `
    <div class="message message-${type}">
      ${text}
    </div>
  `;
}

function clearMessage() {
  messageBox.innerHTML = "";
}

function nextLabel() {
  const all = [...savedEntries, ...temporaryEntries];
  let highest = 0;

  all.forEach(item => {
    const match = /^totp(\d+)$/i.exec(item.label || "");
    if (match) highest = Math.max(highest, Number(match[1]));
  });

  return `totp${highest + 1}`;
}

function parseInput(value) {
  const text = value.trim();

  // plain Base32 secret support
  if (
    !text.toLowerCase().startsWith("otpauth://") &&
    /^[A-Z2-7]{16,}$/i.test(text.replace(/\s+/g, ""))
  ) {
    return {
      secret: text.replace(/\s+/g, "").toUpperCase(),
      issuer: "",
      label: "",
      algorithm: "SHA1",
      digits: 6,
      period: 30
    };
  }

  let url;

  try {
    url = new URL(text);
  } catch {
    throw new Error("Enter a valid otpauth://totp/... string or Base32 secret.");
  }

  if (url.protocol !== "otpauth:") {
    throw new Error("The string must begin with otpauth://");
  }

  if (url.hostname.toLowerCase() !== "totp") {
    throw new Error("Only TOTP format is supported.");
  }

  const secret = url.searchParams.get("secret");

  if (!secret) {
    throw new Error("No secret was found.");
  }

  const path = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
  const issuerParam = url.searchParams.get("issuer") || "";

  let issuer = issuerParam;
  let label = path;

  if (path.includes(":")) {
    const parts = path.split(":");

    if (!issuer) issuer = parts[0].trim();
    label = parts.slice(1).join(":").trim();
  }

  return {
    secret: secret.replace(/\s+/g, "").toUpperCase(),
    issuer,
    label,
    algorithm: (url.searchParams.get("algorithm") || "SHA1").toUpperCase(),
    digits: Number(url.searchParams.get("digits") || 6),
    period: Number(url.searchParams.get("period") || 30)
  };
}

function base32ToBytes(base32) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = base32.replace(/=+$/, "").toUpperCase();

  let bits = "";

  for (const c of cleaned) {
    const val = chars.indexOf(c);
    if (val === -1) throw new Error("Invalid Base32 secret.");
    bits += val.toString(2).padStart(5, "0");
  }

  const bytes = [];

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }

  return new Uint8Array(bytes);
}

async function generateCode(entry) {
  const secretBytes = base32ToBytes(entry.secret);

  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / entry.period);

  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);

  view.setUint32(0, Math.floor(counter / 4294967296));
  view.setUint32(4, counter);

  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    {
      name: "HMAC",
      hash: { name: entry.algorithm }
    },
    false,
    ["sign"]
  );

  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, buffer)
  );

  const offset = signature[signature.length - 1] & 0x0f;

  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);

  return (binary % (10 ** entry.digits))
    .toString()
    .padStart(entry.digits, "0");
}

function secondsRemaining(period) {
  return period - (Math.floor(Date.now() / 1000) % period);
}

async function render() {
  const allEntries = [
    ...savedEntries.map(x => ({ ...x, saved: true })),
    ...temporaryEntries.map(x => ({ ...x, saved: false }))
  ];

  if (!allEntries.length) {
    emptyState.style.display = "block";
    otpList.innerHTML = "";
    return;
  }

  emptyState.style.display = "none";

  const cards = await Promise.all(
    allEntries.map(async entry => {
      let code = "------";

      try {
        code = await generateCode(entry);
      } catch {
        code = "ERROR";
      }

      const remaining = secondsRemaining(entry.period);
      const progress = (remaining / entry.period) * 100;

      return `
        <div class="col-md-6">
          <div class="otp-card">
            <div class="otp-card-inner">
              <div class="d-flex justify-content-between gap-3">
                <div>
                  <div class="otp-title">${entry.label}</div>
                  <div class="otp-subtitle">${entry.issuer || "No issuer"}</div>
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
                <div class="otp-code">${code}</div>

                <div class="progress-bar-wrap">
                  <div class="progress-bar-inner" style="width:${progress}%"></div>
                </div>

                <div class="otp-timer">
                  Refreshes in ${remaining}s
                </div>
              </div>

              <div class="otp-actions">
                <button class="btn btn-primary btn-sm" onclick="copyCode('${code}')">
                  <i class="fa-solid fa-copy me-1"></i>
                  Copy
                </button>

                <button class="btn btn-outline-danger btn-sm" onclick="removeEntry('${entry.id}', ${entry.saved})">
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

  otpList.innerHTML = cards.join("");
}

window.copyCode = async function(code) {
  try {
    await navigator.clipboard.writeText(code);
    showMessage(`Copied OTP code: <strong>${code}</strong>`);
  } catch {
    showMessage("Could not copy the OTP code.", "error");
  }
};

window.removeEntry = function(id, saved) {
  if (saved) {
    savedEntries = savedEntries.filter(x => x.id !== id);
    saveEntries();
  } else {
    temporaryEntries = temporaryEntries.filter(x => x.id !== id);
  }

  render();
};

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearMessage();

  try {
    const parsed = parseInput(input.value);

    const finalLabel =
      labelInput.value.trim() ||
      parsed.label ||
      nextLabel();

    const entry = {
      id: crypto.randomUUID(),
      label: finalLabel,
      issuer: parsed.issuer,
      secret: parsed.secret,
      algorithm: parsed.algorithm,
      digits: parsed.digits,
      period: parsed.period
    };

    if (saveCheckbox.checked) {
      savedEntries.push(entry);
      saveEntries();
    } else {
      temporaryEntries.push(entry);
    }

    form.reset();
    saveCheckbox.checked = true;

    showMessage(`Added <strong>${finalLabel}</strong>.`);
    render();
  } catch (err) {
    showMessage(err.message, "error");
  }
});

document.getElementById("clearFormBtn").addEventListener("click", () => {
  form.reset();
  saveCheckbox.checked = true;
  clearMessage();
});

document.getElementById("refreshBtn").addEventListener("click", render);

document.getElementById("clearSavedBtn").addEventListener("click", () => {
  if (!confirm("Delete all saved OTP entries from browser storage?")) return;

  savedEntries = [];
  saveEntries();
  render();
  showMessage("All saved entries were deleted.");
});

setInterval(render, 1000);
render();