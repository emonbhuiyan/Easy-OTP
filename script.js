const STORAGE_KEY = "easyOtpSavedKeys";

const form = document.getElementById("totpForm");
const input = document.getElementById("totpInput");
const labelInput = document.getElementById("labelInput");
const saveCheckbox = document.getElementById("saveCheckbox");
const otpList = document.getElementById("otpList");
const otpSection = document.getElementById("otpSection");
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

function nextLabel() {
  const all = [...savedEntries, ...tempEntries];
  let highest = 0;

  all.forEach(item => {
    const match = /^totp(\d+)$/i.exec(item.label || "");
    if (match) highest = Math.max(highest, Number(match[1]));
  });

  return `totp${highest + 1}`;
}

function parseInput(raw) {
  const value = raw.trim();

  if (
    !value.toLowerCase().startsWith("otpauth://") &&
    /^[A-Z2-7\s=]{16,}$/i.test(value)
  ) {
    return {
      secret: value.replace(/\s+/g, "").toUpperCase(),
      label: "",
      issuer: "",
      digits: 6,
      period: 30,
      algorithm: "SHA-1"
    };
  }

  const url = new URL(value);

  const algorithmRaw = (url.searchParams.get("algorithm") || "SHA1")
    .toUpperCase()
    .replace("-", "");

  let algorithm = "SHA-1";
  if (algorithmRaw === "SHA256") algorithm = "SHA-256";
  if (algorithmRaw === "SHA512") algorithm = "SHA-512";

  return {
    secret: (url.searchParams.get("secret") || "").replace(/\s+/g, "").toUpperCase(),
    label: decodeURIComponent(url.pathname.replace(/^\/+/, "")).split(":").slice(1).join(":"),
    issuer: url.searchParams.get("issuer") || "",
    digits: Number(url.searchParams.get("digits") || 6),
    period: Number(url.searchParams.get("period") || 30),
    algorithm
  };
}

function base32ToBytes(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = secret.replace(/=+$/, "").toUpperCase();

  let bits = "";

  for (const char of cleaned) {
    const val = alphabet.indexOf(char);
    if (val === -1) throw new Error("Invalid secret");
    bits += val.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return new Uint8Array(bytes);
}

async function generateCode(entry) {
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

  return (binary % (10 ** entry.digits)).toString().padStart(entry.digits, "0");
}

async function render() {
  const all = [
    ...savedEntries.map(x => ({ ...x, saved: true })),
    ...tempEntries.map(x => ({ ...x, saved: false }))
  ];

  if (!all.length) {
    otpSection.classList.add("d-none");
    otpList.innerHTML = "";
    return;
  }

  otpSection.classList.remove("d-none");

  const html = await Promise.all(all.map(async entry => {
    let code = "INVALID";

    try {
      code = await generateCode(entry);
    } catch {}

    const remaining = entry.period - (Math.floor(Date.now() / 1000) % entry.period);

    return `
      <div class="col-12 col-md-6">
        <div class="otp-card">
          <div class="otp-card-inner">

            <div class="otp-card-top">
              <div>
                <div class="otp-title">${entry.label || "Unnamed"}</div>
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
                <div class="progress-bar-inner" style="width:${(remaining / entry.period) * 100}%"></div>
              </div>

              <div class="otp-timer">
                Refreshes in ${remaining}s
              </div>
            </div>

            <div class="otp-actions">
              <button class="btn btn-outline-primary btn-sm" onclick="navigator.clipboard.writeText('${code}')">
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
  }));

  otpList.innerHTML = html.join("");
}

window.removeEntry = function(id, saved) {
  if (saved) {
    savedEntries = savedEntries.filter(x => x.id !== id);
    saveEntries();
  } else {
    tempEntries = tempEntries.filter(x => x.id !== id);
  }

  render();
};

form.addEventListener("submit", async e => {
  e.preventDefault();

  try {
    const parsed = parseInput(input.value);

    const entry = {
      id: crypto.randomUUID(),
      label: labelInput.value.trim() || parsed.label || nextLabel(),
      issuer: parsed.issuer,
      secret: parsed.secret,
      digits: parsed.digits,
      period: parsed.period,
      algorithm: parsed.algorithm
    };

    if (saveCheckbox.checked) {
      savedEntries.unshift(entry);
      saveEntries();
    } else {
      tempEntries.unshift(entry);
    }

    form.reset();
    saveCheckbox.checked = true;

    showMessage(`Added ${entry.label}.`);
    render();

  } catch {
    showMessage("Invalid TOTP URI or secret key.", "error");
  }
});

document.getElementById("refreshBtn").addEventListener("click", render);

document.getElementById("clearSavedBtn").addEventListener("click", () => {
  savedEntries = [];
  saveEntries();
  render();
});

document.getElementById("clearFormBtn").addEventListener("click", () => {
  form.reset();
});

setInterval(render, 1000);
render();