// static/js/script.js
// ------------------
// Core logic for Client-Side End-to-End Encryption (E2EE) and Blockchain UI.

document.addEventListener("DOMContentLoaded", function () {
    // Automatically dismiss flash alerts
    const alerts = document.querySelectorAll(".alert");
    alerts.forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 5000);
    });

    // Check if we are on the dashboard
    if (typeof window.CURRENT_USER !== "undefined") {
        initDashboard();
    }
});

// -------------------------------------------------------------------------
// GLOBAL STATE
// -------------------------------------------------------------------------
let myPrivateKey = null;
let myPublicKeyPEM = null;
let mySigningPrivKey = null;   // RSA-PSS signing key (NEW)
let activeRecipient = null;
let activeRecipientPublicKey = null;
let chatRefreshInterval = null;
let blockchainBlocks = [];

// Helper functions for Base64 conversions
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

function chunkString(str, length) {
    const matches = str.match(new RegExp('.{1,' + length + '}', 'g'));
    return matches ? matches.join('\n') : str;
}

// -------------------------------------------------------------------------
// CRYPTOGRAPHY UTILITIES (Web Crypto API)
// -------------------------------------------------------------------------

// Generate 2048-bit RSA-OAEP Key Pair (for encryption/decryption)
async function generateRSAKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: { name: "SHA-256" }
        },
        true,
        ["encrypt", "decrypt"]
    );
}

// Generate 2048-bit RSA-PSS Key Pair (for digital signing)
async function generateRSASigningKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: { name: "SHA-256" }
        },
        true,
        ["sign", "verify"]
    );
}

// Sign a message string using RSA-PSS private key → base64 signature
async function signMessage(signingPrivateKey, message) {
    try {
        const data      = new TextEncoder().encode(message);
        const signature = await window.crypto.subtle.sign(
            { name: "RSA-PSS", saltLength: 32 },
            signingPrivateKey,
            data
        );
        return arrayBufferToBase64(signature);
    } catch(e) {
        console.warn("Signing failed:", e);
        return null;
    }
}

// SHA-256 hash of a string (returns hex)
async function sha256Hex(str) {
    const buf  = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
}

// Export RSA-PSS Private Key to JWK
async function exportSigningPrivKeyJWK(key) {
    return JSON.stringify(await window.crypto.subtle.exportKey("jwk", key));
}

// Import RSA-PSS Private Key from JWK
async function importSigningPrivKeyJWK(jwkString) {
    return await window.crypto.subtle.importKey(
        "jwk",
        JSON.parse(jwkString),
        { name: "RSA-PSS", hash: { name: "SHA-256" } },
        true,
        ["sign"]
    );
}

// Export Public Key to SPKI PEM format
async function exportPublicKeyPEM(key) {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    const b64 = arrayBufferToBase64(exported);
    return `-----BEGIN PUBLIC KEY-----\n${chunkString(b64, 64)}\n-----END PUBLIC KEY-----`;
}

// Export Private Key to JWK JSON String
async function exportPrivateKeyJWK(key) {
    const jwk = await window.crypto.subtle.exportKey("jwk", key);
    return JSON.stringify(jwk);
}

// Import Private Key from JWK String
async function importPrivateKeyJWK(jwkString) {
    const jwk = JSON.parse(jwkString);
    return await window.crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "RSA-OAEP",
            hash: { name: "SHA-256" }
        },
        true,
        ["decrypt"]
    );
}

// Import Public Key from SPKI PEM String
async function importPublicKeyPEM(pem) {
    const cleanPem = pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/\s/g, "");
    const buffer = base64ToArrayBuffer(cleanPem);
    return await window.crypto.subtle.importKey(
        "spki",
        buffer,
        {
            name: "RSA-OAEP",
            hash: { name: "SHA-256" }
        },
        true,
        ["encrypt"]
    );
}

// Encrypt plaintext using imported Public Key
async function encryptData(publicKey, plaintext) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        data
    );
    return arrayBufferToBase64(encrypted);
}

// Decrypt ciphertext using imported Private Key
async function decryptData(privateKey, ciphertextBase64) {
    try {
        const data = base64ToArrayBuffer(ciphertextBase64);
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            data
        );
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (err) {
        console.error("Decryption failed:", err);
        return "[Decryption Error: Key mismatch or payload modified]";
    }
}

// =========================================================================
// VAULT: AES-GCM + PBKDF2 — Client-side key encryption for server backup
// =========================================================================

// Derive a 256-bit AES key from a PIN using PBKDF2
async function deriveVaultKey(pin, saltBase64) {
    const enc     = new TextEncoder();
    const keyMat  = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
    const salt    = saltBase64 ? base64ToArrayBuffer(saltBase64) : crypto.getRandomValues(new Uint8Array(16)).buffer;
    const aesKey  = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
        keyMat,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
    return { aesKey, salt: arrayBufferToBase64(salt) };
}

// Encrypt a plaintext string with AES-GCM. Returns JSON {salt, iv, data}
async function vaultEncrypt(pin, plaintext) {
    const { aesKey, salt } = await deriveVaultKey(pin, null);
    const iv        = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        new TextEncoder().encode(plaintext)
    );
    return JSON.stringify({
        salt,
        iv:   arrayBufferToBase64(iv.buffer),
        data: arrayBufferToBase64(encrypted)
    });
}

// Decrypt a vault blob. Throws on wrong PIN.
async function vaultDecrypt(pin, blob) {
    const { salt, iv, data } = JSON.parse(blob);
    const { aesKey } = await deriveVaultKey(pin, salt);
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64ToArrayBuffer(iv) },
        aesKey,
        base64ToArrayBuffer(data)
    );
    return new TextDecoder().decode(decrypted);
}

// Promise-based modal PIN prompt helper
function waitForVaultSetupPin() {
    return new Promise((resolve, reject) => {
        const modal      = new bootstrap.Modal(document.getElementById('setupVaultModal'));
        const confirmBtn = document.getElementById('confirm-vault-setup-btn');
        const cancelBtn  = document.getElementById('cancel-vault-setup-btn');
        const pinInput   = document.getElementById('vault-pin-input');
        const errEl      = document.getElementById('vault-pin-error');
        pinInput.value = '';
        if (errEl) errEl.style.display = 'none';
        modal.show();
        const onConfirm = () => {
            const pin = pinInput.value.trim();
            if (pin.length < 6) {
                if (errEl) errEl.style.display = 'block';
                return;
            }
            cleanup();
            modal.hide();
            resolve(pin);
        };
        const onCancel = () => { cleanup(); modal.hide(); reject(new Error('Cancelled')); };
        const onEnter  = (e) => { if (e.key === 'Enter') onConfirm(); };
        function cleanup() {
            confirmBtn.removeEventListener('click', onConfirm);
            if (cancelBtn) cancelBtn.removeEventListener('click', onCancel);
            pinInput.removeEventListener('keydown', onEnter);
        }
        confirmBtn.addEventListener('click', onConfirm);
        if (cancelBtn) cancelBtn.addEventListener('click', onCancel);
        pinInput.addEventListener('keydown', onEnter);
        // Focus input after modal animates in
        document.getElementById('setupVaultModal').addEventListener('shown.bs.modal', () => pinInput.focus(), { once: true });
    });
}

// =========================================================================
// DASHBOARD CONTROLLER
// =========================================================================
async function initDashboard() {
    const username = window.CURRENT_USER;
    
    // Wire up UI buttons
    const initializeBtn = document.getElementById("initialize-keys-btn");
    const auditBtn      = document.getElementById("btn-audit-chain");
    const tamperBtn     = document.getElementById("btn-tamper-db");
    if (initializeBtn) initializeBtn.addEventListener("click", handleInitializeKeys);
    if (auditBtn)      auditBtn.addEventListener("click", runBlockchainAudit);
    if (tamperBtn)     tamperBtn.addEventListener("click", simulateDatabaseTampering);

    // ── Step 1: Try loading keys from localStorage (fast path) ──
    const savedPrivKey  = localStorage.getItem(`secure_msg_priv_key_${username}`);
    const savedPubKey   = localStorage.getItem(`secure_msg_pub_key_${username}`);
    const savedSignPriv = localStorage.getItem(`secure_msg_sign_priv_${username}`);

    if (savedPrivKey && savedPubKey) {
        try {
            myPrivateKey   = await importPrivateKeyJWK(savedPrivKey);
            myPublicKeyPEM = savedPubKey;
            if (savedSignPriv) mySigningPrivKey = await importSigningPrivKeyJWK(savedSignPriv);
            updateKeyUIStatus(true);
        } catch (e) {
            console.error("Failed to import saved keys from localStorage:", e);
            localStorage.removeItem(`secure_msg_priv_key_${username}`);
            updateKeyUIStatus(false);
        }
    } else {
        // ── Step 2: localStorage empty — check server for encrypted vault backup ──
        updateKeyUIStatus(false);
        try {
            const resp = await fetch("/api/keys/download");
            if (resp.ok) {
                const vaultData = await resp.json();
                if (vaultData.encrypted_private_key) {
                    // Encrypted backup exists — ask user for PIN to unlock
                    await unlockVaultFromServer(username, vaultData);
                }
            }
        } catch (e) {
            console.warn("Could not check server vault:", e);
        }
    }

    // Initial data fetch
    await fetchContacts();
    await fetchBlockchainBlocks();

    // Initialize Socket.IO for real-time messaging
    if (typeof io !== "undefined") {
        const socket = io();
        socket.on("connected", (data) => console.log("Socket connected:", data));
        socket.on("new_message", (block) => {
            fetchBlockchainBlocks();
            if (activeRecipient && (block.sender === activeRecipient || block.recipient === activeRecipient)) {
                fetchChatHistory(false);
            }
        });
    }
}

// Unlock vault from server-side encrypted backup
async function unlockVaultFromServer(username, vaultData) {
    return new Promise((resolve) => {
        const modal      = new bootstrap.Modal(document.getElementById('unlockVaultModal'));
        const confirmBtn = document.getElementById('confirm-vault-unlock-btn');
        const pinInput   = document.getElementById('vault-unlock-pin-input');
        const errEl      = document.getElementById('unlock-error');
        pinInput.value = '';
        if (errEl) errEl.style.display = 'none';
        modal.show();

        const tryUnlock = async () => {
            const pin = pinInput.value.trim();
            if (!pin) return;
            confirmBtn.disabled = true;
            confirmBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Decrypting...';
            if (errEl) errEl.style.display = 'none';
            try {
                const privJWK    = await vaultDecrypt(pin, vaultData.encrypted_private_key);
                const signPrivJWK = vaultData.encrypted_signing_key 
                    ? await vaultDecrypt(pin, vaultData.encrypted_signing_key) 
                    : null;

                // Import & cache in memory
                myPrivateKey   = await importPrivateKeyJWK(privJWK);
                myPublicKeyPEM = vaultData.public_key;
                if (signPrivJWK) mySigningPrivKey = await importSigningPrivKeyJWK(signPrivJWK);

                // Cache in localStorage for this browser
                localStorage.setItem(`secure_msg_priv_key_${username}`, privJWK);
                localStorage.setItem(`secure_msg_pub_key_${username}`,  vaultData.public_key);
                if (signPrivJWK) localStorage.setItem(`secure_msg_sign_priv_${username}`, signPrivJWK);

                updateKeyUIStatus(true);
                modal.hide();
                if (window.showToast) window.showToast('🔓 Vault unlocked — keys restored successfully!', 'success');
                cleanup();
                resolve();
            } catch (err) {
                console.error("Vault decrypt failed:", err);
                if (errEl) errEl.style.display = 'block';
                confirmBtn.disabled = false;
                confirmBtn.innerHTML = '<i class="bi bi-unlock-fill me-1"></i>UNLOCK & RESTORE';
            }
        };

        const onEnter = (e) => { if (e.key === 'Enter') tryUnlock(); };
        confirmBtn.addEventListener('click', tryUnlock);
        pinInput.addEventListener('keydown', onEnter);
        document.getElementById('unlockVaultModal').addEventListener('shown.bs.modal', () => pinInput.focus(), { once: true });

        function cleanup() {
            confirmBtn.removeEventListener('click', tryUnlock);
            pinInput.removeEventListener('keydown', onEnter);
        }
    });
}

function updateKeyUIStatus(hasKeys) {
    const badge = document.getElementById("key-status-badge");
    const initializeBtn = document.getElementById("initialize-keys-btn");
    const pubkeyBox = document.getElementById("pubkey-box");
    const privkeyBox = document.getElementById("privkey-box");

    // Guard: if badge doesn't exist on this page, skip silently
    if (!badge) return;

    if (hasKeys) {
        badge.className = "badge bg-success-subtle border border-success text-success px-3 py-2";
        badge.innerHTML = '<i class="bi bi-shield-fill-check me-1"></i>Key Pair Secure';
        if (initializeBtn) initializeBtn.style.display = "none";
        if (pubkeyBox) pubkeyBox.innerText = myPublicKeyPEM;
        if (privkeyBox) {
            const savedPriv = localStorage.getItem(`secure_msg_priv_key_${window.CURRENT_USER}`);
            privkeyBox.innerText = savedPriv ? savedPriv : "-----BEGIN RSA PRIVATE KEY-----\n[Encrypted local JWK Structure]\n-----END RSA PRIVATE KEY-----";
        }
    } else {
        badge.className = "badge bg-danger-subtle border border-danger text-danger px-3 py-2";
        badge.innerHTML = '<i class="bi bi-shield-slash-fill me-1"></i>Keys Missing';
        if (initializeBtn) initializeBtn.style.display = "inline-block";
        if (pubkeyBox) pubkeyBox.innerText = "Not generated yet. Click 'Initialize RSA' to generate keys.";
        if (privkeyBox) privkeyBox.innerText = "Not generated yet. Click 'Initialize RSA' to generate keys.";
    }
}


// Generate & Upload Key Pair — with Vault PIN encryption
async function handleInitializeKeys() {
    const username      = window.CURRENT_USER;
    const initializeBtn = document.getElementById("initialize-keys-btn");

    // Step 1: Ask for Vault PIN before generating anything
    let vaultPin;
    try {
        vaultPin = await waitForVaultSetupPin();
    } catch (e) {
        // User cancelled
        return;
    }

    if (initializeBtn) {
        initializeBtn.disabled = true;
        initializeBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>Generating...';
    }

    try {
        // Step 2: Generate RSA-OAEP + RSA-PSS key pairs
        const keyPair        = await generateRSAKeyPair();
        const signingKeyPair = await generateRSASigningKeyPair();

        const pubKeyPEM  = await exportPublicKeyPEM(keyPair.publicKey);
        const privKeyJWK = await exportPrivateKeyJWK(keyPair.privateKey);
        const sigPrivJWK = await exportSigningPrivKeyJWK(signingKeyPair.privateKey);
        const sigPubPEM  = await exportPublicKeyPEM(signingKeyPair.publicKey);

        // Step 3: Encrypt private keys with Vault PIN (AES-GCM)
        const encPrivBlob = await vaultEncrypt(vaultPin, privKeyJWK);
        const encSignBlob = await vaultEncrypt(vaultPin, sigPrivJWK);

        // Step 4: Upload public keys + encrypted private blobs to server
        const response = await fetch("/api/keys/upload", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                public_key:            pubKeyPEM,
                signing_public_key:    sigPubPEM,
                encrypted_private_key: encPrivBlob,
                encrypted_signing_key: encSignBlob
            })
        });
        if (!response.ok) throw new Error("Failed to upload keys to server.");

        // Step 5: Also cache plaintext keys in localStorage for this browser session
        localStorage.setItem(`secure_msg_priv_key_${username}`,  privKeyJWK);
        localStorage.setItem(`secure_msg_pub_key_${username}`,   pubKeyPEM);
        localStorage.setItem(`secure_msg_sign_priv_${username}`, sigPrivJWK);

        myPrivateKey     = keyPair.privateKey;
        myPublicKeyPEM   = pubKeyPEM;
        mySigningPrivKey = signingKeyPair.privateKey;

        updateKeyUIStatus(true);
        await fetchContacts();
        if (window.showToast) {
            window.showToast('🔐 Keys generated & encrypted vault backup created!', 'success', 6000);
        }
    } catch (e) {
        console.error("Key generation/upload failed:", e);
        if (window.showToast) window.showToast('Key generation failed: ' + e.message, 'danger');
        if (initializeBtn) {
            initializeBtn.disabled = false;
            initializeBtn.innerHTML = '<i class="bi bi-gear-fill me-1"></i>GENERATE KEYS';
        }
    }
}

// Fetch Contacts List
async function fetchContacts() {
    const container = document.getElementById("contacts-list");
    if (!container) return;

    try {
        const response = await fetch("/api/users");
        if (!response.ok) throw new Error("Could not fetch contacts list.");
        const data = await response.json();
        
        container.innerHTML = "";
        
        if (data.users.length === 0) {
            container.innerHTML = '<div class="text-center text-muted py-5 small">No other registered users found.</div>';
            return;
        }

        data.users.forEach(user => {
            const item = document.createElement("div");
            item.className = `chat-user-item ${activeRecipient === user.username ? 'active' : ''}`;
            
            const initials = user.full_name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
            const keyIcon = user.has_key 
                ? '<span class="chat-user-status has-key"><i class="bi bi-shield-lock-fill me-1"></i>Encrypted</span>'
                : '<span class="chat-user-status text-muted"><i class="bi bi-shield-slash me-1"></i>Uninitialized</span>';

            item.innerHTML = `
                <div class="chat-user-avatar">${initials}</div>
                <div class="chat-user-info">
                    <div class="chat-user-name">${user.full_name}</div>
                    ${keyIcon}
                </div>
            `;

            item.addEventListener("click", () => selectRecipient(user.username, user.has_key));
            container.appendChild(item);
        });
    } catch (e) {
        console.error(e);
        container.innerHTML = '<div class="text-center text-danger py-5 small">Error loading contacts.</div>';
    }
}

// Select a user to chat
async function selectRecipient(username, hasKey) {
    activeRecipient = username;
    
    // Highlight active item
    const items = document.querySelectorAll(".chat-user-item");
    items.forEach(el => el.classList.remove("active"));
    
    // Re-highlight list
    await fetchContacts();

    const windowContainer = document.getElementById("chat-window");
    if (!windowContainer) return;

    if (!hasKey) {
        activeRecipientPublicKey = null;
        windowContainer.innerHTML = `
            <div class="chat-window-header">
                <span class="fw-bold text-light">@${username}</span>
            </div>
            <div class="chat-messages align-items-center justify-content-center text-center text-muted">
                <i class="bi bi-shield-slash display-4 mb-3 text-danger" style="opacity: 0.5;"></i>
                <h6 class="text-light">Secure Connection Unavailable</h6>
                <p class="small" style="max-width: 320px;">
                    This contact has not initialized their RSA public keys yet. End-to-end encryption cannot be established.
                </p>
            </div>
            <div class="chat-input-area" style="opacity: 0.5; pointer-events: none;">
                <div class="chat-input-group">
                    <input type="text" class="form-control form-control-cyber" placeholder="Messaging locked..." disabled>
                    <button class="btn btn-cyber-primary" disabled><i class="bi bi-send-fill"></i></button>
                </div>
            </div>
        `;
        return;
    }

    // Load Recipient Public Key
    try {
        windowContainer.innerHTML = `
            <div class="chat-window-header">
                <span class="fw-bold text-light">@${username}</span>
                <span class="badge bg-success-subtle border border-success text-success px-2 py-1 small" style="font-size: 0.75rem;">
                    <i class="bi bi-lock-fill me-1"></i>E2EE LINK ESTABLISHED
                </span>
            </div>
            <div class="chat-messages" id="chat-messages-box">
                <div class="text-center text-muted py-5"><div class="spinner-border spinner-border-sm text-cyber-blue" role="status"></div></div>
            </div>
            <div class="chat-input-area">
                <form id="chat-send-form" onsubmit="event.preventDefault(); sendMessage();">
                    <div class="chat-input-group">
                        <input type="text" id="chat-input" class="form-control form-control-cyber" placeholder="Write a secure message..." required autocomplete="off">
                        <button type="submit" class="btn btn-cyber-primary" id="btn-chat-send"><i class="bi bi-send-fill"></i></button>
                    </div>
                </form>
            </div>
        `;

        const res = await fetch(`/api/keys/${username}`);
        if (!res.ok) throw new Error("Could not fetch recipient public key.");
        const keyData = await res.json();
        
        activeRecipientPublicKey = await importPublicKeyPEM(keyData.public_key);
        
        // Load chat history
        await fetchChatHistory(true);
    } catch (e) {
        console.error(e);
        windowContainer.innerHTML = `<div class="chat-placeholder text-danger">Error loading key: ${e.message}</div>`;
    }
}

// Fetch and Decrypt Chat History
async function fetchChatHistory(showSpinner = false) {
    const box = document.getElementById("chat-messages-box");
    if (!box) return;

    if (showSpinner) {
        box.innerHTML = '<div class="text-center text-muted py-5"><div class="spinner-border spinner-border-sm text-cyber-blue" role="status"></div></div>';
    }

    try {
        const response = await fetch("/api/messages/history");
        if (!response.ok) throw new Error("Could not fetch message history.");
        const data = await response.json();
        
        // Filter messages involving activeRecipient
        const conversation = data.messages.filter(msg => 
            (msg.sender === window.CURRENT_USER && msg.recipient === activeRecipient) ||
            (msg.sender === activeRecipient && msg.recipient === window.CURRENT_USER)
        );

        box.innerHTML = "";

        if (conversation.length === 0) {
            box.innerHTML = '<div class="text-center text-muted py-5 small"><i class="bi bi-chat-lock me-1"></i>Secure log is empty. Send a message to link.</div>';
            return;
        }

        for (const [msgIndex, msg] of conversation.entries()) {
            const isSentByMe = msg.sender === window.CURRENT_USER;
            const container = document.createElement("div");
            const initials = isSentByMe
                ? (window.CURRENT_USER || 'M').substring(0, 2).toUpperCase()
                : (activeRecipient || 'U').substring(0, 2).toUpperCase();
            container.className = `chat-bubble-container ${isSentByMe ? 'sent' : 'received'}`;
            container.setAttribute('data-initials', initials);
            const staggerDelay = Math.max(0, (conversation.length - 8 + msgIndex)) * 0.05;
            container.style.animationDelay = `${staggerDelay}s`;

            let decryptedText = "";
            let isDecryptError = false;
            let decryptErrorMsg = "";

            if (isSentByMe) {
                if (msg.sender_encrypted) {
                    if (myPrivateKey) {
                        try {
                            const rawEncrypted = await fetchFromIPFS(msg.sender_encrypted);
                            decryptedText = await decryptData(myPrivateKey, rawEncrypted);
                            if (decryptedText.startsWith('[Decryption Error')) {
                                isDecryptError = true;
                                decryptErrorMsg = "Key changed — old message cannot be decrypted";
                            }
                        } catch (err) {
                            console.error("Decryption error for msg", msg.id, err);
                            isDecryptError = true;
                            decryptErrorMsg = "Key changed — old message cannot be decrypted";
                        }
                    } else {
                        isDecryptError = true;
                        decryptErrorMsg = "Initialize RSA keys to read your messages";
                    }
                } else {
                    isDecryptError = true;
                    decryptErrorMsg = "No local copy stored for this message";
                }
            } else {
                if (myPrivateKey) {
                    try {
                        const rawEncrypted = await fetchFromIPFS(msg.encrypted_message);
                        decryptedText = await decryptData(myPrivateKey, rawEncrypted);
                        if (decryptedText.startsWith('[Decryption Error')) {
                            isDecryptError = true;
                            decryptErrorMsg = "Encrypted with a different key — cannot decrypt";
                        }
                    } catch (err) {
                        console.error("Decryption error for msg", msg.id, err);
                        isDecryptError = true;
                        decryptErrorMsg = "Encrypted with a different key — cannot decrypt";
                    }
                } else {
                    isDecryptError = true;
                    decryptErrorMsg = "Initialize RSA keys to decrypt messages";
                }
            }

            // Signature badge
            let sigBadge = '';
            if (msg.sig_valid === 1 || msg.sig_valid === true) {
                sigBadge = `<span class="sig-badge verified" title="Digital signature verified"><i class="bi bi-patch-check-fill"></i></span>`;
            } else if (msg.sig_valid === 0 || msg.sig_valid === false) {
                sigBadge = `<span class="sig-badge invalid" title="Signature verification failed"><i class="bi bi-patch-exclamation-fill"></i></span>`;
            }

            // Format timestamp: show only time HH:MM
            const ts = msg.timestamp ? msg.timestamp.split(' ')[1]?.substring(0,5) || msg.timestamp : '';

            const bubbleContent = isDecryptError
                ? `<span class="decrypt-error-inline"><i class="bi bi-lock-fill"></i> ${decryptErrorMsg}</span>`
                : decryptedText;

            container.innerHTML = `
                <div class="chat-bubble ${isDecryptError ? 'bubble-error' : ''}">
                    <span class="bubble-text">${bubbleContent}</span>
                    <span class="bubble-footer">
                        <span class="bubble-time">${ts}</span>
                        ${isSentByMe ? `<span class="bubble-ticks"><i class="bi bi-check2-all"></i></span>` : ''}
                        ${sigBadge}
                        <i class="bi bi-shield-lock-fill bubble-e2ee" title="E2EE · Block #${msg.id}"></i>
                    </span>
                </div>
            `;
            box.appendChild(container);
        }

        // Scroll to bottom
        box.scrollTop = box.scrollHeight;
    } catch (e) {
        console.error("History loading error:", e);
        box.innerHTML = `<div class="text-center text-danger py-4 small">Error decrypting logs.</div>`;
    }
}

// IPFS Helpers (Global scope — used by sendMessage AND fetchChatHistory)
async function uploadToIPFS(encrypted_payload) {
    if (!encrypted_payload) return "";
    const res = await fetch("/api/ipfs/upload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ encrypted_payload })
    });
    if (!res.ok) throw new Error("IPFS Upload Failed");
    const data = await res.json();
    return "ipfs://" + data.ipfs_cid;
}

async function fetchFromIPFS(ipfs_uri) {
    if (!ipfs_uri || !ipfs_uri.startsWith("ipfs://")) return ipfs_uri;
    const cid = ipfs_uri.replace("ipfs://", "");
    const res = await fetch(`/ipfs/${cid}`);
    if (!res.ok) throw new Error("IPFS Fetch Failed");
    return await res.text();
}

// Encrypt and Send Message (Mines a Block)
async function sendMessage() {
    const input = document.getElementById("chat-input");
    const sendBtn = document.getElementById("btn-chat-send");
    if (!input || !activeRecipientPublicKey) return;

    const text = input.value.trim();
    if (!text) return;

    // Show mining overlay
    const overlay = document.getElementById("mining-status-overlay");
    const nonceCounter = document.getElementById("mining-nonce-counter");
    
    if (overlay) overlay.classList.add("active");
    if (sendBtn) sendBtn.disabled = true;

    // Let's run a fake nonce incrementor in the UI for aesthetic visual realism!
    let fakeNonce = 0;
    const fakeMining = setInterval(() => {
        fakeNonce += Math.floor(Math.random() * 20) + 1;
        if (nonceCounter) nonceCounter.innerText = `Calculating SHA-256 hash | Nonce: ${fakeNonce}`;
    }, 80);



    try {
        // 1. Encrypt for recipient using recipient's public key
        let encryptedForRecipient = await encryptData(activeRecipientPublicKey, text);

        // 2. Encrypt for myself using my own public key (so I can view history)
        let encryptedForSender = "";
        if (myPublicKeyPEM) {
            const myPublicKey = await importPublicKeyPEM(myPublicKeyPEM);
            encryptedForSender = await encryptData(myPublicKey, text);
        }

        // 2.5. Upload payloads to IPFS concurrently
        if (nonceCounter) nonceCounter.innerText = `Pinning payload to IPFS...`;
        const [recCID, senCID] = await Promise.all([
            uploadToIPFS(encryptedForRecipient),
            encryptedForSender ? uploadToIPFS(encryptedForSender) : Promise.resolve("")
        ]);
        encryptedForRecipient = recCID;
        encryptedForSender    = senCID;
        if (nonceCounter) nonceCounter.innerText = `Signing message & calculating SHA-256...`;

        // 2.6. Sign the message with RSA-PSS signing key (NEW)
        let digitalSignature = null;
        let plainHash        = null;
        if (mySigningPrivKey) {
            plainHash        = await sha256Hex(text);
            digitalSignature = await signMessage(mySigningPrivKey, plainHash);
        }

        // 3. Send to server blockchain
        const response = await fetch("/api/messages/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                recipient:          activeRecipient,
                encrypted_message:  encryptedForRecipient,
                sender_encrypted:   encryptedForSender,
                digital_signature:  digitalSignature,
                plain_hash:         plainHash,
            })
        });

        clearInterval(fakeMining);

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.error || "Failed to append block to ledger.");
        }

        input.value = "";
        
        // Hide overlay and refresh
        if (overlay) overlay.classList.remove("active");
        if (sendBtn) sendBtn.disabled = false;

        await fetchChatHistory(false);
        await fetchBlockchainBlocks(); // Update blockchain list tab
    } catch (e) {
        clearInterval(fakeMining);
        if (overlay) overlay.classList.remove("active");
        if (sendBtn) sendBtn.disabled = false;
        alert("Mining Failed: " + e.message);
    }
}

// -------------------------------------------------------------------------
// BLOCKCHAIN VISUALIZER & AUDITING
// -------------------------------------------------------------------------
async function fetchBlockchainBlocks() {
    const container = document.getElementById("blockchain-timeline-list");
    if (!container) return;

    try {
        const response = await fetch("/api/blockchain/blocks");
        if (!response.ok) throw new Error("Could not fetch blockchain blocks.");
        const data = await response.json();
        
        blockchainBlocks = data.blocks;
        renderBlockchainTimeline(container, blockchainBlocks);
    } catch (e) {
        console.error(e);
        container.innerHTML = '<div class="text-center text-danger w-100 py-5">Error loading blockchain data.</div>';
    }
}

function renderBlockchainTimeline(container, blocks, auditDetails = null) {
    if (blocks.length === 0) {
        container.innerHTML = `
            <div class="text-center text-muted w-100 py-5">
                No blocks mined on this ledger yet. Send a message in "Secure Chat" to mine the first block.
            </div>
        `;
        return;
    }

    container.innerHTML = "";

    blocks.forEach((block, index) => {
        const blockDiv = document.createElement("div");
        blockDiv.className = "blockchain-block";
        blockDiv.id = `block-card-${block.id}`;
        blockDiv.style.animationDelay = `${index * 0.08}s`;
        
        // Check audit status
        let borderClass = "";
        let auditMsg = "";
        
        if (auditDetails) {
            const auditResult = auditDetails.results.find(r => r.id === block.id);
            if (auditResult) {
                if (auditResult.is_valid) {
                    blockDiv.classList.add("verified");
                } else {
                    blockDiv.classList.add("tampered");
                    borderClass = "border-neon-red";
                    auditMsg = `<div class="text-danger small fw-bold mt-2"><i class="bi bi-x-circle-fill me-1"></i>Block Corrupted: ${auditResult.issues.join('; ')}</div>`;
                }
            }
        }

        let msgSnippet = block.encrypted_message.substring(0, 18) + "...";
        let msgLabel = "Encrypted Payload";
        if (block.encrypted_message.startsWith("ipfs://")) {
            msgSnippet = `<i class="bi bi-hdd-network me-1 text-success"></i>${block.encrypted_message.substring(7, 24)}...`;
            msgLabel = "IPFS Storage CID";
        }
        
        blockDiv.innerHTML = `
            <div class="block-header">
                <span class="block-title">BLOCK #${block.id}</span>
                <span class="badge bg-secondary-subtle text-light small px-2 py-1">Nonce: ${block.nonce}</span>
            </div>
            <div class="block-body">
                <div class="block-data-field">
                    <span class="block-data-label">Sender</span>
                    <span class="block-data-value text-cyber-blue">@${block.sender}</span>
                </div>
                <div class="block-data-field">
                    <span class="block-data-label">Recipient</span>
                    <span class="block-data-value text-cyber-purple">@${block.recipient}</span>
                </div>
                <div class="block-data-field">
                    <span class="block-data-label">${msgLabel}</span>
                    <span class="block-data-value text-muted" title="${block.encrypted_message}">${msgSnippet}</span>
                </div>
                <div class="block-data-field mt-1">
                    <span class="block-data-label">Previous Hash</span>
                    <div class="block-hash-box prev" title="${block.previous_hash}">${block.previous_hash.substring(0, 14)}...</div>
                </div>
                <div class="block-data-field">
                    <span class="block-data-label">Block Hash</span>
                    <div class="block-hash-box" title="${block.hash}">${block.hash.substring(0, 14)}...</div>
                </div>
                ${auditMsg}
            </div>
        `;

        container.appendChild(blockDiv);

        // Add linkage arrow if not the last block
        if (index < blocks.length - 1) {
            const arrow = document.createElement("div");
            arrow.className = "block-link-arrow";
            arrow.innerHTML = '<i class="bi bi-arrow-right"></i>';
            container.appendChild(arrow);
        }
    });
}

// Run Cryptographic Blockchain Integrity Audit
async function runBlockchainAudit() {
    const container = document.getElementById("audit-status-container");
    const banner = document.getElementById("audit-status-banner");
    const listContainer = document.getElementById("blockchain-timeline-list");
    const auditBtn = document.getElementById("btn-audit-chain");
    
    if (!banner || !container) return;

    if (auditBtn) {
        auditBtn.disabled = true;
        auditBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>Auditing...';
    }

    try {
        const response = await fetch("/api/blockchain/audit", { method: "POST" });
        if (!response.ok) throw new Error("Audit endpoint returned HTTP error.");
        const auditData = await response.json();
        
        container.classList.remove("d-none");
        
        if (auditData.is_valid) {
            banner.className = "audit-indicator valid";
            banner.innerHTML = '<i class="bi bi-check-circle-fill"></i> <span>Audit Successful: Ledger is intact. All Proof-of-Work values and block hashes link sequentially.</span>';
        } else {
            banner.className = "audit-indicator invalid";
            banner.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> <span>Ledger Validation Error: Detected data tampering! Blockchain validation detected sequential mismatch.</span>';
        }

        // Re-render blocks with audit overlay details
        renderBlockchainTimeline(listContainer, blockchainBlocks, auditData);
    } catch (e) {
        console.error(e);
        alert("Failed to run ledger audit: " + e.message);
    } finally {
        if (auditBtn) {
            auditBtn.disabled = false;
            auditBtn.innerHTML = '<i class="bi bi-shield-fill-check me-1"></i>Run Ledger Audit';
        }
    }
}

// Simulate Database Tampering
async function simulateDatabaseTampering() {
    const tamperBtn = document.getElementById("btn-tamper-db");
    
    if (tamperBtn) {
        tamperBtn.disabled = true;
        tamperBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>Tampering...';
    }

    try {
        const response = await fetch("/api/blockchain/tamper", { method: "POST" });
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Failed to tamper database.");
        }

        alert(`Intruder attack simulation triggered! Modified Block #${data.tampered_block_id}'s payload in the SQLite file. Run the Ledger Audit to see the blockchain catch this modification.`);
        
        // Refresh blocks list from server (will have modified text in database but same hashes)
        await fetchBlockchainBlocks();
        
    } catch (e) {
        console.error(e);
        alert("Tamper simulation failed: " + e.message);
    } finally {
        if (tamperBtn) {
            tamperBtn.disabled = false;
            tamperBtn.innerHTML = '<i class="bi bi-lightning-charge-fill me-1"></i>Simulate Database Tamper';
        }
    }
}

// Copy Utilities
function copyPublicKey() {
    if (myPublicKeyPEM) {
        navigator.clipboard.writeText(myPublicKeyPEM)
            .then(() => alert("RSA Public Key copied to clipboard!"))
            .catch(err => console.error("Could not copy:", err));
    }
}

function copyPrivateKey() {
    const username = window.CURRENT_USER;
    const savedPrivKey = localStorage.getItem(`secure_msg_priv_key_${username}`);
    if (savedPrivKey) {
        navigator.clipboard.writeText(savedPrivKey)
            .then(() => alert("RSA Private Key (JWK String) copied to clipboard!"))
            .catch(err => console.error("Could not copy:", err));
    }
}

function downloadPrivateKey() {
    const username = window.CURRENT_USER;
    const savedPrivKey = localStorage.getItem(`secure_msg_priv_key_${username}`);
    if (savedPrivKey) {
        const element = document.createElement("a");
        const file = new Blob([savedPrivKey], {type: 'text/plain'});
        element.href = URL.createObjectURL(file);
        element.download = `private_key_${username}.jwk`;
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);
    }
}
