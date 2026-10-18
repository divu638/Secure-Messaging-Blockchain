import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))
from app import app, db_execute

print("=" * 60)
print("TESTING FULL APPLICATION WORKFLOW ON SUPABASE POSTGRESQL")
print("=" * 60)

with app.app_context():
    client = app.test_client()
    
    test_ts = int(time.time())
    test_username = f"verify_{test_ts}"
    test_email = f"verify_{test_ts}@example.com"
    test_password = "SecurePassword123!"
    
    # ── Test 1: User Registration ─────────────────────────────────────────────
    print(f"\n[Test 1] Registering new user: {test_username}...")
    reg_res = client.post("/register", data={
        "full_name": "Supabase Test User",
        "username": test_username,
        "email": test_email,
        "password": test_password,
        "confirm_password": test_password,
    }, follow_redirects=True)
    
    assert reg_res.status_code == 200, f"Registration failed with code {reg_res.status_code}"
    
    # Verify user exists in Supabase
    user_row = db_execute("SELECT * FROM users WHERE username = ?", (test_username,), fetchone=True)
    assert user_row is not None, "User not found in Supabase users table!"
    print(f"   [+] User successfully saved in Supabase! ID: {user_row['id']}")
    
    # ── Test 2: User Login ────────────────────────────────────────────────────
    print(f"\n[Test 2] Logging in as {test_username}...")
    login_res = client.post("/login", data={
        "username": test_username,
        "password": test_password,
    }, follow_redirects=True)
    
    assert login_res.status_code == 200, f"Login failed with code {login_res.status_code}"
    print("   [+] Login successful, authenticated session created!")
    
    # ── Test 3: Dashboard Access ──────────────────────────────────────────────
    print("\n[Test 3] Loading /dashboard...")
    dash_res = client.get("/dashboard")
    assert dash_res.status_code == 200, f"Dashboard returned {dash_res.status_code}"
    print("   [+] Dashboard loaded successfully (HTTP 200)!")
    
    # ── Test 4: Key Management API ────────────────────────────────────────────
    print("\n[Test 4] Uploading cryptographic public keys...")
    mock_pub_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----"
    key_res = client.post("/api/keys/upload", json={
        "public_key": mock_pub_key,
        "signing_public_key": mock_pub_key,
        "encrypted_private_key": "mock_encrypted_private_key",
        "encrypted_signing_key": "mock_encrypted_signing_key"
    })
    assert key_res.status_code == 200, f"Key upload failed: {key_res.data}"
    
    saved_key = db_execute("SELECT * FROM user_keys WHERE user_id = ?", (user_row['id'],), fetchone=True)
    assert saved_key is not None, "User key not saved in Supabase!"
    print("   [+] Public keys stored in Supabase user_keys table!")
    
    # ── Test 5: Mine & Send Blockchain Message ────────────────────────────────
    print("\n[Test 5] Mining & sending encrypted message onto blockchain...")
    # Send message to an existing user e.g. 'divya'
    msg_res = client.post("/api/messages/send", json={
        "recipient": "divya",
        "encrypted_message": "CIPHERTEXT:TestMessageForSupabaseVerification",
        "sender_encrypted": "CIPHERTEXT:SenderCopy",
    })
    assert msg_res.status_code == 200, f"Send message failed: {msg_res.data}"
    msg_json = msg_res.get_json()
    new_block = msg_json.get("block", {})
    block_id = new_block.get("id")
    print(f"   [+] Block #{block_id} mined and appended to Supabase blockchain!")
    print(f"       Hash: {new_block.get('hash')}")
    print(f"       Nonce: {new_block.get('nonce')}")
    
    # ── Test 6: Blockchain History API ────────────────────────────────────────
    print("\n[Test 6] Fetching messages history from Supabase...")
    hist_res = client.get("/api/messages/history")
    assert hist_res.status_code == 200, f"History API returned {hist_res.status_code}"
    hist_json = hist_res.get_json()
    assert len(hist_json.get("messages", [])) > 0, "No messages returned from history!"
    print(f"   [+] History API returned {len(hist_json['messages'])} message(s) successfully!")
    
    # ── Test 7: Blockchain Audit ──────────────────────────────────────────────
    print("\n[Test 7] Auditing blockchain blocks...")
    audit_res = client.post("/api/blockchain/audit")
    assert audit_res.status_code == 200, f"Audit returned {audit_res.status_code}"
    audit_json = audit_res.get_json()
    total_audited = len(audit_json.get("results", []))
    print(f"   [+] Audit executed over {total_audited} blocks in Supabase!")
    
    # ── Cleanup ───────────────────────────────────────────────────────────────
    print("\n[Cleanup] Cleaning up temporary test user and block from Supabase...")
    if block_id:
        db_execute("DELETE FROM blockchain WHERE id = ?", (block_id,), commit=True)
    db_execute("DELETE FROM user_keys WHERE user_id = ?", (user_row['id'],), commit=True)
    db_execute("DELETE FROM users WHERE id = ?", (user_row['id'],), commit=True)
    print("   [+] Test records cleaned up successfully.")

print("\n" + "=" * 60)
print(">>> ALL 7 SYSTEM TESTS PASSED ON SUPABASE POSTGRESQL! <<<")
print("=" * 60)
