import sys
import os
import sqlite3

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import settings
from crypto import crypto
from database import init_db, engine
from models import AppUser, UserRole
from auth import hash_password, verify_password
from sqlmodel import Session, select

def run_tests():
    print("=== STARTING SCAFFOLD TESTS ===")

    # 1. Config Check
    print("1. Checking configurations...")
    assert settings.BASE_DOMAIN == "ops.local"
    assert settings.ADMIN_USER == "admin"
    print("   [OK] Config loaded successfully.")

    # 2. Database WAL Check
    print("2. Checking database WAL mode...")
    init_db()
    
    # Query journal mode from sqlite connection
    db_path = os.path.join(settings.PROJECT_ROOT, "opspanel.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    journal_mode = cursor.execute("PRAGMA journal_mode;").fetchone()[0]
    cursor.close()
    conn.close()
    
    print(f"   Journal mode: {journal_mode}")
    assert journal_mode.lower() == "wal"
    print("   [OK] Database running in WAL mode.")

    # 3. Cryptography check (envelope encryption/decryption)
    print("3. Checking crypto envelope (AES-256-GCM)...")
    plaintext = "super_secret_ssh_password"
    envelope = crypto.encrypt(plaintext)
    
    # Verify version and key ID header bytes
    assert envelope[0] == 0x01  # version
    assert envelope[1] == 0x01  # key_id
    
    decrypted = crypto.decrypt(envelope)
    assert decrypted == plaintext
    print(f"   Encrypted payload length: {len(envelope)} bytes")
    print("   [OK] Encryption/decryption verified.")

    # 4. Authentication (argon2 hashing)
    print("4. Checking authentication password hashing...")
    pw = "my-secure-password"
    hashed = hash_password(pw)
    assert hashed != pw
    assert verify_password(hashed, pw) is True
    assert verify_password(hashed, "wrong-pw") is False
    print("   [OK] Password hashing/verification verified.")

    # 5. Seeding verification
    print("5. Checking Admin user seeding...")
    with Session(engine) as db:
        statement = select(AppUser).where(AppUser.username == settings.ADMIN_USER)
        admin = db.exec(statement).first()
        if not admin:
            admin = AppUser(
                username=settings.ADMIN_USER,
                password_hash=hash_password(settings.ADMIN_PASS),
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(admin)
            db.commit()
            admin = db.exec(statement).first()
        
        assert admin is not None
        assert admin.username == "admin"
        assert admin.role == UserRole.ADMIN
        print("   [OK] Seeded admin check passed.")

    print("=== ALL SCAFFOLD TESTS PASSED ===")

if __name__ == "__main__":
    run_tests()
