import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import settings

class CryptoAgility:
    VERSION_AES_256_GCM = 0x01
    DEFAULT_KEY_ID = 0x01

    def __init__(self):
        try:
            # Load master key from hex representation
            master_key = bytes.fromhex(settings.ENC_KEY)
            if len(master_key) != 32:
                raise ValueError("ENC_KEY must be a 32-byte hex string (64 characters).")
        except Exception as e:
            raise ValueError(f"Invalid ENC_KEY configuration: {e}")

        # Key ring for crypto-agility and key rotation
        self.key_ring = {
            self.DEFAULT_KEY_ID: master_key
        }

    def encrypt(self, plaintext: str) -> bytes:
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")
        
        version = self.VERSION_AES_256_GCM
        key_id = self.DEFAULT_KEY_ID
        key = self.key_ring[key_id]
        
        # 12-byte nonce standard for AES-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        
        # Authenticated data binding version and key_id to prevent tampering / replacement
        associated_data = bytes([version, key_id])
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), associated_data)
        
        # Envelope structure: version_byte (1B) || key_id (1B) || nonce (12B) || ciphertext + tag
        return bytes([version, key_id]) + nonce + ciphertext_and_tag

    def decrypt(self, envelope: bytes) -> str:
        if not envelope or len(envelope) < 14:  # 1B version + 1B key_id + 12B nonce
            raise ValueError("Invalid cipher envelope size")
            
        version = envelope[0]
        key_id = envelope[1]
        nonce = envelope[2:14]
        ciphertext_and_tag = envelope[14:]
        
        if version != self.VERSION_AES_256_GCM:
            raise ValueError(f"Unsupported cipher version: {version}")
            
        if key_id not in self.key_ring:
            raise ValueError(f"Key ID {key_id} not found in key ring")
            
        key = self.key_ring[key_id]
        aesgcm = AESGCM(key)
        
        associated_data = bytes([version, key_id])
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
        return decrypted_bytes.decode('utf-8')

crypto = CryptoAgility()
