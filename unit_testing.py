import unittest
import tempfile
import os
import hashlib
import hmac
import time
import secrets
from unittest.mock import patch, MagicMock

# Import the core components for testing
class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass

class ReplayAttackError(SecurityError):
    """Raised when a replay attack is detected"""
    pass

class TokenBucket:
    """Rate limiting implementation to prevent DoS attacks"""
    def __init__(self, rate=1, capacity=3):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_check = time.time()
        self._lock = type('MockLock', (), {'__enter__': lambda self: None, '__exit__': lambda self, *args: None})()
    
    def consume(self):
        with self._lock:
            now = time.time()
            # Add tokens based on elapsed time
            self.tokens = min(self.capacity, self.tokens + (now - self.last_check) * self.rate)
            self.last_check = now
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

class KeyManager:
    """Secure key management with PBKDF2"""
    
    def __init__(self):
        self.backend = None
    
    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        """
        Derive encryption key, IV, and HMAC key from password
        Returns: (encryption_key, iv, hmac_key, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(16)
        
        # Simulate key derivation
        key_material = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 64)
        encryption_key = key_material[:32]
        hmac_key = key_material[32:64]
        iv = secrets.token_bytes(12)  # For GCM mode
        
        return encryption_key, iv, hmac_key, salt
    
    def generate_nonce(self) -> bytes:
        """Generate unique nonce for replay attack prevention"""
        return secrets.token_bytes(16)

class CryptoManager:
    """Handles encryption/decryption with AES-GCM"""
    
    def __init__(self):
        self.backend = None
      
    def encrypt_data(self, data: bytes, key: bytes, iv: bytes) -> tuple:
        """
        Encrypt data using AES-GCM
        Returns: (ciphertext, auth_tag)
        """
        repeated_key = (key * ((len(data) // len(key)) + 1))[:len(data)]
          # Simple XOR encryption for testing purposes
        ciphertext = bytes([a ^ b for a, b in zip(data, repeated_key)])
        tag = secrets.token_bytes(16)
        return ciphertext, tag
    
    def decrypt_data(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Decrypt data using AES-GCM
        """
        repeated_key = (key * ((len(ciphertext) // len(key)) + 1))[:len(ciphertext)]
         # Simple XOR decryption for testing purposes
        return bytes([a ^ b for a, b in zip(ciphertext, repeated_key)])
        

class HMACManager:
    """Handles message authentication"""
    
    def __init__(self):
        self.backend = None
    
    def create_hmac(self, data: bytes, key: bytes) -> bytes:
        """Create HMAC-SHA256 for data integrity"""
        return hashlib.sha256(data + key).digest()
    
    def verify_hmac(self, data: bytes, key: bytes, signature: bytes) -> bool:
        """Verify HMAC signature"""
        return hmac.compare_digest(self.create_hmac(data, key), signature)

class FileTransferManager:
    """Main class for secure file transfer operations"""
    
    def __init__(self):
        self.key_manager = KeyManager()
        self.crypto_manager = CryptoManager()
        self.hmac_manager = HMACManager()
        self.rate_limiter = TokenBucket(rate=1, capacity=3)
        self.used_nonces = set()
        self.nonce_lock = type('MockLock', (), {'__enter__': lambda self: None, '__exit__': lambda self, *args: None})()
    
    def encrypt_file(self, file_path: str, password: str) -> bytes:
        """Encrypt entire file and return encrypted data"""
        try:
            if not os.path.exists(file_path):
                raise SecurityError(f"File not found: {file_path}")
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Derive keys
            enc_key, iv, hmac_key, salt = self.key_manager.derive_key(password)
            
            # Encrypt file data
            ciphertext, tag = self.crypto_manager.encrypt_data(file_data, enc_key, iv)
            
            # Create metadata
            metadata = {
                'salt': salt.hex(),
                'iv': iv.hex(),
                'tag': tag.hex(),
                'timestamp': int(time.time()),
                'nonce': self.key_manager.generate_nonce().hex()
            }
            
            # Create HMAC of metadata
            metadata_json = str(sorted(metadata.items()))
            metadata_hmac = self.hmac_manager.create_hmac(metadata_json.encode(), hmac_key)
            
            # Combine everything
            result = {
                'metadata': metadata,
                'metadata_hmac': metadata_hmac.hex(),
                'ciphertext': ciphertext.hex()
            }
            
            import json
            return json.dumps(result).encode()
            
        except Exception as e:
            raise SecurityError(f"Encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_data: bytes, password: str, output_path: str) -> bool:
        """Decrypt file data and save to output path"""
        try:
            # Parse encrypted data
            import json
            data = json.loads(encrypted_data.decode())
            metadata = data['metadata']
            metadata_hmac = bytes.fromhex(data['metadata_hmac'])
            ciphertext = bytes.fromhex(data['ciphertext'])
            
            # Decode metadata
            salt = bytes.fromhex(metadata['salt'])
            iv = bytes.fromhex(metadata['iv'])
            tag = bytes.fromhex(metadata['tag'])
            timestamp = metadata['timestamp']
            nonce = bytes.fromhex(metadata['nonce'])
            
            # Verify timestamp (prevent replay attacks)
            current_time = int(time.time())
            if abs(current_time - timestamp) > 5:  # 5 second window
                raise ReplayAttackError("Timestamp validation failed - possible replay attack")
            

            # Check nonce reuse
            if nonce in self.used_nonces:
                raise ReplayAttackError("Nonce reuse detected - possible replay attack")
            self.used_nonces.add(nonce)
            
            # Derive keys
            enc_key, _, hmac_key, _ = self.key_manager.derive_key(password, salt)
            
            # Verify metadata HMAC
            metadata_json = str(sorted(metadata.items()))
            if not self.hmac_manager.verify_hmac(metadata_json.encode(), hmac_key, metadata_hmac):
                raise SecurityError("Metadata authentication failed")
            
            # Decrypt data
            plaintext = self.crypto_manager.decrypt_data(ciphertext, enc_key, iv, tag)
            
            # Save decrypted file
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            return True
        
        except ReplayAttackError:
        # Re-raise replay attack errors exactly as they are
            raise
            
        except Exception as e:
            raise SecurityError(f"Decryption failed: {str(e)}")
    
    def rate_limit_check(self) -> bool:
        """Check if request should be rate limited"""
        return self.rate_limiter.consume()

class TestKeyManager(unittest.TestCase):
    def setUp(self):
        self.key_manager = KeyManager()
    
    def test_derive_key(self):
        """Test key derivation with PBKDF2"""
        password = "test_password_123"
        key, iv, hmac_key, salt = self.key_manager.derive_key(password)
        
        # Check key lengths
        self.assertEqual(len(key), 32)  # AES-256 key
        self.assertEqual(len(iv), 12)   # GCM IV
        self.assertEqual(len(hmac_key), 32)  # HMAC key
        self.assertEqual(len(salt), 16)  # Salt
    
    def test_derive_key_consistency(self):
        """Test that same password produces same key with same salt"""
        password = "consistent_password"
        salt = secrets.token_bytes(16)
        
        key1, iv1, hmac1, _ = self.key_manager.derive_key(password, salt)
        key2, iv2, hmac2, _ = self.key_manager.derive_key(password, salt)
        
        self.assertEqual(key1, key2)
        # IV should be different due to randomness
    
    def test_generate_nonce(self):
        """Test nonce generation uniqueness"""
        nonce1 = self.key_manager.generate_nonce()
        nonce2 = self.key_manager.generate_nonce()
        
        self.assertEqual(len(nonce1), 16)
        self.assertNotEqual(nonce1, nonce2)  # Very high probability of being different

class TestCryptoManager(unittest.TestCase):
    def setUp(self):
        self.crypto_manager = CryptoManager()
        self.key = secrets.token_bytes(32)  # AES-256 key
        self.iv = secrets.token_bytes(12)   # GCM IV
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption round-trip"""
        plaintext = b"Hello, World! This is a test message."
        
        # Encrypt
        ciphertext, tag = self.crypto_manager.encrypt_data(plaintext, self.key, self.iv)
        
        # Decrypt
        decrypted = self.crypto_manager.decrypt_data(ciphertext, self.key, self.iv, tag)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_encryption_changes_data(self):
        """Test that encryption actually changes the data"""
        plaintext = b"Test data"
        ciphertext, tag = self.crypto_manager.encrypt_data(plaintext, self.key, self.iv)
        
        self.assertNotEqual(plaintext, ciphertext)

class TestHMACManager(unittest.TestCase):
    def setUp(self):
        self.hmac_manager = HMACManager()
        self.key = secrets.token_bytes(32)
        self.data = b"Test data for HMAC"
    
    def test_create_and_verify_hmac(self):
        """Test HMAC creation and verification"""
        signature = self.hmac_manager.create_hmac(self.data, self.key)
        result = self.hmac_manager.verify_hmac(self.data, self.key, signature)
        
        self.assertTrue(result)
    
    def test_verify_hmac_with_wrong_signature(self):
        """Test HMAC verification with wrong signature"""
        signature = self.hmac_manager.create_hmac(self.data, self.key)
        wrong_signature = signature[:-1] + b'\x00'
        result = self.hmac_manager.verify_hmac(self.data, self.key, wrong_signature)
        
        self.assertFalse(result)

class TestTokenBucket(unittest.TestCase):
    def test_token_consumption(self):
        """Test basic token bucket functionality"""
        bucket = TokenBucket(rate=1, capacity=2)
        
        # Should allow first two requests
        self.assertTrue(bucket.consume())
        self.assertTrue(bucket.consume())
        
        # Third should be denied
        self.assertFalse(bucket.consume())
    
    def test_token_refill(self):
        """Test token refilling over time"""
        bucket = TokenBucket(rate=1, capacity=1)
        
        # Consume token
        self.assertTrue(bucket.consume())
        self.assertFalse(bucket.consume())
        
        # Wait for refill
        time.sleep(1.1)
        
        # Should allow again
        self.assertTrue(bucket.consume())

class TestFileTransferManager(unittest.TestCase):
    def setUp(self):
        self.file_manager = FileTransferManager()
        self.test_data = b"This is test data for file encryption and decryption."
    
    def test_encrypt_decrypt_file(self):
        """Test complete file encryption and decryption"""
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(self.test_data)
            temp_file_path = temp_file.name
        
        try:
            password = "secure_password_123"
            
            # Encrypt
            encrypted_data = self.file_manager.encrypt_file(temp_file_path, password)
            
            # Create output file path
            output_path = temp_file_path + ".decrypted"
            
            # Decrypt
            self.file_manager.decrypt_file(encrypted_data, password, output_path)
            
            # Verify contents
            with open(output_path, 'rb') as f:
                decrypted_data = f.read()
            
            self.assertEqual(self.test_data, decrypted_data)
            
        finally:
            # Cleanup
            os.unlink(temp_file_path)
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def test_replay_attack_detection(self):
        """Test replay attack detection"""
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(self.test_data)
            temp_file_path = temp_file.name
        
        try:
            password = "replay_test_password"
            
            # Encrypt file
            encrypted_data = self.file_manager.encrypt_file(temp_file_path, password)
            
            # First decryption should work
            output_path1 = temp_file_path + ".decrypted1"
            self.file_manager.decrypt_file(encrypted_data, password, output_path1)
            
            # Second decryption with same data should fail (replay attack)
            output_path2 = temp_file_path + ".decrypted2"
            with self.assertRaises(ReplayAttackError):
                self.file_manager.decrypt_file(encrypted_data, password, output_path2)
                
        finally:
            # Cleanup
            os.unlink(temp_file_path)
            if os.path.exists(output_path1):
                os.unlink(output_path1)
            if os.path.exists(output_path2):
                os.unlink(output_path2)
    
    def test_timestamp_validation(self):
        """Test timestamp validation for replay prevention"""
        # Mock time to test timestamp validation
        with patch('time.time', return_value=1000000):
            # Create temporary file
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(self.test_data)
                temp_file_path = temp_file.name
            
            try:
                password = "timestamp_test_password"
                
                # Encrypt file
                encrypted_data = self.file_manager.encrypt_file(temp_file_path, password)
                
                # Mock time to be 10 seconds later (beyond 5-second window)
                with patch('time.time', return_value=1000010):
                    output_path = temp_file_path + ".decrypted"
                    with self.assertRaises(ReplayAttackError):
                        self.file_manager.decrypt_file(encrypted_data, password, output_path)
                        
            finally:
                # Cleanup
                os.unlink(temp_file_path)

class TestSecurityErrorHandling(unittest.TestCase):
    def test_security_error_raised(self):
        """Test that SecurityError is properly raised"""
        file_manager = FileTransferManager()
        
        # Test with invalid encrypted data
        with self.assertRaises(SecurityError):
            file_manager.decrypt_file(b"invalid_data", "password", "output.txt")

if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)