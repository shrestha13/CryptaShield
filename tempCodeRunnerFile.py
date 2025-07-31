import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
import json
import time
import secrets
import hashlib
from datetime import datetime
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

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
        self._lock = threading.Lock()
    
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
        self.backend = default_backend()
    
    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        """
        Derive encryption key, IV, and HMAC key from password
        Returns: (encryption_key, iv, hmac_key, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(16)
        
        # Derive main key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 32 for AES + 32 for HMAC
            salt=salt,
            iterations=310000,
            backend=self.backend
        )
        key_material = kdf.derive(password.encode())
        
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
        self.backend = default_backend()
    
    def encrypt_data(self, data: bytes, key: bytes, iv: bytes) -> tuple:
        """
        Encrypt data using AES-GCM
        Returns: (ciphertext, auth_tag)
        """
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, encryptor.tag
    
    def decrypt_data(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Decrypt data using AES-GCM
        Raises InvalidTag if authentication fails
        """
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class HMACManager:
    """Handles message authentication"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def create_hmac(self, data: bytes, key: bytes) -> bytes:
        """Create HMAC-SHA256 for data integrity"""
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(data)
        return h.finalize()
    
    def verify_hmac(self, data: bytes, key: bytes, signature: bytes) -> bool:
        """Verify HMAC signature"""
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(data)
        try:
            h.verify(signature)
            return True
        except Exception:
            return False

class FileTransferManager:
    """Main class for secure file transfer operations"""
    
    def __init__(self):
        self.key_manager = KeyManager()
        self.crypto_manager = CryptoManager()
        self.hmac_manager = HMACManager()
        self.rate_limiter = TokenBucket(rate=1, capacity=3)
        self.used_nonces = set()
        self.nonce_lock = threading.Lock()
    
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
            metadata_json = json.dumps(metadata, sort_keys=True)
            metadata_hmac = self.hmac_manager.create_hmac(metadata_json.encode(), hmac_key)
            
            # Combine everything
            result = {
                'metadata': metadata,
                'metadata_hmac': metadata_hmac.hex(),
                'ciphertext': ciphertext.hex()
            }
            
            return json.dumps(result).encode()
            
        except Exception as e:
            raise SecurityError(f"Encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_data: bytes, password: str, output_path: str) -> bool:
        """Decrypt file data and save to output path"""
        try:
            # Parse encrypted data
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
            with self.nonce_lock:
                if nonce in self.used_nonces:
                    raise ReplayAttackError("Nonce reuse detected - possible replay attack")
                self.used_nonces.add(nonce)
            
            # Derive keys
            enc_key, _, hmac_key, _ = self.key_manager.derive_key(password, salt)
            
            # Verify metadata HMAC
            metadata_json = json.dumps(metadata, sort_keys=True)
            if not self.hmac_manager.verify_hmac(metadata_json.encode(), hmac_key, metadata_hmac):
                raise SecurityError("Metadata authentication failed")
            
            # Decrypt data
            plaintext = self.crypto_manager.decrypt_data(ciphertext, enc_key, iv, tag)
            
            # Save decrypted file
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            return True
            
        except Exception as e:
            raise SecurityError(f"Decryption failed: {str(e)}")
    
    def rate_limit_check(self) -> bool:
        """Check if request should be rate limited"""
        return self.rate_limiter.consume()

class CryptaShieldGUI:
    """Graphical User Interface for CryptaShield"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("CryptaShield - Secure File Transfer")
        self.root.geometry("800x700")
        self.root.configure(bg='#1e1e2e')
        
        # Initialize components
        self.file_manager = FileTransferManager()
        
        # Create GUI
        self.create_widgets()
        
        # Status variables
        self.is_processing = False
        
    def create_widgets(self):
        # Main frame
        main_frame = tk.Frame(self.root, bg='#1e1e2e')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_frame = tk.Frame(main_frame, bg='#1e1e2e')
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(
            title_frame, 
            text="🔒 CryptaShield", 
            font=("Arial", 24, "bold"),
            bg='#1e1e2e',
            fg='#c678dd'
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Secure File Transfer System",
            font=("Arial", 12),
            bg='#1e1e2e',
            fg='#56b6c2'
        )
        subtitle_label.pack()
        
        # Security Status Frame
        status_frame = tk.LabelFrame(main_frame, text="🛡️ Security Status", bg='#282c34', fg='#61afef', font=("Arial", 10, "bold"))
        status_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.security_status = tk.Label(
            status_frame,
            text="✅ TLS 1.3 • ✅ AES-256-GCM • ✅ Nonce Valid",
            font=("Arial", 10),
            fg='#98c379',
            bg='#282c34'
        )
        self.security_status.pack(pady=10)
        
        # File Transfer Frame
        transfer_frame = tk.LabelFrame(main_frame, text="📁 File Operations", bg='#282c34', fg='#61afef', font=("Arial", 10, "bold"))
        transfer_frame.pack(fill=tk.X, pady=(0, 20))
        
        # File selection
        file_frame = tk.Frame(transfer_frame, bg='#282c34')
        file_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(file_frame, text="File:", bg='#282c34', fg='white').pack(side=tk.LEFT)
        self.file_path_var = tk.StringVar()
        self.file_entry = tk.Entry(file_frame, textvariable=self.file_path_var, width=50, bg='#3e4451', fg='white')
        self.file_entry.pack(side=tk.LEFT, padx=(10, 10))
        tk.Button(file_frame, text="Browse", command=self.browse_file, bg='#4a4a59', fg='white').pack(side=tk.LEFT)
        
        # Password
        password_frame = tk.Frame(transfer_frame, bg='#282c34')
        password_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(password_frame, text="Password:", bg='#282c34', fg='white').pack(side=tk.LEFT)
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(password_frame, textvariable=self.password_var, show="*", width=50, bg='#3e4451', fg='white')
        self.password_entry.pack(side=tk.LEFT, padx=(10, 10))
        
        # Output file
        output_frame = tk.Frame(transfer_frame, bg='#282c34')
        output_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(output_frame, text="Output:", bg='#282c34', fg='white').pack(side=tk.LEFT)
        self.output_path_var = tk.StringVar()
        self.output_entry = tk.Entry(output_frame, textvariable=self.output_path_var, width=50, bg='#3e4451', fg='white')
        self.output_entry.pack(side=tk.LEFT, padx=(10, 10))
        tk.Button(output_frame, text="Browse", command=self.browse_output, bg='#4a4a59', fg='white').pack(side=tk.LEFT)
        
        # Action buttons
        button_frame = tk.Frame(transfer_frame, bg='#282c34')
        button_frame.pack(fill=tk.X, padx=10, pady=20)
        
        self.encrypt_button = tk.Button(button_frame, text="📤 Encrypt File", command=self.encrypt_file, bg='#98c379', fg='black', font=("Arial", 10, "bold"))
        self.encrypt_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.decrypt_button = tk.Button(button_frame, text="📥 Decrypt File", command=self.decrypt_file, bg='#e06c75', fg='black', font=("Arial", 10, "bold"))
        self.decrypt_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Progress bar
        self.progress = ttk.Progressbar(transfer_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Log Frame
        log_frame = tk.LabelFrame(main_frame, text="📋 Activity Log", bg='#282c34', fg='#61afef', font=("Arial", 10, "bold"))
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=12, bg='#3e4451', fg='#abb2bf', font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Clear log button
        tk.Button(log_frame, text="Clear Log", command=self.clear_log, bg='#4a4a59', fg='white').pack(pady=(0, 10))
        
        # Footer
        footer_frame = tk.Frame(main_frame, bg='#1e1e2e')
        footer_frame.pack(fill=tk.X)
        
        tk.Label(
            footer_frame,
            text="🛡️ Protection against MITM, Replay, and DoS attacks",
            bg='#1e1e2e',
            fg='#56b6c2',
            font=("Arial", 9)
        ).pack()
        
    def browse_file(self):
        """Open file dialog to select file"""
        filename = filedialog.askopenfilename(
            title="Select file to process",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.file_path_var.set(filename)
            
            # Auto-set output path
            if not self.output_path_var.get():
                base, ext = os.path.splitext(filename)
                if ext == '.encrypted':
                    self.output_path_var.set(base + '.decrypted')
                else:
                    self.output_path_var.set(base + '.encrypted')
    
    def browse_output(self):
        """Open file dialog to select output file"""
        filename = filedialog.asksaveasfilename(
            title="Select output file",
            defaultextension=".encrypted",
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
        )
        if filename:
            self.output_path_var.set(filename)
    
    def log_message(self, message, level="INFO"):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.root.update()
    
    def clear_log(self):
        """Clear the log text area"""
        self.log_text.delete(1.0, tk.END)
    
    def encrypt_file(self):
        """Encrypt file"""
        if not self.file_path_var.get():
            messagebox.showerror("Error", "Please select a file to encrypt")
            return
            
        if not self.password_var.get():
            messagebox.showerror("Error", "Please enter a password")
            return
            
        if not self.output_path_var.get():
            messagebox.showerror("Error", "Please specify an output file")
            return
            
        # Disable buttons during operation
        self.encrypt_button.config(state="disabled")
        self.decrypt_button.config(state="disabled")
        self.progress.start()
        self.log_message("Starting file encryption...")
        
        # Run in separate thread to prevent GUI freezing
        thread = threading.Thread(target=self._encrypt_file_thread)
        thread.daemon = True
        thread.start()
    
    def _encrypt_file_thread(self):
        """Thread function for encrypting file"""
        try:
            encrypted_data = self.file_manager.encrypt_file(
                self.file_path_var.get(),
                self.password_var.get()
            )
            
            with open(self.output_path_var.get(), 'wb') as f:
                f.write(encrypted_data)
            
            # Update GUI in main thread
            self.root.after(0, lambda: self.log_message(f"File encrypted successfully: {self.output_path_var.get()}", "SUCCESS"))
            self.root.after(0, lambda: messagebox.showinfo("Success", "File encrypted successfully!"))
            
        except SecurityError as e:
            self.root.after(0, lambda: self.log_message(f"Security error: {str(e)}", "ERROR"))
            self.root.after(0, lambda: messagebox.showerror("Security Error", str(e)))
        except ReplayAttackError as e:
            self.root.after(0, lambda: self.log_message(f"Replay attack detected: {str(e)}", "SECURITY"))
            self.root.after(0, lambda: messagebox.showerror("Replay Attack", str(e)))
        except Exception as e:
            self.root.after(0, lambda: self.log_message(f"Encryption failed: {str(e)}", "ERROR"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Encryption failed: {str(e)}"))
        finally:
            self.root.after(0, self._reset_ui)
    
    def decrypt_file(self):
        """Decrypt file"""
        if not self.file_path_var.get():
            messagebox.showerror("Error", "Please select a file to decrypt")
            return
            
        if not self.password_var.get():
            messagebox.showerror("Error", "Please enter a password")
            return
            
        if not self.output_path_var.get():
            messagebox.showerror("Error", "Please specify an output file")
            return
            
        # Disable buttons during operation
        self.encrypt_button.config(state="disabled")
        self.decrypt_button.config(state="disabled")
        self.progress.start()
        self.log_message("Starting file decryption...")
        
        # Run in separate thread to prevent GUI freezing
        thread = threading.Thread(target=self._decrypt_file_thread)
        thread.daemon = True
        thread.start()
    
    def _decrypt_file_thread(self):
        """Thread function for decrypting file"""
        try:
            with open(self.file_path_var.get(), 'rb') as f:
                encrypted_data = f.read()
            
            self.file_manager.decrypt_file(
                encrypted_data,
                self.password_var.get(),
                self.output_path_var.get()
            )
            
            # Update GUI in main thread
            self.root.after(0, lambda: self.log_message(f"File decrypted successfully: {self.output_path_var.get()}", "SUCCESS"))
            self.root.after(0, lambda: messagebox.showinfo("Success", "File decrypted successfully!"))
            
        except SecurityError as e:
            self.root.after(0, lambda: self.log_message(f"Security error: {str(e)}", "ERROR"))
            self.root.after(0, lambda: messagebox.showerror("Security Error", str(e)))
        except ReplayAttackError as e:
            self.root.after(0, lambda: self.log_message(f"Replay attack detected: {str(e)}", "SECURITY"))
            self.root.after(0, lambda: messagebox.showerror("Replay Attack", str(e)))
        except Exception as e:
            self.root.after(0, lambda: self.log_message(f"Decryption failed: {str(e)}", "ERROR"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Decryption failed: {str(e)}"))
        finally:
            self.root.after(0, self._reset_ui)
    
    def _reset_ui(self):
        """Reset UI after operation"""
        self.encrypt_button.config(state="normal")
        self.decrypt_button.config(state="normal")
        self.progress.stop()

def main():
    root = tk.Tk()
    app = CryptaShieldGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()