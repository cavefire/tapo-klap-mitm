from kasa.transports.klaptransport import KlapEncryptionSession, KlapTransport, KlapTransportV2, PACK_SIGNED_LONG
from kasa.credentials import Credentials, DEFAULT_CREDENTIALS, get_default_credentials
from cryptography.hazmat.primitives import padding
import hashlib


class KlapDecryptor:
    """A class for decrypting KLAP protocol data using handshake information."""
    
    def __init__(self, handshake1_request: str, handshake1_response: str, handshake2_request: str, username: str, password: str):
        """
        Initialize the KlapDecryptor with handshake data and credentials.
        
        Args:
            handshake1_request: Hex string of handshake1 request (local seed)
            handshake1_response: Hex string of handshake1 response (remote seed + server hash)
            handshake2_request: Hex string of handshake2 request (for verification)
            username: Username for authentication
            password: Password for authentication
        """
        self.handshake1_request_hex = handshake1_request
        self.handshake1_response_hex = handshake1_response
        self.handshake2_request_hex = handshake2_request
        self.username = username
        self.password = password
        
        self.local_seed = bytes.fromhex(handshake1_request)
        handshake1_response_bytes = bytes.fromhex(handshake1_response)
        self.remote_seed = handshake1_response_bytes[:16]
        self.server_hash = handshake1_response_bytes[16:]
        
        self.transport_class, self.auth_hash = self._find_auth_method()
        
        if not self.transport_class or self.auth_hash is None:
            raise ValueError("No matching authentication method found!")
        
        self._verify_handshake2()
        
        self.encryption_session = KlapEncryptionSession(self.local_seed, self.remote_seed, self.auth_hash)
    
    def _find_auth_method(self):
        """Find the correct authentication method by trying different combinations."""
        auth_methods = [
            ("User credentials (v1)", KlapTransport, Credentials(username=self.username, password=self.password)),
            ("User credentials (v2)", KlapTransportV2, Credentials(username=self.username, password=self.password)),
            ("Blank credentials (v1)", KlapTransport, Credentials()),
            ("Blank credentials (v2)", KlapTransportV2, Credentials()),
        ]
        
        for key, value in DEFAULT_CREDENTIALS.items():
            default_creds = get_default_credentials(value)
            auth_methods.append((f"Default {key} (v1)", KlapTransport, default_creds))
            auth_methods.append((f"Default {key} (v2)", KlapTransportV2, default_creds))
        
        for method_name, transport_class, credentials in auth_methods:
            auth_hash = transport_class.generate_auth_hash(credentials)
            calculated_hash = transport_class.handshake1_seed_auth_hash(self.local_seed, self.remote_seed, auth_hash)
            
            if calculated_hash == self.server_hash:
                print(f"Authentication method found: {method_name}")
                return transport_class, auth_hash
        
        return None, None
    
    def _verify_handshake2(self):
        if self.transport_class is None:
            raise ValueError("No valid transport class found for handshake2 verification!")
        expected_handshake2 = self.transport_class.handshake2_seed_auth_hash(self.local_seed, self.remote_seed, self.auth_hash)
        actual_handshake2 = bytes.fromhex(self.handshake2_request_hex)
        
        if expected_handshake2 != actual_handshake2:
            raise ValueError("Handshake2 verification failed!")
        
        print("Handshake2 verification: PASS")
    
    def decrypt(self, seq_number: int, encrypted_data_hex: str, verify_signature: bool = True) -> str:
        """
        Decrypt KLAP encrypted data.
        
        Args:
            seq_number: Sequence number used during encryption
            encrypted_data_hex: Hex string of encrypted data (signature + ciphertext)
            verify_signature: Whether to verify the signature (default: True)
        
        Returns:
            Decrypted string
        
        Raises:
            ValueError: If decryption fails or signature doesn't match
        """
        encrypted_data = bytes.fromhex(encrypted_data_hex)
        
        if len(encrypted_data) < 32:
            raise ValueError("Encrypted data too short!")
        
        signature = encrypted_data[:32]
        ciphertext = encrypted_data[32:]
        
        self.encryption_session._seq = seq_number
        self.encryption_session._generate_cipher()
        
        try:
            decryptor = self.encryption_session._cipher.decryptor()
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_bytes = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            if verify_signature:
                expected_signature = hashlib.sha256(
                    self.encryption_session._sig + 
                    PACK_SIGNED_LONG(seq_number) + 
                    ciphertext
                ).digest()
                
                if expected_signature != signature:
                    raise ValueError(f"Signature verification failed! Expected: {expected_signature.hex()}, Got: {signature.hex()}")
                
                print("Signature verification: PASS")
            
            try:
                return decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                for encoding in ['latin1', 'ascii', 'cp1252']:
                    try:
                        return decrypted_bytes.decode(encoding)
                    except:
                        continue
                
                return decrypted_bytes.hex()
                
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def encrypt(self, seq_number: int, data: str) -> str:
        """
        Encrypt data using KLAP protocol.
        
        Args:
            seq_number: Sequence number to use for encryption
            data: String data to encrypt
            
        Returns:
            Hex string of encrypted data (signature + ciphertext)
        """
        try:
            plaintext = data.encode('utf-8')
            
            self.encryption_session._seq = seq_number
            self.encryption_session._generate_cipher()
            
            encryptor = self.encryption_session._cipher.encryptor()
            
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext)
            padded_data += padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            signature = hashlib.sha256(
                self.encryption_session._sig + 
                PACK_SIGNED_LONG(seq_number) + 
                ciphertext
            ).digest()
            
            encrypted_data = signature + ciphertext
            
            return encrypted_data.hex().upper()
            
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")