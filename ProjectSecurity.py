from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib


def hash_Password(s):
    """
        Has the password using SHA-256
        """
    return hashlib.sha256(s.encode()).hexdigest()


def generate_rsa_keys():
    """
    Generates a private key and public key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(message, public_key):
    """
    Encrypts a message using the public key.
    """
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def rsa_decrypt(encrypted_message, private_key):
    """
    Decrypts an encrypted message using the private key.
    """
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode('utf-8')


def generate_symmetric_key():
    """Generate a Fernet symmetric key."""
    return Fernet.generate_key()


def symmetric_encrypt_file(message, key):
    """Encrypt message using a symmetric key."""
    f = Fernet(key)
    return f.encrypt(message)  # message is already bytes


def symmetric_decrypt_file(encrypted_message, key):
    """Decrypt message using a symmetric key."""
    f = Fernet(key)
    return f.decrypt(encrypted_message)  # returns bytes, no need to decode


def symmetric_encrypt(message, key):
    """Encrypt message using a symmetric key."""
    f = Fernet(key)
    # Ensure the message is in bytes
    encoded_message = message.encode()
    return f.encrypt(encoded_message)


def symmetric_decrypt(encrypted_message, key):
    """Decrypt message using a symmetric key."""
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    # Decode the decrypted message from bytes to string
    return decrypted_message.decode()


def serialize_public_key(public_key):
    """ This function takes a public key object and converts it into a byte string
    in PEM format, making it easier to store or transmit. """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def load_public_key(pem_data):
    """
        This function takes PEM format data as input and converts it into a public key
        object. It is useful for loading a public key from a stored or transmitted PEM
        formatted string.
        """
    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key
