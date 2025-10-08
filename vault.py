import os
import json
import hashlib
import tempfile
from base64 import urlsafe_b64encode
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_FILE_PATH = os.path.join(BASE_DIR, "vault.txt")
METADATA_DEFAULT = os.path.join(BASE_DIR, "vault_metadata.json")


class Vault:
    """
    Vault simple que cifra/descifra un archivo con AES-GCM.
    - No guarda la clave AES en claro.
    - Guarda salt + hash(derived_key) en metadata para verificar contraseña.
    """
    def __init__(self):
        self.session = False
        self.salt: Optional[bytes] = None
        self._key: Optional[bytes] = None  # clave raw (32 bytes)

    def derive_key(self, password: str, salt: bytes, iterations: int = 200_000) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode())  # raw 32 bytes

    def _atomic_write_json(self, path: str, obj: dict, mode: int = 0o600):
        # escribe de forma atómica y con permisos restringidos
        dirn = os.path.dirname(path) or "."
        fd, tmp_path = tempfile.mkstemp(dir=dirn)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(obj, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            os.chmod(path, mode)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def load_vault(self, password: str, metadata_path: str = METADATA_DEFAULT) -> int:
        """
        Si metadata_path no existe => crea un nuevo vault (devuelve 0).
        Si existe => verifica la contraseña y abre sesión (devuelve 1).
        """
        if metadata_path is None:
            metadata_path = METADATA_DEFAULT

        if not os.path.exists(metadata_path):
            # crear nuevo vault
            self.salt = os.urandom(16)
            key = self.derive_key(password, self.salt)
            key_hash = hashlib.sha256(key).hexdigest()

            data = {"salt": self.salt.hex(), "key_hash": key_hash}
            # escribir metadata y vault vacío de forma segura
            self._atomic_write_json(metadata_path, data)
            # vault inicial sin contenido cifrado (se detecta en read_file)
            self._atomic_write_json(VAULT_FILE_PATH, {"ciphertext": "", "iv": ""})
            self._key = key
            self.session = True
            return 0
        else:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            self.salt = bytes.fromhex(metadata["salt"])
            key = self.derive_key(password, self.salt)
            key_hash = hashlib.sha256(key).hexdigest()
            if key_hash != metadata.get("key_hash"):
                raise ValueError("Incorrect password.")
            self._key = key
            self.session = True
            return 1

    def end_session(self):
        if not self.session:
            return
        self.session = False
        if self._key is not None:
            try:
                # sobrescribir bytearray si fuera posible
                temp = bytearray(len(self._key))
                for i in range(len(temp)):
                    temp[i] = 0
            except Exception:
                pass
        self._key = None
        self.salt = None

    def encrypt(self, plaintext: str):
        if not self.session or self._key is None:
            raise PermissionError("No active session. Please authenticate first.")
        aesgcm = AESGCM(self._key)
        iv = os.urandom(12)
        ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)
        return iv, ciphertext

    def decrypt(self, ciphertext: bytes, iv: bytes) -> str:
        if not self.session or self._key is None:
            raise PermissionError("No active session. Please authenticate first.")
        aesgcm = AESGCM(self._key)
        return aesgcm.decrypt(iv, ciphertext, None).decode()

    def save_file(self, plaintext: str) -> bool:
        iv, ciphertext = self.encrypt(plaintext)
        return self.save_object_to_file(ciphertext.hex(), iv.hex())

    def read_file(self) -> Optional[str]:
        if not self.session:
            raise PermissionError("No active session. Please authenticate first.")
        if not os.path.exists(VAULT_FILE_PATH):
            raise FileNotFoundError("Vault file does not exist.")
        with open(VAULT_FILE_PATH, "r") as f:
            obj = json.load(f)
        # vault vacío: devolver None o cadena vacía según prefieras
        if not obj.get("ciphertext"):
            return None
        return self.decrypt(bytes.fromhex(obj["ciphertext"]), bytes.fromhex(obj["iv"]))

    def save_object_to_file(self, ciphertext_hex: str, iv_hex: str) -> bool:
        obj = {"ciphertext": ciphertext_hex, "iv": iv_hex}
        try:
            self._atomic_write_json(VAULT_FILE_PATH, obj)
            return True
        except Exception as e:
            # aquí conviene registrar el error; por ahora re-lanzamos
            raise

    def file_to_object(self) -> dict:
        if not os.path.exists(VAULT_FILE_PATH):
            raise FileNotFoundError("Vault file does not exist.")
        with open(VAULT_FILE_PATH, "r") as file:
            return json.load(file)
