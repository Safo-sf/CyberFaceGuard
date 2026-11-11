import os
import json
import secrets
import struct
import hashlib
import hmac
from pathlib import Path, PurePosixPath

import win32crypt

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CyberFaceGuard - Secure Vault V1.1
# ============================================================

APP_NAME = "CyberFaceGuard"

LOCAL_APPDATA = os.getenv("LOCALAPPDATA")

if not LOCAL_APPDATA:
    LOCAL_APPDATA = os.path.expanduser("~")

APP_DATA_DIR = Path(LOCAL_APPDATA) / APP_NAME

# V1.1 uses separate storage.
# The old V1.0 vault is NOT touched.
VAULT_DIR = APP_DATA_DIR / "vault"

ENCRYPTED_DIR = VAULT_DIR / "encrypted_v11"
METADATA_FILE = VAULT_DIR / "vault_v11.dat"
KEY_FILE = VAULT_DIR / "vault_v11.key"

VAULT_VERSION = 11

# File encryption format
FILE_MAGIC = b"CFGVLT11"
META_MAGIC = b"CFGMETA11"

# 1 MB chunks prevent large files from being loaded completely into RAM.
CHUNK_SIZE = 1024 * 1024

META_AAD = b"CyberFaceGuard-Vault-Metadata-V11"


VAULT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

ENCRYPTED_DIR.mkdir(
    parents=True,
    exist_ok=True
)


class VaultManager:

    def __init__(self):

        self.unlocked = False
        self._vault_key = None

        self.metadata = {
            "version": VAULT_VERSION,
            "items": []
        }

        self._initialize_key()

    # ========================================================
    # KEY MANAGEMENT
    # ========================================================

    def _initialize_key(self):

        if KEY_FILE.exists():
            return

        key = AESGCM.generate_key(
            bit_length=256
        )

        protected_key = win32crypt.CryptProtectData(
            key,
            "CyberFaceGuard Vault Key",
            None,
            None,
            None,
            0
        )

        temp_file = KEY_FILE.with_suffix(
            ".tmp"
        )

        try:

            temp_file.write_bytes(
                protected_key
            )

            os.replace(
                temp_file,
                KEY_FILE
            )

        except Exception:

            if temp_file.exists():

                try:
                    temp_file.unlink()
                except Exception:
                    pass

            raise

    def _load_key(self):

        if not KEY_FILE.exists():

            raise FileNotFoundError(
                "Vault key not found."
            )

        protected_key = KEY_FILE.read_bytes()

        key = win32crypt.CryptUnprotectData(
            protected_key,
            None,
            None,
            None,
            0
        )[1]

        if len(key) != 32:

            raise ValueError(
                "Invalid vault key."
            )

        return key

    # ========================================================
    # BASIC HELPERS
    # ========================================================

    def _require_unlock(self):

        if not self.unlocked:

            raise PermissionError(
                "Vault is locked."
            )

        if self._vault_key is None:

            raise PermissionError(
                "Vault key is unavailable."
            )

    def is_unlocked(self):

        return self.unlocked

    def _default_metadata(self):

        return {
            "version": VAULT_VERSION,
            "items": []
        }

    def _normalize_virtual_path(
        self,
        value
    ):

        value = str(value).strip()

        value = value.replace(
            "\\",
            "/"
        )

        if not value:

            raise ValueError(
                "Virtual path cannot be empty."
            )

        path = PurePosixPath(value)

        if path.is_absolute():

            raise ValueError(
                "Absolute virtual paths are not allowed."
            )

        parts = []

        for part in path.parts:

            if part in ("", "."):
                continue

            if part == "..":

                raise ValueError(
                    "Invalid virtual path."
                )

            parts.append(part)

        if not parts:

            raise ValueError(
                "Invalid virtual path."
            )

        return "/".join(parts)

    def _is_inside_vault(
        self,
        path
    ):

        try:

            path = Path(path).resolve()
            vault = VAULT_DIR.resolve()

            return (
                path == vault
                or vault in path.parents
            )

        except Exception:

            return False

    def _get_item(
        self,
        item_id
    ):

        for item in self.metadata["items"]:

            if item["id"] == item_id:
                return item

        return None

    def get_item(
        self,
        item_id
    ):

        self._require_unlock()

        item = self._get_item(
            item_id
        )

        if item is None:
            return None

        return dict(item)

    # ========================================================
    # HASH / FILE INTEGRITY
    # ========================================================

    def _calculate_sha256(
        self,
        file_path
    ):

        file_path = Path(
            file_path
        )

        if not file_path.exists():

            raise FileNotFoundError(
                f"File not found:\n{file_path}"
            )

        if not file_path.is_file():

            raise ValueError(
                f"Not a file:\n{file_path}"
            )

        digest = hashlib.sha256()

        with open(
            file_path,
            "rb"
        ) as file:

            while True:

                chunk = file.read(
                    CHUNK_SIZE
                )

                if not chunk:
                    break

                digest.update(
                    chunk
                )

        return digest.hexdigest()

    def _verify_file_integrity(
        self,
        file_path,
        expected_size,
        expected_sha256
    ):

        file_path = Path(
            file_path
        )

        if not file_path.exists():

            raise FileNotFoundError(
                "Integrity verification file is missing."
            )

        actual_size = file_path.stat().st_size

        if actual_size != int(
            expected_size
        ):

            raise ValueError(
                "File size verification failed."
            )

        actual_sha256 = (
            self._calculate_sha256(
                file_path
            )
        )

        if expected_sha256:

            if not hmac.compare_digest(
                actual_sha256.lower(),
                str(expected_sha256).lower()
            ):

                raise ValueError(
                    "SHA-256 integrity verification failed."
                )

        return actual_sha256

    # ========================================================
    # ENCRYPTED METADATA
    # ========================================================

    def _load_metadata(self):

        if not METADATA_FILE.exists():

            return self._default_metadata()

        encrypted = METADATA_FILE.read_bytes()

        minimum_size = (
            len(META_MAGIC)
            + 12
            + 16
        )

        if len(encrypted) < minimum_size:

            raise ValueError(
                "Vault metadata is corrupted."
            )

        if not encrypted.startswith(
            META_MAGIC
        ):

            raise ValueError(
                "Invalid Vault metadata."
            )

        offset = len(META_MAGIC)

        nonce = encrypted[
            offset:
            offset + 12
        ]

        ciphertext = encrypted[
            offset + 12:
        ]

        aes = AESGCM(
            self._vault_key
        )

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            META_AAD
        )

        data = json.loads(
            plaintext.decode(
                "utf-8"
            )
        )

        if not isinstance(
            data,
            dict
        ):

            raise ValueError(
                "Invalid Vault metadata."
            )

        if data.get("version") != VAULT_VERSION:

            raise ValueError(
                "Unsupported Vault metadata version."
            )

        if not isinstance(
            data.get("items"),
            list
        ):

            raise ValueError(
                "Invalid Vault item list."
            )

        return data

    def _save_metadata(self):

        self._require_unlock()

        payload = json.dumps(
            self.metadata,
            indent=2,
            ensure_ascii=False
        ).encode(
            "utf-8"
        )

        nonce = secrets.token_bytes(
            12
        )

        aes = AESGCM(
            self._vault_key
        )

        ciphertext = aes.encrypt(
            nonce,
            payload,
            META_AAD
        )

        data = (
            META_MAGIC
            + nonce
            + ciphertext
        )

        temp_file = METADATA_FILE.with_suffix(
            ".tmp"
        )

        try:

            temp_file.write_bytes(
                data
            )

            os.replace(
                temp_file,
                METADATA_FILE
            )

        except Exception:

            if temp_file.exists():

                try:
                    temp_file.unlink()
                except Exception:
                    pass

            raise

    # ========================================================
    # UNLOCK / LOCK
    # ========================================================

    def unlock(self):

        if self.unlocked:
            return True

        key = self._load_key()

        self._vault_key = key

        try:

            self.metadata = (
                self._load_metadata()
            )

        except Exception:

            self._vault_key = None
            self.unlocked = False

            raise

        self.unlocked = True

        return True

    def lock(self):

        self.metadata = (
            self._default_metadata()
        )

        self._vault_key = None

        self.unlocked = False

    # ========================================================
    # PATH / DUPLICATE VALIDATION
    # ========================================================

    def _check_virtual_path_available(
        self,
        virtual_path,
        new_type
    ):

        virtual_path = (
            self._normalize_virtual_path(
                virtual_path
            )
        )

        for item in self.metadata["items"]:

            existing = item[
                "virtual_path"
            ]

            existing_type = item[
                "type"
            ]

            if existing == virtual_path:

                raise FileExistsError(
                    f"An item already exists at:\n"
                    f"{virtual_path}"
                )

            # A file cannot contain another item.
            if (
                existing_type == "file"
                and virtual_path.startswith(
                    existing + "/"
                )
            ):

                raise ValueError(
                    f"'{existing}' is already a file."
                )

            # New file cannot replace a folder.
            if (
                new_type == "file"
                and existing.startswith(
                    virtual_path + "/"
                )
            ):

                raise ValueError(
                    f"'{virtual_path}' already contains items."
                )

        return virtual_path

    # ========================================================
    # FILE ENCRYPTION
    # ========================================================

    def _encrypt_file(
        self,
        source,
        destination,
        item_id
    ):

        self._require_unlock()

        source = Path(
            source
        )

        destination = Path(
            destination
        )

        aes = AESGCM(
            self._vault_key
        )

        aad = (
            f"CyberFaceGuard:{item_id}"
        ).encode(
            "utf-8"
        )

        temp_file = destination.with_suffix(
            ".tmp"
        )

        try:

            with open(
                source,
                "rb"
            ) as src, open(
                temp_file,
                "wb"
            ) as dst:

                dst.write(
                    FILE_MAGIC
                )

                while True:

                    chunk = src.read(
                        CHUNK_SIZE
                    )

                    if not chunk:
                        break

                    nonce = secrets.token_bytes(
                        12
                    )

                    ciphertext = aes.encrypt(
                        nonce,
                        chunk,
                        aad
                    )

                    dst.write(
                        struct.pack(
                            ">I",
                            len(chunk)
                        )
                    )

                    dst.write(
                        nonce
                    )

                    dst.write(
                        ciphertext
                    )

            os.replace(
                temp_file,
                destination
            )

        except Exception:

            if temp_file.exists():

                try:
                    temp_file.unlink()
                except Exception:
                    pass

            raise

    # ========================================================
    # FILE DECRYPTION
    # ========================================================

    def _decrypt_file(
        self,
        encrypted_file,
        destination,
        item_id
    ):

        self._require_unlock()

        encrypted_file = Path(
            encrypted_file
        )

        destination = Path(
            destination
        )

        aes = AESGCM(
            self._vault_key
        )

        aad = (
            f"CyberFaceGuard:{item_id}"
        ).encode(
            "utf-8"
        )

        temp_file = destination.with_name(
            destination.name
            + ".cguard_restore_tmp"
        )

        try:

            with open(
                encrypted_file,
                "rb"
            ) as src:

                magic = src.read(
                    len(FILE_MAGIC)
                )

                if magic != FILE_MAGIC:

                    raise ValueError(
                        "Invalid encrypted file format."
                    )

                destination.parent.mkdir(
                    parents=True,
                    exist_ok=True
                )

                with open(
                    temp_file,
                    "wb"
                ) as dst:

                    while True:

                        length_data = src.read(
                            4
                        )

                        if not length_data:
                            break

                        if len(length_data) != 4:

                            raise ValueError(
                                "Corrupted encrypted file."
                            )

                        plain_length = struct.unpack(
                            ">I",
                            length_data
                        )[0]

                        if (
                            plain_length < 0
                            or plain_length > CHUNK_SIZE
                        ):

                            raise ValueError(
                                "Invalid encrypted chunk."
                            )

                        nonce = src.read(
                            12
                        )

                        if len(nonce) != 12:

                            raise ValueError(
                                "Corrupted encryption nonce."
                            )

                        ciphertext = src.read(
                            plain_length + 16
                        )

                        if len(ciphertext) != (
                            plain_length + 16
                        ):

                            raise ValueError(
                                "Corrupted encrypted data."
                            )

                        plaintext = aes.decrypt(
                            nonce,
                            ciphertext,
                            aad
                        )

                        if len(plaintext) != plain_length:

                            raise ValueError(
                                "Integrity verification failed."
                            )

                        dst.write(
                            plaintext
                        )

            os.replace(
                temp_file,
                destination
            )

        except Exception:

            if temp_file.exists():

                try:
                    temp_file.unlink()
                except Exception:
                    pass

            raise

    # ========================================================
    # ADD FILE
    # ========================================================

    def _add_file_internal(
        self,
        source,
        virtual_path
    ):

        source = Path(
            source
        ).resolve()

        if not source.exists():

            raise FileNotFoundError(
                f"File not found:\n{source}"
            )

        if not source.is_file():

            raise ValueError(
                f"Not a file:\n{source}"
            )

        if self._is_inside_vault(
            source
        ):

            raise ValueError(
                "You cannot add a file from inside the Vault."
            )

        virtual_path = (
            self._check_virtual_path_available(
                virtual_path,
                "file"
            )
        )

        item_id = secrets.token_hex(
            16
        )

        encrypted_name = (
            f"{item_id}.cguard"
        )

        encrypted_path = (
            ENCRYPTED_DIR
            / encrypted_name
        )

        size = source.stat().st_size

        # ----------------------------------------------------
        # 1. Calculate original SHA-256
        # ----------------------------------------------------

        original_sha256 = (
            self._calculate_sha256(
                source
            )
        )

        verify_path = (
            ENCRYPTED_DIR
            / f"{item_id}.verify"
        )

        try:

            # ------------------------------------------------
            # 2. Encrypt
            # ------------------------------------------------

            self._encrypt_file(
                source,
                encrypted_path,
                item_id
            )

            # ------------------------------------------------
            # 3. Decrypt temporary copy
            # ------------------------------------------------

            self._decrypt_file(
                encrypted_path,
                verify_path,
                item_id
            )

            # ------------------------------------------------
            # 4. Verify size + SHA-256
            # ------------------------------------------------

            verified_sha256 = (
                self._verify_file_integrity(
                    verify_path,
                    size,
                    original_sha256
                )
            )
            if not hmac.compare_digest(
    verified_sha256,
    original_sha256
):

                raise ValueError(
                    "SHA-256 verification failed."
                )

            # Temporary verification file
            # is no longer needed.
            verify_path.unlink(
                missing_ok=True
            )

            # ------------------------------------------------
            # 5. Add metadata
            # ------------------------------------------------

            item = {
                "id": item_id,
                "original_name": source.name,
                "original_path": str(source),
                "virtual_path": virtual_path,
                "encrypted_file": encrypted_name,
                "type": "file",
                "size": size,
                "sha256": original_sha256,
                "status": "ENCRYPTED"
            }

            self.metadata[
                "items"
            ].append(
                item
            )

            return item

        except Exception:

            if verify_path.exists():

                try:
                    verify_path.unlink()
                except Exception:
                    pass

            if encrypted_path.exists():

                try:
                    encrypted_path.unlink()
                except Exception:
                    pass

            raise

    # ========================================================
    # PROTECT FILE
    # ========================================================

    def protect_file(
        self,
        file_path,
        move_to_vault=True,
        virtual_path=None
    ):

        self._require_unlock()

        source = Path(
            file_path
        ).resolve()

        if not source.exists():

            raise FileNotFoundError(
                f"File not found:\n{source}"
            )

        if not source.is_file():

            raise ValueError(
                "Selected path is not a file."
            )

        if self._is_inside_vault(
            source
        ):

            raise ValueError(
                "You cannot protect a file inside the Vault."
            )

        if virtual_path is None:

            virtual_path = source.name

        old_metadata = list(
            self.metadata["items"]
        )

        metadata_committed = False

        item = None

        try:

            # ------------------------------------------------
            # Encrypt + verify + add metadata
            # ------------------------------------------------

            item = self._add_file_internal(
                source,
                virtual_path
            )

            # ------------------------------------------------
            # Commit metadata
            # ------------------------------------------------

            self._save_metadata()

            metadata_committed = True

            # ------------------------------------------------
            # Delete original only AFTER commit
            # ------------------------------------------------

            if move_to_vault:

                try:

                    source.unlink()

                except Exception as error:

                    # IMPORTANT:
                    #
                    # Encryption already succeeded.
                    # Metadata already committed.
                    #
                    # Therefore we KEEP the encrypted copy.
                    # We do NOT rollback.
                    raise RuntimeError(
                        "File was encrypted successfully, "
                        "but the original could not be deleted.\n\n"
                        f"{error}"
                    )

            return True

        except Exception:

            # ------------------------------------------------
            # Rollback ONLY before metadata was committed.
            # ------------------------------------------------

            if not metadata_committed:

                self.metadata[
                    "items"
                ] = old_metadata

                if item is not None:

                    encrypted_name = item.get(
                        "encrypted_file"
                    )

                    if encrypted_name:

                        encrypted_path = (
                            ENCRYPTED_DIR
                            / encrypted_name
                        )

                        encrypted_path.unlink(
                            missing_ok=True
                        )

                try:

                    self._save_metadata()

                except Exception:
                    pass

            # If metadata_committed == True:
            #
            # DO NOT rollback.
            #
            # The encrypted item is already safely stored.

            raise

    # ========================================================
    # ADD FOLDER ITEM
    # ========================================================

    def _add_folder_item(
        self,
        name,
        virtual_path,
        original_path
    ):

        virtual_path = (
            self._check_virtual_path_available(
                virtual_path,
                "folder"
            )
        )

        item = {
            "id": secrets.token_hex(
                16
            ),
            "original_name": name,
            "original_path": str(
                original_path
            ),
            "virtual_path": virtual_path,
            "encrypted_file": None,
            "type": "folder",
            "size": 0,
            "status": "FOLDER"
        }

        self.metadata[
            "items"
        ].append(
            item
        )

        return item

    # ========================================================
    # PROTECT FOLDER
    # ========================================================

    def protect_folder(
        self,
        folder_path,
        move_to_vault=True
    ):

        self._require_unlock()

        source = Path(
            folder_path
        ).resolve()

        if not source.exists():

            raise FileNotFoundError(
                f"Folder not found:\n{source}"
            )

        if not source.is_dir():

            raise ValueError(
                "Selected path is not a folder."
            )

        if self._is_inside_vault(
            source
        ):

            raise ValueError(
                "You cannot add the Vault folder itself."
            )

        root_virtual = (
            self._check_virtual_path_available(
                source.name,
                "folder"
            )
        )

        old_metadata = list(
            self.metadata["items"]
        )

        created_files = []

        metadata_committed = False

        deletion_errors = []

        try:

            # ------------------------------------------------
            # 1. Root folder
            # ------------------------------------------------

            self._add_folder_item(
                source.name,
                root_virtual,
                source
            )

            # ------------------------------------------------
            # 2. Walk folder tree
            # ------------------------------------------------

            for current_root, dirs, files in os.walk(
                source,
                followlinks=False
            ):

                current_root = Path(
                    current_root
                )

                relative = current_root.relative_to(
                    source
                )

                if str(relative) != ".":

                    folder_virtual = (
                        root_virtual
                        + "/"
                        + relative.as_posix()
                    )

                    self._add_folder_item(
                        current_root.name,
                        folder_virtual,
                        current_root
                    )

                for filename in files:

                    file_path = (
                        current_root
                        / filename
                    )

                    # Skip symbolic links.
                    if file_path.is_symlink():
                        continue

                    relative_file = (
                        file_path
                        .relative_to(source)
                        .as_posix()
                    )

                    file_virtual = (
                        root_virtual
                        + "/"
                        + relative_file
                    )

                    item = self._add_file_internal(
                        file_path,
                        file_virtual
                    )

                    created_files.append(
                        item
                    )

            # ------------------------------------------------
            # 3. Commit metadata
            # ------------------------------------------------

            self._save_metadata()

            metadata_committed = True

            # ------------------------------------------------
            # 4. Delete original files
            # ------------------------------------------------

            if move_to_vault:

                for item in created_files:

                    original = Path(
                        item["original_path"]
                    )

                    if not original.exists():
                        continue

                    try:

                        original.unlink()

                    except Exception as error:

                        deletion_errors.append(
                            f"{original}\n{error}"
                        )

                # ------------------------------------------------
                # 5. Remove empty directories
                # ------------------------------------------------

                directories = []

                for current_root, dirs, files in os.walk(
                    source,
                    topdown=False
                ):

                    directories.append(
                        Path(current_root)
                    )

                for directory in directories:

                    try:

                        directory.rmdir()

                    except OSError:
                        pass

                try:

                    source.rmdir()

                except OSError:
                    pass

            # ------------------------------------------------
            # 6. Report deletion problems AFTER commit
            # ------------------------------------------------

            if deletion_errors:

                raise RuntimeError(
                    "Folder was encrypted successfully, "
                    "but some original files could not be deleted.\n\n"
                    + "\n".join(
                        deletion_errors
                    )
                )

            return True

        except Exception:

            # ------------------------------------------------
            # IMPORTANT:
            #
            # If metadata has already been committed,
            # DO NOT delete encrypted copies.
            #
            # Some original files may already have been
            # deleted, so rollback here could cause DATA LOSS.
            # ------------------------------------------------

            if metadata_committed:

                raise

            # ------------------------------------------------
            # Encryption/metadata commit failed.
            # Safe to rollback this operation.
            # ------------------------------------------------

            current_items = self.metadata[
                "items"
            ]

            old_ids = {
                item["id"]
                for item in old_metadata
            }

            new_items = [
                item
                for item in current_items
                if item["id"] not in old_ids
            ]

            for item in new_items:

                encrypted_name = item.get(
                    "encrypted_file"
                )

                if encrypted_name:

                    encrypted_path = (
                        ENCRYPTED_DIR
                        / encrypted_name
                    )

                    encrypted_path.unlink(
                        missing_ok=True
                    )

            self.metadata[
                "items"
            ] = old_metadata

            try:

                self._save_metadata()

            except Exception:
                pass

            raise

    # ========================================================
    # CREATE VIRTUAL FOLDER
    # ========================================================

    def create_folder(
        self,
        folder_name,
        parent_path=""
    ):

        self._require_unlock()

        folder_name = str(
            folder_name
        ).strip()

        if not folder_name:

            raise ValueError(
                "Folder name cannot be empty."
            )

        if "/" in folder_name or "\\" in folder_name:

            raise ValueError(
                "Folder name cannot contain / or \\."
            )

        if folder_name in (".", ".."):

            raise ValueError(
                "Invalid folder name."
            )

        if parent_path:

            parent_path = (
                self._normalize_virtual_path(
                    parent_path
                )
            )

            virtual_path = (
                parent_path
                + "/"
                + folder_name
            )

        else:

            virtual_path = folder_name

        self._check_virtual_path_available(
            virtual_path,
            "folder"
        )

        item = {
            "id": secrets.token_hex(
                16
            ),
            "original_name": folder_name,
            "original_path": "",
            "virtual_path": virtual_path,
            "encrypted_file": None,
            "type": "folder",
            "size": 0,
            "status": "FOLDER"
        }

        self.metadata[
            "items"
        ].append(
            item
        )

        try:

            self._save_metadata()

        except Exception:

            self.metadata[
                "items"
            ].remove(
                item
            )

            raise

        return item

    # ========================================================
    # GET ITEMS
    # ========================================================

    def get_items(self):

        if not self.unlocked:

            return []

        return [
            dict(item)
            for item in self.metadata[
                "items"
            ]
        ]

    # ========================================================
    # SEARCH
    # ========================================================

    def search_items(
        self,
        query=""
    ):

        if not self.unlocked:

            return []

        query = str(
            query
        ).strip().lower()

        if not query:

            return self.get_items()

        results = []

        for item in self.metadata[
            "items"
        ]:

            name = item.get(
                "original_name",
                ""
            ).lower()

            virtual_path = item.get(
                "virtual_path",
                ""
            ).lower()

            if (
                query in name
                or query in virtual_path
            ):

                results.append(
                    dict(item)
                )

        return results

    # ========================================================
    # EXPORT / RESTORE
    # ========================================================

    def export_item(
        self,
        item_id,
        destination
    ):

        self._require_unlock()

        item = self._get_item(
            item_id
        )

        if item is None:

            raise FileNotFoundError(
                "Vault item not found."
            )

        destination = Path(
            destination
        ).expanduser()

        # ====================================================
        # FILE
        # ====================================================

        if item["type"] == "file":

            if destination.exists():

                raise FileExistsError(
                    f"Destination already exists:\n"
                    f"{destination}"
                )

            encrypted_path = (
                ENCRYPTED_DIR
                / item["encrypted_file"]
            )

            if not encrypted_path.exists():

                raise FileNotFoundError(
                    "Encrypted Vault file is missing."
                )

            self._decrypt_file(
                encrypted_path,
                destination,
                item["id"]
            )

            try:

                expected_sha256 = item.get(
                    "sha256"
                )

                self._verify_file_integrity(
                    destination,
                    item.get(
                        "size",
                        0
                    ),
                    expected_sha256
                )

            except Exception:

                try:

                    if destination.exists():
                        destination.unlink()

                except Exception:
                    pass

                raise

            return str(
                destination
            )

        # ====================================================
        # FOLDER
        # ====================================================

        if item["type"] == "folder":

            base = PurePosixPath(
                item["virtual_path"]
            )

            output_root = (
                destination
                / item["original_name"]
            )

            if output_root.exists():

                raise FileExistsError(
                    f"Destination folder already exists:\n"
                    f"{output_root}"
                )

            files_exported = 0

            try:

                for child in self.metadata[
                    "items"
                ]:

                    if child["type"] != "file":
                        continue

                    child_path = PurePosixPath(
                        child["virtual_path"]
                    )

                    try:

                        relative = (
                            child_path.relative_to(
                                base
                            )
                        )

                    except ValueError:

                        continue

                    output_file = (
                        output_root
                        / Path(
                            *relative.parts
                        )
                    )

                    encrypted_path = (
                        ENCRYPTED_DIR
                        / child["encrypted_file"]
                    )

                    if not encrypted_path.exists():

                        raise FileNotFoundError(
                            f"Encrypted file missing:\n"
                            f"{child['original_name']}"
                        )

                    self._decrypt_file(
                        encrypted_path,
                        output_file,
                        child["id"]
                    )

                    self._verify_file_integrity(
                        output_file,
                        child.get(
                            "size",
                            0
                        ),
                        child.get(
                            "sha256"
                        )
                    )

                    files_exported += 1

                return str(
                    output_root
                )

            except Exception:

                # Remove incomplete export.
                if output_root.exists():

                    for path in sorted(
                        output_root.rglob("*"),
                        reverse=True
                    ):

                        try:

                            if path.is_file():
                                path.unlink()

                            elif path.is_dir():
                                path.rmdir()

                        except Exception:
                            pass

                    try:
                        output_root.rmdir()
                    except Exception:
                        pass

                raise

        raise ValueError(
            "Unknown Vault item type."
        )

    # Alias for readability.
    restore_item = export_item

    # ========================================================
    # DELETE
    # ========================================================

    def remove_item(
        self,
        item_id
    ):

        self._require_unlock()

        target = self._get_item(
            item_id
        )

        if target is None:

            raise FileNotFoundError(
                "Vault item not found."
            )

        target_path = target[
            "virtual_path"
        ]

        items_to_remove = []

        if target["type"] == "folder":

            prefix = (
                target_path
                + "/"
            )

            for item in self.metadata[
                "items"
            ]:

                if (
                    item["virtual_path"]
                    == target_path
                    or item["virtual_path"].startswith(
                        prefix
                    )
                ):

                    items_to_remove.append(
                        item
                    )

        else:

            items_to_remove = [
                target
            ]

        old_metadata = list(
            self.metadata["items"]
        )

        deleted_encrypted = []

        try:

            for item in items_to_remove:

                encrypted_name = item.get(
                    "encrypted_file"
                )

                if encrypted_name:

                    encrypted_path = (
                        ENCRYPTED_DIR
                        / encrypted_name
                    )

                    if encrypted_path.exists():

                        encrypted_path.unlink()

                        deleted_encrypted.append(
                            encrypted_path
                        )

            remove_ids = {
                item["id"]
                for item in items_to_remove
            }

            self.metadata[
                "items"
            ] = [
                item
                for item in self.metadata[
                    "items"
                ]
                if item["id"] not in remove_ids
            ]

            self._save_metadata()

            return True

        except Exception:

            # Restore metadata in memory.
            self.metadata[
                "items"
            ] = old_metadata

            # Best effort restoration is not possible for
            # already-deleted encrypted files unless a backup
            # exists. Metadata is restored, but the encrypted
            # bytes are intentionally not recreated blindly.
            try:

                self._save_metadata()

            except Exception:
                pass

            raise

    # ========================================================
    # STATISTICS
    # ========================================================

    def get_stats(self):

        if not self.unlocked:

            return {
                "status": "LOCKED",
                "files": 0,
                "folders": 0,
                "total": 0,
                "total_size": 0,
                "visible": False
            }

        files = [
            item
            for item in self.metadata["items"]
            if item["type"] == "file"
        ]

        folders = [
            item
            for item in self.metadata["items"]
            if item["type"] == "folder"
        ]

        total_size = sum(
            int(item.get("size", 0))
            for item in files
        )

        return {
            "status": "UNLOCKED",
            "files": len(files),
            "folders": len(folders),
            "total": len(files) + len(folders),
            "total_size": total_size,
            "visible": True
        }