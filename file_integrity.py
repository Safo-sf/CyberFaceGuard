import os
import json
import hashlib
from datetime import datetime


class FileIntegrity:

    def __init__(self):
        self.data_dir = os.path.join(
            os.getenv("LOCALAPPDATA"),
            "CyberFaceGuard",
            "file_integrity"
        )

        os.makedirs(
            self.data_dir,
            exist_ok=True
        )

        self.baseline_file = os.path.join(
            self.data_dir,
            "baseline.json"
        )

    # =========================================================
    # SHA-256
    # =========================================================

    def calculate_hash(self, file_path):

        sha256 = hashlib.sha256()

        with open(
            file_path,
            "rb"
        ) as file:

            while True:

                chunk = file.read(1024 * 1024)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    # =========================================================
    # Scan Folder
    # =========================================================

    def scan_folder(self, folder_path):

        files = {}

        folder_path = os.path.abspath(folder_path)

        if not os.path.isdir(folder_path):
            raise ValueError(
                "Selected path is not a valid folder."
            )

        for root, dirs, filenames in os.walk(
            folder_path
        ):

            # Ignore symbolic-link directories
            dirs[:] = [
                d for d in dirs
                if not os.path.islink(
                    os.path.join(root, d)
                )
            ]

            for filename in filenames:

                file_path = os.path.join(
                    root,
                    filename
                )

                try:

                    if os.path.islink(file_path):
                        continue

                    relative_path = os.path.relpath(
                        file_path,
                        folder_path
                    )

                    file_hash = self.calculate_hash(
                        file_path
                    )

                    stat = os.stat(file_path)

                    files[relative_path] = {
                        "hash": file_hash,
                        "size": stat.st_size
                    }

                except (
                    PermissionError,
                    OSError
                ):
                    continue

        return files

    # =========================================================
    # Create Baseline
    # =========================================================

    def create_baseline(self, folder_path):

        folder_path = os.path.abspath(folder_path)

        files = self.scan_folder(
            folder_path
        )

        baseline = {
            "folder": folder_path,
            "created_at": datetime.now().isoformat(),
            "files": files
        }

        with open(
            self.baseline_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                baseline,
                file,
                indent=4
            )

        return baseline

    # =========================================================
    # Load Baseline
    # =========================================================

    def load_baseline(self):

        if not os.path.exists(
            self.baseline_file
        ):
            return None

        with open(
            self.baseline_file,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    # =========================================================
    # Compare Folder
    # =========================================================

    def compare_folder(self, folder_path):

        baseline = self.load_baseline()

        if baseline is None:
            raise ValueError(
                "No baseline exists. "
                "Create a baseline first."
            )

        folder_path = os.path.abspath(
            folder_path
        )

        baseline_folder = os.path.abspath(
            baseline.get("folder", "")
        )

        if folder_path != baseline_folder:

            raise ValueError(
                "Selected folder does not match "
                "the baseline folder."
            )

        old_files = baseline.get(
            "files",
            {}
        )

        current_files = self.scan_folder(
            folder_path
        )

        results = []

        # =====================================================
        # Check old files
        # =====================================================

        for relative_path, old_data in old_files.items():

            if relative_path not in current_files:

                results.append({
                    "file": relative_path,
                    "status": "DELETED",
                    "old_hash": old_data.get(
                        "hash",
                        ""
                    ),
                    "new_hash": ""
                })

                continue

            old_hash = old_data.get(
                "hash",
                ""
            )

            new_hash = current_files[
                relative_path
            ].get(
                "hash",
                ""
            )

            if old_hash == new_hash:

                status = "UNCHANGED"

            else:

                status = "MODIFIED"

            results.append({
                "file": relative_path,
                "status": status,
                "old_hash": old_hash,
                "new_hash": new_hash
            })

        # =====================================================
        # Check new files
        # =====================================================

        for relative_path, new_data in current_files.items():

            if relative_path not in old_files:

                results.append({
                    "file": relative_path,
                    "status": "NEW",
                    "old_hash": "",
                    "new_hash": new_data.get(
                        "hash",
                        ""
                    )
                })

        return results

    # =========================================================
    # Clear Baseline
    # =========================================================

    def clear_baseline(self):

        if os.path.exists(
            self.baseline_file
        ):

            os.remove(
                self.baseline_file
            )

            return True

        return False

    # =========================================================
    # Baseline Exists
    # =========================================================

    def baseline_exists(self):

        return os.path.exists(
            self.baseline_file
        )