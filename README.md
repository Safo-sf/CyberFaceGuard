# CyberFaceGuard

CyberFaceGuard is a Windows desktop security application built with
Python and PySide6. It combines AI-based face detection and recognition
with local security-monitoring tools in a graphical interface.

## Features

-   **Face detection and recognition** using OpenCV-based YuNet and
    SFace models.
-   **Liveness-related functionality** for face-verification workflows.
-   **Network auditing** with open-port and process information.
-   **Security auditing** with results displayed in the desktop
    interface.
-   **File integrity monitoring** to help identify changes to monitored
    files.
-   **Password and vault management** for locally managed credentials.
-   **PDF reporting** for audit results.
-   **License validation** using a public-key verification workflow.

> Feature availability depends on the configured modules and models in
> the version being used. Do not treat automated findings as a
> substitute for professional security assessment.

## Technology Stack

-   Python
-   PySide6
-   OpenCV
-   YuNet face-detection model
-   SFace face-recognition model
-   PyInstaller
-   Inno Setup

## Project Structure

``` text
CyberFaceGuard/
├── assets/                 # Application icons and images
├── models/                 # YuNet and SFace model files
├── keys/
│   └── public_key.pem      # Public key used for license verification
├── main.py                 # Application entry point
├── gui.py                  # Desktop interface
├── network_audit.py        # Network auditing
├── security_audit.py       # Security audit logic
├── file_integrity.py       # File integrity functionality
├── liveness.py             # Liveness-related functionality
├── license_manager.py      # License validation
├── password_manager.py     # Password-management functionality
├── vault_manager.py        # Vault functionality
├── verify_engine.py        # Face verification engine
├── CyberFaceGuard.spec     # PyInstaller build configuration
└── README.md
```

## Requirements

-   Windows 10 or Windows 11
-   Python version compatible with the dependencies in the project
-   Required Python packages listed in `requirements.txt` (if provided)
-   The YuNet and SFace model files in the `models/` directory

## Run from Source

1.  Clone the repository:

    ``` bash
    git clone https://github.com/Safo-sf/CyberFaceGuard.git
    cd CyberFaceGuard
    ```

2.  Create and activate a virtual environment:

    ``` powershell
    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    ```

3.  Install the project's dependencies. If the repository contains
    `requirements.txt`:

    ``` powershell
    py -m pip install -r requirements.txt
    ```

4.  Start the application:

    ``` powershell
    py main.py
    ```

## Build the Windows Application

If PyInstaller and the project dependencies are installed, build using
the included spec file:

``` powershell
py -m PyInstaller --noconfirm --clean CyberFaceGuard.spec
```

The bundled application is normally generated under:

``` text
dist/CyberFaceGuard/
```

To create an installer, open `CyberFaceGuard.iss` with Inno Setup and
compile it. Adjust the filename if your installer script is stored as
`CyberFaceGuard.iss.txt`.

## Security and Privacy

-   Never commit private keys, activation secrets, passwords, personal
    data, or real user records.
-   Keep the license-signing private key offline and outside this
    repository.
-   Only distribute the public verification key required by the
    application.
-   Review audit logs and generated reports before sharing them; they
    may contain device or network details.
-   Run network audits only on devices and networks you own or are
    explicitly authorized to assess.
-   Face data and credentials are sensitive. Use appropriate consent,
    access controls, and secure storage.

## Responsible Use

CyberFaceGuard is intended for lawful, authorized security monitoring
and face-verification workflows. Obtain consent before enrolling or
processing anyone's face data, and follow applicable privacy and
data-protection laws.

## License

This repository includes a `LICENSE` file. Review it for the exact terms
governing use, modification, and distribution.

## Disclaimer

CyberFaceGuard is provided for educational and legitimate security
purposes. The maintainers make no guarantee that the application will
detect every threat or prevent every security incident. Always validate
important findings independently.
