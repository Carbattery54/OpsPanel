# OpsPanel

OpsPanel is a unified, secure, and modern DevOps operations dashboard designed for managing infrastructure inventory, monitoring telemetry, and establishing secure remote connections (SSH, RDP, WinRM) directly from your web browser. 

Built using a light, high-performance tech stack, it provides real-time access to Linux and Windows hosts without requiring agent installations on the target endpoints.

---

## 🚀 Key Features

*   **Infrastructure Inventory & Groups:** Organize network hosts, OS types (Linux/Windows), and dynamic labels. Generates automatic service-discovery files for Prometheus scraping configurations.
*   **Encrypted Credential Profiles:** Securely stores target SSH keys, domain credentials, and server passwords. Protected database-level with versioned **AES-256-GCM Envelope Encryption**.
*   **Embedded Telemetry & Metrics:** Interactive host telemetry screens powered by **Prometheus** and **Grafana** dashboards with Server-Sent Events (SSE) live telemetry charts.
*   **In-Browser SSH Web Terminal:** Interactive secure shell sessions powered by **xterm.js** and WebSockets. Includes local clipboard synchronization (copy-paste), automatic resizing, and persistent font-size memory (`localStorage`).
*   **HTML5 RDP Remote Console:** Native in-browser RDP remote desktop console powered by **Apache Guacamole (guacd)**. Uses secure short-lived AES-256-CBC token exchange to hide server credentials from the browser. Supports Turkish physical keyboard layout mapping, copy-paste lockouts, and remote file uploads.
*   **WinRM Command Orchestrator:** Parallel, asynchronous PowerShell script execution engine for Windows targets using **pypsrp** over HTTPS. Stream execution logs to the web console in real-time.
*   **Security & Audit Logging:** Comprehensive database logging of user actions (SSH sessions, RDP connections, WinRM runs, login attempts) to maintain security compliance.

---

## 🛠️ Technology Stack

*   **Backend:** Python 3, FastAPI, SQLModel (SQLAlchemy), Asyncio, AsyncSSH, Pypsrp
*   **Frontend:** HTML5, Vanilla CSS (Glassmorphism design system), HTMX, Alpine.js, Chart.js, xterm.js, Guacamole-common-js
*   **Database:** SQLite (WAL mode activated for concurrent reads/writes)
*   **Services:** Docker, Docker Compose, Prometheus, Grafana, Guacd

---

## 📦 Getting Started

### Prerequisites
*   Docker and Docker Compose installed.

### Setup Instructions

1.  **Clone the repository & enter directory:**
    ```bash
    git clone https://github.com/your-username/OpsPanel.git
    cd OpsPanel
    ```

2.  **Configure Environment Variables:**
    Copy the example environment template and configure your secrets:
    ```bash
    cp .env.example .env
    ```
    *Open `.env` and configure your `APP_SECRET`, `ENC_KEY`, `ADMIN_PASS`, and `GUACAMOLE_SHARED_KEY` (32 characters). These have no defaults and must be set.*

3.  **Start application using Docker Compose:**
    ```bash
    docker compose up --build -d
    ```
    This builds the FastAPI main application, starts Prometheus, Grafana, the Guacamole daemon (guacd), the Node.js websocket tunnel proxy, and maps ports:
    *   **OpsPanel Dashboard:** `http://localhost:8000`
    *   **Prometheus:** `http://localhost:9090`
    *   **Grafana:** `http://localhost:3001`

4.  **Initial Login:**
    Log in using the default seeded admin credentials:
    *   **Username:** `admin`
    *   **Password:** *Set in your `.env` file under `ADMIN_PASS`*

---

## 🔒 Security Practices
*   Sensitive passwords and private keys are encrypted inside the SQLite database before being saved.
*   Connections to RDP do not expose credentials to client browser sidecars or Guacamole-lite logs. Short-lived encrypted tokens are generated on-the-fly.
*   Sessions are protected with secure HTTP cookies and user verification middleware.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
