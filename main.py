import os
import json
import asyncio
import threading
import time
from typing import Optional, List
import httpx
import asyncssh
from fastapi import FastAPI, Depends, Request, Form, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlmodel import Session as SQLSession, select
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel

from config import settings
from database import init_db, get_session, engine
from models import (
    AppUser, UserRole, AuditEvent, AuditAction,
    Host, HostGroup, LocalCredential, CredentialSource, OSType, AuthType, SavedCommand
)
from auth import hash_password, verify_password, get_current_user
from crypto import crypto

# Initialize FastAPI
app = FastAPI(title="OpsPanel", version="1.0.0")

# Setup folder paths relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(BASE_DIR, "static")
templates_dir = os.path.join(BASE_DIR, "templates")

# Mount static files
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Initialize Jinja2 templates
templates = Jinja2Templates(directory=templates_dir)

# Add Starlette session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.APP_SECRET,
    session_cookie="opspanel_session",
    max_age=3600  # 1 hour
)

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """Intercept 401 Unauthorized exceptions for browser navigation and redirect to login."""
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Return standard response for other exceptions or non-HTML requests
    from fastapi.exception_handlers import http_exception_handler
    return await http_exception_handler(request, exc)

@app.on_event("startup")
def on_startup():
    """Run database migration and seed the initial admin account."""
    init_db()
    with SQLSession(engine) as db:
        # Check if the configured admin user already exists
        statement = select(AppUser).where(AppUser.username == settings.ADMIN_USER)
        admin = db.exec(statement).first()
        if not admin:
            hashed = hash_password(settings.ADMIN_PASS)
            new_admin = AppUser(
                username=settings.ADMIN_USER,
                password_hash=hashed,
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(new_admin)
            
            # Log audit event for seed admin creation
            seed_event = AuditEvent(
                actor="system",
                action=AuditAction.LOGIN,
                detail=f"Seeded admin user: {settings.ADMIN_USER}",
                source_ip="127.0.0.1"
            )
            db.add(seed_event)
            db.commit()
        
        # Regenerate Prometheus target discovery file from DB on startup
        try:
            regenerate_prometheus_file_sd(db)
        except Exception as e:
            print(f"Startup targets regeneration failed: {e}")

# Helper for logging audit events
def log_audit(db: SQLSession, actor: str, action: AuditAction, host_id: Optional[int] = None, detail: Optional[str] = None, source_ip: Optional[str] = None):
    event = AuditEvent(
        actor=actor,
        action=action,
        host_id=host_id,
        detail=detail,
        source_ip=source_ip
    )
    db.add(event)
    db.commit()

def regenerate_prometheus_file_sd(db: SQLSession):
    """Regenerate the Prometheus target JSON discovery file from active hosts in database."""
    # Query all active/enabled hosts
    statement = select(Host).where(Host.enabled == True)
    active_hosts = db.exec(statement).all()
    
    targets_data = []
    for host in active_hosts:
        # Determine job label
        job_label = "node" if host.os_type == OSType.LINUX else "windows"
        # Get group name
        group_name = host.group.name.lower() if host.group else "default"
        
        targets_data.append({
            "targets": [f"{host.hostname}:{host.exporter_port}"],
            "labels": {
                "job": job_label,
                "instance": host.prometheus_instance,
                "os": host.os_type.value,
                "group": group_name
            }
        })
    
    # Write JSON file safely
    try:
        os.makedirs(os.path.dirname(settings.PROMETHEUS_FILE_SD_PATH), exist_ok=True)
        with open(settings.PROMETHEUS_FILE_SD_PATH, "w") as f:
            json.dump(targets_data, f, indent=2)
    except Exception as e:
        print(f"Error writing Prometheus file_sd: {e}")

@app.get("/health")
def health_check():
    """Unauthenticated health status check."""
    return {"status": "healthy", "service": "opspanel"}

@app.get("/login", response_class=HTMLResponse)
def get_login(request: Request):
    """Render login page. Redirect to dashboard if session exists."""
    if request.session.get("username"):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "login.html")

@app.post("/login", response_class=HTMLResponse)
def post_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: SQLSession = Depends(get_session)
):
    """Process login form submission."""
    # Find active user
    statement = select(AppUser).where(AppUser.username == username, AppUser.is_active == True)
    user = db.exec(statement).first()
    
    client_ip = request.client.host if request.client else "unknown"
    
    if user and verify_password(user.password_hash, password):
        # Successful login
        request.session["username"] = user.username
        request.session["role"] = user.role.value
        
        log_audit(db, user.username, AuditAction.LOGIN, detail="User logged in successfully", source_ip=client_ip)
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    
    # Failed login
    log_audit(db, username, AuditAction.LOGIN_FAIL, detail="Failed login attempt", source_ip=client_ip)
    return templates.TemplateResponse(request, "login.html", {"error": "Invalid username or password"})

@app.post("/logout")
def post_logout(request: Request):
    """Clear session and redirect to login."""
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)


# ==========================================
# HOSTS & GROUPS ENDPOINTS (INVENTORY CRUD)
# ==========================================

@app.get("/", response_class=HTMLResponse)
@app.get("/hosts", response_class=HTMLResponse)
def get_hosts_page(request: Request, current_user: AppUser = Depends(get_current_user)):
    """Render full hosts list view."""
    return templates.TemplateResponse(
        request,
        "hosts/hosts_list.html",
        {
            "current_user": current_user,
            "active_page": "hosts"
        }
    )

@app.get("/hosts/table", response_class=HTMLResponse)
def get_hosts_table(
    request: Request,
    group_id: Optional[str] = None,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Render the HTMX partial hosts table, with optional group filtering."""
    statement = select(Host)
    if group_id is not None and group_id != "" and group_id != "null":
        try:
            g_id = int(group_id)
            statement = statement.where(Host.group_id == g_id)
        except ValueError:
            pass
    hosts = db.exec(statement).all()
    return templates.TemplateResponse(request, "hosts/hosts_table.html", {"hosts": hosts})

@app.get("/hosts/new", response_class=HTMLResponse)
def get_new_host_form(
    request: Request,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Render the partial HTML form for adding a host inside the modal."""
    groups = db.exec(select(HostGroup)).all()
    credentials = db.exec(select(LocalCredential)).all()
    return templates.TemplateResponse(
        request, 
        "hosts/host_form.html",
        {
            "host": None,
            "groups": groups,
            "credentials": credentials,
            "vaultwarden_enabled": settings.VAULTWARDEN_ENABLED
        }
    )

@app.post("/hosts", response_class=HTMLResponse)
def create_host(
    request: Request,
    name: str = Form(...),
    hostname: str = Form(...),
    os_type: OSType = Form(...),
    group_id: Optional[int] = Form(None),
    ssh_port: int = Form(22),
    rdp_port: int = Form(3389),
    winrm_port: int = Form(5986),
    exporter_port: int = Form(...),
    prometheus_instance: str = Form(...),
    tags: Optional[str] = Form(None),
    credential_source: CredentialSource = Form(CredentialSource.LOCAL),
    local_credential_id: Optional[int] = Form(None),
    vaultwarden_item_id: Optional[str] = Form(None),
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Create a new Host target in database."""
    # Ensure credential source parameters alignment
    if credential_source == CredentialSource.LOCAL:
        if not local_credential_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Local credential must be set")
        vaultwarden_item_id = None
    elif credential_source == CredentialSource.VAULTWARDEN:
        if not vaultwarden_item_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vaultwarden item ID must be specified")
        local_credential_id = None

    host = Host(
        name=name,
        hostname=hostname,
        os_type=os_type,
        group_id=group_id,
        ssh_port=ssh_port,
        rdp_port=rdp_port,
        winrm_port=winrm_port,
        exporter_port=exporter_port,
        prometheus_instance=prometheus_instance,
        tags=tags,
        credential_source=credential_source,
        local_credential_id=local_credential_id,
        vaultwarden_item_id=vaultwarden_item_id,
        enabled=True
    )
    
    try:
        db.add(host)
        db.commit()
        db.refresh(host)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Host name or Prometheus instance already exists")

    # Generate new Prometheus configuration & Log audit
    regenerate_prometheus_file_sd(db)
    client_ip = request.client.host if request.client else "unknown"
    log_audit(db, current_user.username, AuditAction.HOST_CREATE, host_id=host.id, detail=f"Created host {host.name}", source_ip=client_ip)

    hosts = db.exec(select(Host)).all()
    return templates.TemplateResponse(request, "hosts/hosts_table.html", {"hosts": hosts})

@app.get("/hosts/{host_id}/edit", response_class=HTMLResponse)
def get_edit_host_form(
    request: Request,
    host_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Render the partial form populated with existing Host settings inside the modal."""
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    groups = db.exec(select(HostGroup)).all()
    credentials = db.exec(select(LocalCredential)).all()
    return templates.TemplateResponse(
        request,
        "hosts/host_form.html",
        {
            "host": host,
            "groups": groups,
            "credentials": credentials,
            "vaultwarden_enabled": settings.VAULTWARDEN_ENABLED
        }
    )

@app.post("/hosts/{host_id}/edit", response_class=HTMLResponse)
def edit_host(
    request: Request,
    host_id: int,
    name: str = Form(...),
    hostname: str = Form(...),
    os_type: OSType = Form(...),
    group_id: Optional[int] = Form(None),
    ssh_port: int = Form(22),
    rdp_port: int = Form(3389),
    winrm_port: int = Form(5986),
    exporter_port: int = Form(...),
    prometheus_instance: str = Form(...),
    tags: Optional[str] = Form(None),
    credential_source: CredentialSource = Form(CredentialSource.LOCAL),
    local_credential_id: Optional[int] = Form(None),
    vaultwarden_item_id: Optional[str] = Form(None),
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Modify details of an existing Host target."""
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    if credential_source == CredentialSource.LOCAL:
        if not local_credential_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Local credential must be set")
        vaultwarden_item_id = None
    elif credential_source == CredentialSource.VAULTWARDEN:
        if not vaultwarden_item_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vaultwarden item ID must be specified")
        local_credential_id = None

    host.name = name
    host.hostname = hostname
    host.os_type = os_type
    host.group_id = group_id
    host.ssh_port = ssh_port
    host.rdp_port = rdp_port
    host.winrm_port = winrm_port
    host.exporter_port = exporter_port
    host.prometheus_instance = prometheus_instance
    host.tags = tags
    host.credential_source = credential_source
    host.local_credential_id = local_credential_id
    host.vaultwarden_item_id = vaultwarden_item_id

    try:
        db.add(host)
        db.commit()
        db.refresh(host)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Host name or Prometheus instance already exists")

    regenerate_prometheus_file_sd(db)
    client_ip = request.client.host if request.client else "unknown"
    log_audit(db, current_user.username, AuditAction.HOST_UPDATE, host_id=host.id, detail=f"Updated host {host.name}", source_ip=client_ip)

    hosts = db.exec(select(Host)).all()
    return templates.TemplateResponse(request, "hosts/hosts_table.html", {"hosts": hosts})

@app.delete("/hosts/{host_id}")
def delete_host(
    request: Request,
    host_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Delete a Host target from database."""
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
        
    db.delete(host)
    db.commit()

    regenerate_prometheus_file_sd(db)
    client_ip = request.client.host if request.client else "unknown"
    log_audit(db, current_user.username, AuditAction.HOST_DELETE, host_id=host_id, detail=f"Deleted host {host.name}", source_ip=client_ip)
    
    # Return empty response to make HTMX swap work
    return HTMLResponse(content="")

@app.post("/hosts/{host_id}/toggle-enable")
def toggle_host_enable(
    request: Request,
    host_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Toggle a host target's metrics scraping status."""
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    host.enabled = not host.enabled
    db.add(host)
    db.commit()

    regenerate_prometheus_file_sd(db)
    client_ip = request.client.host if request.client else "unknown"
    log_audit(db, current_user.username, AuditAction.HOST_UPDATE, host_id=host.id, detail=f"Toggled enabled status to {host.enabled} for host {host.name}", source_ip=client_ip)
    
    return HTMLResponse(content="")


# ==========================================
# HOST GROUPS ENDPOINTS
# ==========================================

@app.get("/groups", response_class=HTMLResponse)
def get_groups_list(
    request: Request,
    active_group_id: Optional[int] = None,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Render the HTMX partial listing all host groups in sidebar."""
    groups = db.exec(select(HostGroup)).all()
    total_hosts = db.exec(select(Host)).all()
    return templates.TemplateResponse(
        request,
        "hosts/groups_list.html",
        {
            "groups": groups,
            "total_hosts_count": len(total_hosts),
            "active_group_id": active_group_id
        }
    )

@app.get("/groups/new", response_class=HTMLResponse)
def get_new_group_form(request: Request, current_user: AppUser = Depends(get_current_user)):
    """Render the partial group creation form for the modal."""
    return templates.TemplateResponse(request, "hosts/group_form.html", {})

@app.post("/groups", response_class=HTMLResponse)
def create_group(
    request: Request,
    name: str = Form(...),
    description: Optional[str] = Form(None),
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Create a new HostGroup."""
    group = HostGroup(name=name, description=description)
    try:
        db.add(group)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group name already exists")

    client_ip = request.client.host if request.client else "unknown"
    log_audit(db, current_user.username, AuditAction.HOST_UPDATE, detail=f"Created group {group.name}", source_ip=client_ip)

    # Return updated list
    groups = db.exec(select(HostGroup)).all()
    total_hosts = db.exec(select(Host)).all()
    return templates.TemplateResponse(
        request,
        "hosts/groups_list.html",
        {
            "groups": groups,
            "total_hosts_count": len(total_hosts),
            "active_group_id": None
        }
    )

@app.delete("/groups/{group_id}", response_class=HTMLResponse)
def delete_group(
    request: Request,
    group_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Delete a HostGroup (unlinks hosts but does not delete hosts)."""
    group = db.get(HostGroup, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Set all linked hosts' group_id to None
    for host in group.hosts:
        host.group_id = None
        db.add(host)
    
    db.delete(group)
    db.commit()

    # Regenerate target JSON (since group labels changed to default)
    regenerate_prometheus_file_sd(db)
    client_ip = request.client.host if request.client else "unknown"
    log_audit(db, current_user.username, AuditAction.HOST_UPDATE, detail=f"Deleted group {group.name}", source_ip=client_ip)

    groups = db.exec(select(HostGroup)).all()
    total_hosts = db.exec(select(Host)).all()
    return templates.TemplateResponse(
        request,
        "hosts/groups_list.html",
        {
            "groups": groups,
            "total_hosts_count": len(total_hosts),
            "active_group_id": None
        }
    )


# ==========================================
# CREDENTIALS CRUD ENDPOINTS
# ==========================================

@app.get("/credentials", response_class=HTMLResponse)
def get_credentials_page(
    request: Request,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Render full credentials list view."""
    credentials = db.exec(select(LocalCredential)).all()
    return templates.TemplateResponse(
        request,
        "credentials/credentials_list.html",
        {
            "credentials": credentials,
            "current_user": current_user,
            "active_page": "credentials"
        }
    )

@app.get("/credentials/new", response_class=HTMLResponse)
def get_new_credential_form(request: Request, current_user: AppUser = Depends(get_current_user)):
    """Render partial credential creation form for the modal."""
    return templates.TemplateResponse(request, "credentials/credential_form.html", {"credential": None})

@app.post("/credentials", response_class=HTMLResponse)
def create_credential(
    request: Request,
    name: str = Form(...),
    username: str = Form(...),
    auth_type: AuthType = Form(...),
    secret: Optional[str] = Form(None),
    private_key: Optional[str] = Form(None),
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Create a new LocalCredential profile."""
    secret_enc = None
    private_key_enc = None

    if auth_type == AuthType.PASSWORD and not secret:
        raise HTTPException(status_code=400, detail="Password is required for password auth")
    if auth_type == AuthType.SSH_KEY and not private_key:
        raise HTTPException(status_code=400, detail="Private key file is required for SSH Key auth")

    if secret:
        secret_enc = crypto.encrypt(secret)
    if private_key:
        private_key_enc = crypto.encrypt(private_key)

    cred = LocalCredential(
        name=name,
        username=username,
        auth_type=auth_type,
        secret_encrypted=secret_enc,
        private_key_encrypted=private_key_enc
    )

    try:
        db.add(cred)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Credential profile name already exists")

    client_ip = request.client.host if request.client else "unknown"
    log_audit(db, current_user.username, AuditAction.CRED_RESOLVE, detail=f"Created credential profile {cred.name}", source_ip=client_ip)

    credentials = db.exec(select(LocalCredential)).all()
    return templates.TemplateResponse(request, "credentials/credentials_table.html", {"credentials": credentials})

@app.get("/credentials/{cred_id}/edit", response_class=HTMLResponse)
def get_edit_credential_form(
    request: Request,
    cred_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Render the partial credential edit form inside the modal."""
    cred = db.get(LocalCredential, cred_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential profile not found")
    return templates.TemplateResponse(request, "credentials/credential_form.html", {"credential": cred})

@app.post("/credentials/{cred_id}/edit", response_class=HTMLResponse)
def edit_credential(
    request: Request,
    cred_id: int,
    name: str = Form(...),
    username: str = Form(...),
    auth_type: AuthType = Form(...),
    secret: Optional[str] = Form(None),
    private_key: Optional[str] = Form(None),
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Modify credentials settings."""
    cred = db.get(LocalCredential, cred_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential profile not found")

    cred.name = name
    cred.username = username
    cred.auth_type = auth_type

    # Only overwrite encrypted fields if a value was provided
    if secret:
        cred.secret_encrypted = crypto.encrypt(secret)
    if private_key:
        cred.private_key_encrypted = crypto.encrypt(private_key)

    try:
        db.add(cred)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Credential profile name already exists")

    client_ip = request.client.host if request.client else "unknown"
    log_audit(db, current_user.username, AuditAction.CRED_RESOLVE, detail=f"Updated credential profile {cred.name}", source_ip=client_ip)

    credentials = db.exec(select(LocalCredential)).all()
    return templates.TemplateResponse(request, "credentials/credentials_table.html", {"credentials": credentials})

@app.delete("/credentials/{cred_id}", response_class=HTMLResponse)
def delete_credential(
    request: Request,
    cred_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Delete a LocalCredential profile."""
    cred = db.get(LocalCredential, cred_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential profile not found")

    # Set all linked hosts' local_credential_id to None
    for host in cred.hosts:
        host.local_credential_id = None
        db.add(host)

    db.delete(cred)
    db.commit()

    client_ip = request.client.host if request.client else "unknown"
    log_audit(db, current_user.username, AuditAction.CRED_RESOLVE, detail=f"Deleted credential profile {cred.name}", source_ip=client_ip)

    return HTMLResponse(content="")


# ==========================================
# METRICS & GRAFANA ENDPOINTS (PHASE 2)
# ==========================================

@app.get("/hosts/{host_id}", response_class=HTMLResponse)
def get_host_details(
    request: Request,
    host_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Render the detailed view of a host containing live metrics and embedded Grafana panels."""
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    return templates.TemplateResponse(
        request,
        "hosts/host_detail.html",
        {
            "host": host,
            "current_user": current_user,
            "active_page": "hosts",
            "grafana_url": settings.GRAFANA_URL,
            "grafana_dashboard_uid": settings.GRAFANA_DASHBOARD_UID
        }
    )

@app.get("/api/metrics/{host_id}/stream")
async def stream_host_metrics(
    request: Request,
    host_id: int,
    mock: bool = False,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """FastAPI SSE endpoint streaming live metrics (CPU, RAM, Disk) queried from Prometheus."""
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    async def metrics_generator():
        client = httpx.AsyncClient(timeout=2.0)
        try:
            import random
            mock_cpu = 25.0
            mock_ram = 50.0
            mock_disk = 60.0

            while True:
                if await request.is_disconnected():
                    break

                if mock:
                    mock_cpu = max(0.0, min(100.0, mock_cpu + random.uniform(-5.0, 5.0)))
                    mock_ram = max(0.0, min(100.0, mock_ram + random.uniform(-2.0, 2.0)))
                    mock_disk = max(0.0, min(100.0, mock_disk + random.uniform(-0.1, 0.1)))
                    payload = {
                        "cpu": round(mock_cpu, 2),
                        "ram": round(mock_ram, 2),
                        "disk": round(mock_disk, 2),
                        "status": "online"
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
                    await asyncio.sleep(2)
                    continue

                instance = host.prometheus_instance
                up_query = f'up{{instance="{instance}"}}'

                if host.os_type == OSType.LINUX:
                    cpu_query = f'100 - (avg(rate(node_cpu_seconds_total{{instance="{instance}",mode="idle"}}[1m])) * 100)'
                    ram_query = f'100 * (1 - (node_memory_MemAvailable_bytes{{instance="{instance}"}} / node_memory_MemTotal_bytes{{instance="{instance}"}}))'
                    disk_query = f'100 * (1 - (node_filesystem_free_bytes{{instance="{instance}",mountpoint="/"}} / node_filesystem_size_bytes{{instance="{instance}",mountpoint="/"}}))'
                else:
                    cpu_query = f'100 - (avg(irate(windows_cpu_time_total{{instance="{instance}",mode="idle"}}[2m])) * 100)'
                    ram_query = f'100 * (1 - (windows_os_physical_memory_free_bytes{{instance="{instance}"}} / windows_os_visible_memory_bytes{{instance="{instance}"}}))'
                    disk_query = f'100 * (1 - (windows_logical_disk_free_bytes{{instance="{instance}",volume="C:"}} / windows_logical_disk_size_bytes{{instance="{instance}",volume="C:"}}))'

                async def fetch_val(q):
                    try:
                        resp = await client.get(f"{settings.PROMETHEUS_URL}/api/v1/query", params={"query": q})
                        if resp.status_code == 200:
                            res = resp.json().get("data", {}).get("result", [])
                            if res:
                                return float(res[0]["value"][1])
                    except Exception:
                        pass
                    return None

                up_val, cpu_val, ram_val, disk_val = await asyncio.gather(
                    fetch_val(up_query),
                    fetch_val(cpu_query),
                    fetch_val(ram_query),
                    fetch_val(disk_query)
                )

                if up_val is None:
                    status_str = "offline"
                    cpu, ram, disk = 0.0, 0.0, 0.0
                elif up_val == 1.0:
                    status_str = "online"
                    cpu = round(cpu_val, 2) if cpu_val is not None else 0.0
                    ram = round(ram_val, 2) if ram_val is not None else 0.0
                    disk = round(disk_val, 2) if disk_val is not None else 0.0
                else:
                    status_str = "offline"
                    cpu, ram, disk = 0.0, 0.0, 0.0

                payload = {
                    "cpu": cpu,
                    "ram": ram,
                    "disk": disk,
                    "status": status_str
                }
                yield f"data: {json.dumps(payload)}\n\n"
                await asyncio.sleep(2)
        except asyncio.CancelledError:
            pass
        finally:
            await client.aclose()

    return StreamingResponse(metrics_generator(), media_type="text/event-stream")


# ==========================================
# CREDENTIAL RESOLVER & SSH TERMINAL (PHASE 3)
# ==========================================

class ResolvedCredential:
    def __init__(self, username: str, secret: Optional[str] = None, private_key: Optional[str] = None):
        self.username = username
        self.secret = secret
        self.private_key = private_key

async def resolve_credential(host: Host, db: SQLSession, actor: str, source_ip: str) -> ResolvedCredential:
    """Resolve per-host dual credentials (local database or Vaultwarden API sidecar)."""
    if host.credential_source == CredentialSource.VAULTWARDEN:
        if not settings.VAULTWARDEN_ENABLED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Vaultwarden integration is disabled in settings"
            )
        try:
            url = f"{settings.VAULTWARDEN_BW_SERVE_URL.rstrip('/')}/object/item/{host.vaultwarden_item_id}"
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    login = data.get("login", {})
                    username = login.get("username", "")
                    password = login.get("password")
                    
                    private_key = None
                    fields = data.get("fields", [])
                    for f in fields:
                        if f.get("name") == "ssh_key":
                            private_key = f.get("value")
                            break
                    
                    log_audit(
                        db,
                        actor=actor,
                        action=AuditAction.CRED_RESOLVE,
                        host_id=host.id,
                        detail=f"Resolved credentials from Vaultwarden item {host.vaultwarden_item_id}",
                        source_ip=source_ip
                    )
                    return ResolvedCredential(username=username, secret=password, private_key=private_key)
                else:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"Vaultwarden API returned error status {resp.status_code}"
                    )
        except Exception as e:
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to resolve Vaultwarden credentials: {e}"
            )

    # Local SQLite backend
    if not host.local_credential_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Host '{host.name}' has no local credential profile linked"
        )
        
    cred = db.get(LocalCredential, host.local_credential_id)
    if not cred:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential profile linked to host not found"
        )
        
    secret = None
    private_key = None
    
    if cred.secret_encrypted:
        secret = crypto.decrypt(cred.secret_encrypted)
    if cred.private_key_encrypted:
        private_key = crypto.decrypt(cred.private_key_encrypted)
        
    log_audit(
        db,
        actor=actor,
        action=AuditAction.CRED_RESOLVE,
        host_id=host.id,
        detail=f"Resolved credentials from local profile: {cred.name}",
        source_ip=source_ip
    )
    return ResolvedCredential(username=cred.username, secret=secret, private_key=private_key)


@app.get("/hosts/{host_id}/ssh", response_class=HTMLResponse)
def get_host_ssh(
    request: Request,
    host_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Render the SSH terminal page for a host."""
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
        
    return templates.TemplateResponse(
        request,
        "hosts/host_ssh.html",
        {
            "host": host,
            "current_user": current_user,
            "active_page": "hosts"
        }
    )


@app.websocket("/ws/ssh/{host_id}")
async def websocket_ssh_endpoint(
    websocket: WebSocket,
    host_id: int
):
    """WebSocket tunnel proxying xterm.js frontend to target SSH server via asyncssh."""
    with SQLSession(engine) as db:
        # Authenticate user from session
        username = websocket.session.get("username")
        if not username:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        statement = select(AppUser).where(AppUser.username == username, AppUser.is_active == True)
        user = db.exec(statement).first()
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        host = db.get(Host, host_id)
        if not host:
            await websocket.close(code=4004)
            return

        await websocket.accept()
        client_ip = websocket.client.host if websocket.client else "unknown"

        # Resolve credentials
        try:
            resolved_cred = await resolve_credential(host, db, actor=user.username, source_ip=client_ip)
        except Exception as e:
            await websocket.send_text(f"\r\n[OpsPanel Error] Failed to resolve credentials: {e}\r\n")
            await websocket.close()
            return

        await websocket.send_text("\r\n[OpsPanel] Connecting to host SSH...\r\n")
        
        connect_kwargs = {
            "host": host.hostname,
            "port": host.ssh_port,
            "username": resolved_cred.username,
            "known_hosts": None,
        }
        
        if resolved_cred.private_key:
            try:
                key = asyncssh.import_private_key(resolved_cred.private_key, passphrase=resolved_cred.secret)
                connect_kwargs["client_keys"] = [key]
            except Exception as e:
                await websocket.send_text(f"\r\n[OpsPanel Error] Invalid SSH private key: {e}\r\n")
                await websocket.close()
                return
        else:
            connect_kwargs["password"] = resolved_cred.secret

        try:
            async with asyncssh.connect(**connect_kwargs) as conn:
                await websocket.send_text("[OpsPanel] SSH Connection established. Starting shell...\r\n")
                
                log_audit(
                    db,
                    actor=user.username,
                    action=AuditAction.SSH_OPEN,
                    host_id=host.id,
                    detail=f"SSH session opened to {host.name} ({host.hostname})",
                    source_ip=client_ip
                )

                async with conn.create_process(term_type="xterm", term_size=(80, 24), encoding="utf-8", errors="replace") as process:
                    
                    async def read_from_ssh():
                        try:
                            while not process.stdout.at_eof():
                                data = await process.stdout.read(4096)
                                if not data:
                                    break
                                await websocket.send_text(data)
                        except asyncio.CancelledError:
                            pass
                        except Exception as e:
                            try:
                                await websocket.send_text(f"\r\n[OpsPanel] SSH Read Error: {e}\r\n")
                            except Exception:
                                pass

                    async def read_from_ws():
                        try:
                            while True:
                                text = await websocket.receive_text()
                                try:
                                    msg = json.loads(text)
                                    if msg.get("type") == "resize":
                                        cols = msg.get("cols", 80)
                                        rows = msg.get("rows", 24)
                                        process.change_terminal_size(cols, rows)
                                    elif msg.get("type") == "data":
                                        data = msg.get("data", "")
                                        process.stdin.write(data)
                                except json.JSONDecodeError:
                                    process.stdin.write(text)
                        except WebSocketDisconnect:
                            pass
                        except asyncio.CancelledError:
                            pass
                        except Exception as e:
                            pass

                    ssh_task = asyncio.create_task(read_from_ssh())
                    ws_task = asyncio.create_task(read_from_ws())

                    done, pending = await asyncio.wait(
                        [ssh_task, ws_task],
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    for task in pending:
                        task.cancel()

                log_audit(
                    db,
                    actor=user.username,
                    action=AuditAction.SSH_CLOSE,
                    host_id=host.id,
                    detail=f"SSH session closed for {host.name}",
                    source_ip=client_ip
                )
                await websocket.send_text("\r\n[OpsPanel] SSH Connection closed.\r\n")

        except Exception as e:
            await websocket.send_text(f"\r\n[OpsPanel Error] SSH Connection failed: {e}\r\n")
        finally:
            try:
                await websocket.close()
            except Exception:
                pass


# ==========================================
# WINRM COMMAND RUNNER & SAVED COMMANDS (PHASE 4)
# ==========================================

from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool, PSInvocationState
import uuid

# Active WinRM execution task store
active_winrm_tasks = {}

class WinRMTask:
    def __init__(self, task_id: str, host_ids: List[int], script: str):
        self.task_id = task_id
        self.host_ids = host_ids
        self.script = script
        self.queue = asyncio.Queue()
        self.active_workers = len(host_ids)
        self.lock = threading.Lock()

    def decrement_worker(self, loop):
        with self.lock:
            self.active_workers -= 1
            if self.active_workers <= 0:
                loop.call_soon_threadsafe(self.queue.put_nowait, None)

def winrm_worker(
    task: WinRMTask,
    host_id: int,
    host_name: str,
    hostname: str,
    port: int,
    username: str,
    password: Optional[str],
    script: str,
    loop: asyncio.AbstractEventLoop
):
    def put_msg(stream, line):
        loop.call_soon_threadsafe(
            task.queue.put_nowait,
            {"host": host_name, "stream": stream, "line": line}
        )

    try:
        put_msg("system", f"Connecting via WinRM HTTPS to {hostname}:{port}...")
        
        wsman = WSMan(
            server=hostname,
            port=port,
            username=username,
            password=password,
            ssl=True,
            cert_validation=False,
            auth="negotiate"
        )
        
        # Wrap PowerShell script to force text serialization for all pipeline objects
        wrapped_script = f"& {{\n{script}\n}} | Out-String"
        
        with RunspacePool(wsman) as pool:
            put_msg("system", "WinRM Session established. Executing PowerShell script...")
            ps = PowerShell(pool)
            ps.add_script(wrapped_script)
            ps.begin_invoke()
            
            while ps.state not in [PSInvocationState.COMPLETED, PSInvocationState.FAILED, PSInvocationState.STOPPED]:
                ps.poll_invoke()
                
                # 1. Output (stdout) stream
                for item in ps.output:
                    if item is not None:
                        for line in str(item).splitlines():
                            put_msg("stdout", line)
                ps.output.clear()
                
                # 2. Error (stderr) stream
                for err in ps.streams.error:
                    if err is not None:
                        put_msg("stderr", str(err))
                ps.streams.error.clear()
                
                # 3. Information (Write-Host / Write-Information) stream
                for info in ps.streams.information:
                    if info is not None:
                        for line in str(info).splitlines():
                            put_msg("stdout", line)
                ps.streams.information.clear()
                
                # 4. Warning stream
                for warn in ps.streams.warning:
                    if warn is not None:
                        put_msg("stderr", f"WARNING: {str(warn)}")
                ps.streams.warning.clear()
                
                time.sleep(0.2)
                
            ps.end_invoke()
            
            # Fetch remaining items
            for item in ps.output:
                if item is not None:
                    for line in str(item).splitlines():
                        put_msg("stdout", line)
                        
            for err in ps.streams.error:
                if err is not None:
                    put_msg("stderr", str(err))
                    
            for info in ps.streams.information:
                if info is not None:
                    for line in str(info).splitlines():
                        put_msg("stdout", line)
                        
            for warn in ps.streams.warning:
                if warn is not None:
                    put_msg("stderr", f"WARNING: {str(warn)}")
                    
            if ps.had_errors:
                put_msg("system", "Execution finished with errors.")
            else:
                put_msg("system", "Execution completed successfully.")
                
    except Exception as e:
        put_msg("stderr", f"WinRM Error: {str(e)}")
    finally:
        task.decrement_worker(loop)

class WinRMRunRequest(BaseModel):
    host_ids: List[int]
    script: str

@app.post("/api/winrm/run")
async def run_winrm(
    request: Request,
    payload: WinRMRunRequest,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    if not payload.host_ids:
        raise HTTPException(status_code=400, detail="No hosts selected")
        
    hosts = db.exec(select(Host).where(Host.id.in_(payload.host_ids))).all()
    if not hosts:
        raise HTTPException(status_code=404, detail="Selected hosts not found")
        
    task_id = str(uuid.uuid4())
    task = WinRMTask(task_id, [h.id for h in hosts], payload.script)
    active_winrm_tasks[task_id] = task
    
    loop = asyncio.get_running_loop()
    client_ip = request.client.host if request.client else "unknown"
    
    for host in hosts:
        if host.os_type != OSType.WINDOWS:
            task.queue.put_nowait({
                "host": host.name,
                "stream": "stderr",
                "line": "Error: WinRM execution is only supported on Windows hosts."
            })
            task.decrement_worker(loop)
            continue
            
        try:
            resolved_cred = await resolve_credential(host, db, actor=current_user.username, source_ip=client_ip)
            
            # Start worker thread
            threading.Thread(
                target=winrm_worker,
                args=(task, host.id, host.name, host.hostname, host.winrm_port, resolved_cred.username, resolved_cred.secret, payload.script, loop),
                daemon=True
            ).start()
            
            log_audit(
                db,
                actor=current_user.username,
                action=AuditAction.WINRM_RUN,
                host_id=host.id,
                detail=f"Executed WinRM PowerShell script (length: {len(payload.script)} characters)",
                source_ip=client_ip
            )
        except Exception as e:
            task.queue.put_nowait({
                "host": host.name,
                "stream": "stderr",
                "line": f"Credential resolution failed: {str(e)}"
            })
            task.decrement_worker(loop)
            
    return {"task_id": task_id}

@app.get("/api/winrm/tasks/{task_id}/stream")
async def stream_winrm_task(
    task_id: str,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    task = active_winrm_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
        
    async def sse_generator():
        try:
            while True:
                msg = await task.queue.get()
                if msg is None:
                    yield f"data: {json.dumps({'host': 'system', 'stream': 'system', 'line': 'EOF'})}\n\n"
                    break
                yield f"data: {json.dumps(msg)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            active_winrm_tasks.pop(task_id, None)

    return StreamingResponse(sse_generator(), media_type="text/event-stream")

@app.get("/commands", response_class=HTMLResponse)
def get_commands_page(
    request: Request,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    windows_hosts = db.exec(select(Host).where(Host.os_type == OSType.WINDOWS)).all()
    saved_commands = db.exec(select(SavedCommand)).all()
    groups = db.exec(select(HostGroup)).all()
    return templates.TemplateResponse(
        request,
        "commands/commands.html",
        {
            "current_user": current_user,
            "active_page": "commands",
            "hosts": windows_hosts,
            "saved_commands": saved_commands,
            "groups": groups
        }
    )

@app.get("/commands/list", response_class=HTMLResponse)
def get_saved_commands_list(
    request: Request,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    saved_commands = db.exec(select(SavedCommand)).all()
    return templates.TemplateResponse(
        request,
        "commands/saved_commands_list.html",
        {"saved_commands": saved_commands}
    )

@app.post("/commands/save", response_class=HTMLResponse)
def save_command(
    request: Request,
    name: str = Form(...),
    body: str = Form(...),
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    statement = select(SavedCommand).where(SavedCommand.name == name)
    existing = db.exec(statement).first()
    if existing:
        existing.body = body
        db.add(existing)
    else:
        cmd = SavedCommand(name=name, body=body)
        db.add(cmd)
    db.commit()
    
    saved_commands = db.exec(select(SavedCommand)).all()
    return templates.TemplateResponse(
        request,
        "commands/saved_commands_list.html",
        {"saved_commands": saved_commands}
    )

@app.delete("/commands/{command_id}", response_class=HTMLResponse)
def delete_command(
    command_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    cmd = db.get(SavedCommand, command_id)
    if cmd:
        db.delete(cmd)
        db.commit()
    return HTMLResponse(content="")

@app.get("/audit", response_class=HTMLResponse)
def get_audit(
    request: Request,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Forbidden")
        
    statement = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(200)
    events = db.exec(statement).all()
    
    hosts_map = {h.id: h.name for h in db.exec(select(Host)).all()}
    
    return templates.TemplateResponse(
        request,
        "audit/audit_list.html",
        {
            "current_user": current_user,
            "active_page": "audit",
            "events": events,
            "hosts_map": hosts_map
        }
    )


def encrypt_guacamole_token(connection_settings: dict, shared_key: str) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    import base64
    import json
    import os

    # shared_key must be exactly 32 bytes (as string or bytes)
    key_bytes = shared_key.encode('utf-8') if isinstance(shared_key, str) else shared_key
    if len(key_bytes) != 32:
        raise ValueError("Guacamole shared key must be exactly 32 bytes")
    
    # Generate 16-byte random IV
    iv = os.urandom(16)
    
    # Serialize settings to JSON string
    data_str = json.dumps(connection_settings)
    data_bytes = data_str.encode('utf-8')
    
    # Apply PKCS7 padding (block size 128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data_bytes) + padder.finalize()
    
    # Encrypt using AES-256-CBC
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Structure for guacamole-lite
    token_dict = {
        "iv": base64.b64encode(iv).decode('utf-8'),
        "value": base64.b64encode(ciphertext).decode('utf-8')
    }
    
    # Serialize token dict to JSON and Base64 encode it
    token_json = json.dumps(token_dict)
    return base64.b64encode(token_json.encode('utf-8')).decode('utf-8')


@app.get("/hosts/{host_id}/rdp", response_class=HTMLResponse)
def get_host_rdp(
    request: Request,
    host_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Render the RDP session page for a Windows host."""
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    if host.os_type != OSType.WINDOWS:
        raise HTTPException(status_code=400, detail="RDP is only available for Windows hosts")
        
    return templates.TemplateResponse(
        request,
        "hosts/host_rdp.html",
        {
            "host": host,
            "current_user": current_user,
            "active_page": "hosts"
        }
    )


@app.post("/api/rdp/{host_id}/token")
async def generate_rdp_token(
    request: Request,
    host_id: int,
    db: SQLSession = Depends(get_session),
    current_user: AppUser = Depends(get_current_user)
):
    """Generate an encrypted connection token for guacamole-lite."""
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    if host.os_type != OSType.WINDOWS:
        raise HTTPException(status_code=400, detail="Only Windows hosts support RDP")

    client_ip = request.client.host if request.client else "unknown"

    # Resolve credentials
    try:
        resolved_cred = await resolve_credential(host, db, actor=current_user.username, source_ip=client_ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to resolve credentials: {e}")

    # Resolve domain and username dynamically
    username = resolved_cred.username
    domain = None
    if "\\" in username:
        parts = username.split("\\", 1)
        domain = parts[0]
        username = parts[1]
    elif "@" in username:
        parts = username.split("@", 1)
        username = parts[0]
        domain = parts[1]
    else:
        domain = settings.AD_DOMAIN

    # Build connection settings for guacamole-lite
    connection_settings = {
        "connection": {
            "type": "rdp",
            "settings": {
                "hostname": host.hostname,
                "port": str(host.rdp_port or 3389),
                "username": username,
                "password": resolved_cred.secret or "",
                "domain": domain,
                "security": "any",
                "ignore-cert": True,
                "resize-method": "reconnect",  # Avoid display-update as it causes black screens on modern Windows
                "color-depth": "24",           # 24-bit color depth for high compatibility
                "disable-wallpaper": "true",   # Disable wallpaper for performance and connection stability
                "enable-font-smoothing": "true", # Smooth text edges
                "enable-desktop-composition": "true", # Performance composition
                "enable-audio": "false",       # Disable audio redirection to avoid latency/channel issues
                "enable-drive": "true",        # Enable virtual disk drive redirection
                "drive-name": "SharedDrive",   # Name of the drive as it will appear in Windows (This PC)
                "drive-path": "/tmp/guac-drive", # Path inside the guacd container
                "create-drive-path": "true",   # Instruct guacd to create the directory if it doesn't exist
                "server-layout": "tr-tr-qwerty" # Map Turkish physical keys to correct scan codes
            }
        }
    }

    # Retrieve optional display settings from query params
    width = request.query_params.get("width")
    height = request.query_params.get("height")
    dpi = request.query_params.get("dpi")

    if width:
        connection_settings["connection"]["settings"]["width"] = str(width)
    if height:
        connection_settings["connection"]["settings"]["height"] = str(height)
    if dpi:
        connection_settings["connection"]["settings"]["dpi"] = str(dpi)

    try:
        token = encrypt_guacamole_token(connection_settings, settings.GUACAMOLE_SHARED_KEY)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to encrypt token: {e}")

    log_audit(
        db,
        actor=current_user.username,
        action=AuditAction.RDP_LAUNCH,
        host_id=host.id,
        detail=f"Generated Guacamole RDP connection token for host {host.name}",
        source_ip=client_ip
    )

    return {
        "token": token,
        "guac_lite_url": settings.GUACAMOLE_LITE_URL
    }


@app.websocket("/ws/rdp/tunnel")
async def websocket_rdp_tunnel(websocket: WebSocket, token: str):
    """WebSocket tunnel proxying Guacamole protocol packets to guacamole-lite container."""
    import websockets
    
    # Negotiate the subprotocol requested by the client browser (usually 'guacamole')
    subprotocols = websocket.headers.get("sec-websocket-protocol", "").split(",")
    subprotocols = [s.strip() for s in subprotocols if s.strip()]
    if "guacamole" in subprotocols:
        await websocket.accept(subprotocol="guacamole")
    else:
        await websocket.accept()
    
    # Target guacamole-lite container over the Docker internal network
    guac_url = f"ws://guacamole-lite:8080/?token={token}"
    
    try:
        # Request 'guacamole' subprotocol to match Guacamole handshake
        async with websockets.connect(guac_url, subprotocols=["guacamole"]) as guac_ws:
            
            async def forward_to_guac():
                try:
                    while True:
                        data = await websocket.receive_text()
                        await guac_ws.send(data)
                except Exception:
                    pass

            async def forward_to_client():
                try:
                    while True:
                        data = await guac_ws.recv()
                        await websocket.send_text(data)
                except Exception:
                    pass

            # Run both tasks concurrently. If either side disconnects/errors out,
            # wait terminates immediately, cancelling the other task.
            task_guac = asyncio.create_task(forward_to_guac())
            task_client = asyncio.create_task(forward_to_client())
            
            done, pending = await asyncio.wait(
                [task_guac, task_client],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            for task in pending:
                task.cancel()
            
    except Exception as e:
        print(f"Error in RDP WebSocket tunnel: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


