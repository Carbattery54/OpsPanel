from datetime import datetime
from enum import Enum
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship

class OSType(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"

class CredentialSource(str, Enum):
    LOCAL = "local"
    VAULTWARDEN = "vaultwarden"

class AuthType(str, Enum):
    PASSWORD = "password"
    SSH_KEY = "ssh_key"

class UserRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"

class AuditAction(str, Enum):
    SSH_OPEN = "ssh_open"
    SSH_CLOSE = "ssh_close"
    RDP_LAUNCH = "rdp_launch"
    WINRM_RUN = "winrm_run"
    CRED_RESOLVE = "cred_resolve"
    HOST_CREATE = "host_create"
    HOST_UPDATE = "host_update"
    HOST_DELETE = "host_delete"
    LOGIN = "login"
    LOGIN_FAIL = "login_fail"

class HostGroup(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    description: Optional[str] = None
    
    hosts: List["Host"] = Relationship(back_populates="group")

class Host(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    hostname: str
    os_type: OSType = Field(default=OSType.LINUX)
    group_id: Optional[int] = Field(default=None, foreign_key="hostgroup.id")
    ssh_port: int = Field(default=22)
    rdp_port: int = Field(default=3389)
    winrm_port: int = Field(default=5986)
    exporter_port: int = Field(default=9100)
    prometheus_instance: str = Field(index=True, unique=True)
    enabled: bool = Field(default=True)
    tags: Optional[str] = None
    
    credential_source: CredentialSource = Field(default=CredentialSource.LOCAL)
    local_credential_id: Optional[int] = Field(default=None, foreign_key="localcredential.id")
    vaultwarden_item_id: Optional[str] = None
    
    guacamole_connection_id: Optional[str] = None
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    group: Optional[HostGroup] = Relationship(back_populates="hosts")
    local_credential: Optional["LocalCredential"] = Relationship(back_populates="hosts")

class LocalCredential(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    username: str
    auth_type: AuthType = Field(default=AuthType.PASSWORD)
    
    secret_encrypted: Optional[bytes] = Field(default=None)
    private_key_encrypted: Optional[bytes] = Field(default=None)
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    hosts: List[Host] = Relationship(back_populates="local_credential")

class AppUser(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    role: UserRole = Field(default=UserRole.OPERATOR)
    is_active: bool = Field(default=True)

class SavedCommand(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    body: str
    target_os: OSType = Field(default=OSType.WINDOWS)

class AuditEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    actor: str
    action: AuditAction
    host_id: Optional[int] = None
    detail: Optional[str] = None
    source_ip: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
