from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    BASE_DOMAIN: str = "ops.local"
    PROJECT_ROOT: str = "C:/Users/akifhan.bulama/.gemini/antigravity/scratch/opspanel"
    AD_DOMAIN: str = "LAB.LOCAL"
    ENC_KEY: str
    APP_SECRET: str
    ADMIN_USER: str = "admin"
    ADMIN_PASS: str
    PROMETHEUS_URL: str = "http://prometheus:9090"
    GRAFANA_URL: str = "http://grafana:3000"
    GRAFANA_DASHBOARD_UID: str = "host-metrics"
    VAULTWARDEN_ENABLED: bool = False
    VAULTWARDEN_BW_SERVE_URL: str = "http://localhost:8087"
    VAULTWARDEN_COLLECTION_ID: str = ""
    PROMETHEUS_FILE_SD_PATH: str = "C:/Users/akifhan.bulama/.gemini/antigravity/scratch/opspanel/prometheus/file_sd/opspanel_targets.json"
    GUACAMOLE_SHARED_KEY: str = "guacamole_shared_secret_key_32ch"
    GUACAMOLE_LITE_URL: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()
