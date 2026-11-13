import os
from dataclasses import dataclass, field
from pathlib import Path


def secret(name):
    path = os.getenv(name + "_FILE")
    return Path(path).read_text().strip() if path else os.environ[name]


@dataclass
class Config:
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./browser.db"))
    data: Path = field(default_factory=lambda: Path(os.getenv("DATA_DIR", "./data")))
    runtime: Path = field(default_factory=lambda: Path(os.getenv("RUNTIME_DIR", "/run/daoos-browser")))
    public_url: str = field(default_factory=lambda: os.getenv("PUBLIC_URL", "http://127.0.0.1:18131"))
    proxy: str = field(default_factory=lambda: os.getenv("BROWSER_PROXY", "http://egress:8888"))
    max_sessions: int = field(default_factory=lambda: int(os.getenv("MAX_SESSIONS", "1")))
    idle_seconds: int = field(default_factory=lambda: int(os.getenv("IDLE_SECONDS", "900")))
    operation_timeout: float = field(default_factory=lambda: float(os.getenv("OPERATION_TIMEOUT", "30")))
    test_origins: tuple = field(default_factory=lambda: tuple(filter(None, os.getenv("DISPOSABLE_ORIGINS", "").split(","))))
    redirect_uris: tuple = field(default_factory=lambda: tuple(filter(None, os.getenv("OAUTH_REDIRECT_URIS", "https://chatgpt.com/connector_platform_oauth_redirect,https://chat.openai.com/aip/plugin/oauth/callback").split(","))))
    profile_key: str = field(default_factory=lambda: secret("PROFILE_KEY"))
    secure_cookies: bool = True

    @property
    def origin(self):
        from urllib.parse import urlsplit
        u = urlsplit(self.public_url)
        return f"{u.scheme}://{u.netloc}"
