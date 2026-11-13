from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from browser.config import Config
from browser.store import Store, Principal


@pytest.fixture
def setup(tmp_path):
    config = Config(database_url="sqlite:///"+str(tmp_path / "test.db"), data=tmp_path / "data", runtime=tmp_path / "runtime",
        profile_key=Fernet.generate_key().decode(), secure_cookies=False)
    store = Store(config.database_url)
    owner = Principal("owner", "org", "test", frozenset({"read", "write", "operator"}))
    raw = store.issue_key(owner, owner.scopes)
    owner = store.authenticate(raw)
    return config, store, owner, raw
