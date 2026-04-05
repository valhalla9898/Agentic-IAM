from pathlib import Path

from config.settings import Settings
from database import Database


def test_database_defaults_to_local_app_data_override(monkeypatch, tmp_path):
    data_dir = tmp_path / "Agentic-IAM-Data"
    monkeypatch.setenv("AGENTIC_IAM_DATA_DIR", str(data_dir))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)

    database = Database()

    expected_path = data_dir / "agentic_iam.db"
    assert Path(database.db_path) == expected_path
    assert expected_path.exists()


def test_settings_default_database_path_matches_app_data_override(monkeypatch, tmp_path):
    app_data_dir = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(app_data_dir))
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("AGENTIC_IAM_DATA_DIR", raising=False)

    settings = Settings(environment="testing", debug=True)

    expected_path = app_data_dir / "Agentic-IAM" / "agentic_iam.db"
    assert Path(settings.database_path) == expected_path
    assert expected_path.parent.exists()