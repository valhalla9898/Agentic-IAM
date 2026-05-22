import app as app_module


def test_get_requested_page_reads_bloome_query_param(monkeypatch):
    monkeypatch.setattr(app_module.st, "query_params", {"page": "Bloome"}, raising=False)

    assert app_module.get_requested_page() == "Bloome"


def test_get_requested_page_returns_none_when_query_param_missing(monkeypatch):
    monkeypatch.setattr(app_module.st, "query_params", {}, raising=False)

    assert app_module.get_requested_page() is None
