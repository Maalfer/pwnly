"""Tests de la copia de seguridad (ZIP con manifest + JSON + imágenes)."""
import base64
import hashlib
import io
import json
import zipfile

import pytest

import backup
import models

PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
PNG = base64.b64decode(PNG_B64)
PNG_URL = f"data:image/png;base64,{PNG_B64}"


def _make_report(client, title="Informe A", with_images=True):
    r = client.post("/api/reports", json={
        "document_title": title, "client_company": "ACME", "client_logo": [PNG_URL, ""],
        "audit_summary": "Resumen", "revision_history": [{"version": "1.0", "date": "2026-01-01", "author": "X", "changes": "ok"}],
    }).json()
    for i, sev in enumerate(["crit", "low"]):
        client.post(f"/api/reports/{r['id']}/findings", json={
            "title": f"Hallazgo {i}", "severity": sev, "order_index": i,
            "images": [PNG_URL, PNG_URL] if with_images else [], "image_captions": ["a", "b"] if with_images else [],
        })
    return r


def _zip(entries, manifest=None, raw_manifest=None):
    """Construye un ZIP de copia a mano. entries: {path: bytes}."""
    files = {p: {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b)} for p, b in entries.items()}
    m = manifest if manifest is not None else {"format": backup.FORMAT, "format_version": 1, "files": files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", raw_manifest if raw_manifest is not None else json.dumps(m))
        for p, b in entries.items():
            zf.writestr(p, b)
    return buf.getvalue()


def _import(client, data, mode="merge", dry_run=False):
    return client.post("/api/backup/import", files={"file": ("b.zip", data, "application/zip")},
                       data={"mode": mode, "dry_run": "true" if dry_run else "false"})


def _export(client):
    r = client.get("/api/backup/export")
    assert r.status_code == 200
    return r.content


class TestExport:
    def test_returns_zip_with_manifest_and_layout(self, client):
        _make_report(client)
        r = client.get("/api/backup/export")
        assert r.headers["content-type"] == "application/zip"
        assert "pwnly-backup-" in r.headers["content-disposition"] and r.headers["content-disposition"].endswith('.zip"')
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        names = set(zf.namelist())
        assert {"manifest.json", "data/reports.json", "data/themes.json", "data/finding_templates.json", "data/settings.json"} <= names
        m = json.loads(zf.read("manifest.json"))
        assert m["format"] == "pwnly-backup" and m["format_version"] == 1
        assert m["counts"]["reports"] == 1 and m["counts"]["findings"] == 2
        for path, meta in m["files"].items():
            assert hashlib.sha256(zf.read(path)).hexdigest() == meta["sha256"]

    def test_images_are_deduplicated_assets_not_inline(self, client):
        _make_report(client)
        zf = zipfile.ZipFile(io.BytesIO(_export(client)))
        assets = [n for n in zf.namelist() if n.startswith("assets/")]
        assert len(assets) == 1 and assets[0].endswith(".png")      # 5 usos, 1 fichero
        assert zf.read(assets[0]) == PNG
        reports_json = zf.read("data/reports.json").decode()
        assert "data:image" not in reports_json and assets[0] in reports_json

    def test_never_exports_credentials(self, client, db_session):
        db_session.add(models.User(username="mario", password_hash="pbkdf2_sha256$1$aa$bb"))
        db_session.commit()
        blob = _export(client)
        zf = zipfile.ZipFile(io.BytesIO(blob))
        joined = b"".join(zf.read(n) for n in zf.namelist())
        assert b"pbkdf2_sha256" not in joined and b"mario" not in joined
        assert "users" in json.loads(zf.read("manifest.json"))["excluded"]

    def test_empty_instance_exports_fine(self, client):
        zf = zipfile.ZipFile(io.BytesIO(_export(client)))
        assert json.loads(zf.read("data/reports.json")) == []


class TestRoundTrip:
    def test_replace_restores_everything(self, client):
        r = _make_report(client)
        client.post("/api/themes", json={"slug": "mio", "name": "Mio", "html_template": "<h1>{{document_title}}</h1>", "custom_css": ".x{color:red}"})
        blob = _export(client)
        client.delete(f"/api/reports/{r['id']}")
        client.delete("/api/themes/1")
        assert client.get("/api/reports").json() == []

        res = _import(client, blob, mode="replace")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["imported"]["reports"] == 1 and body["imported"]["findings"] == 2

        reports = client.get("/api/reports").json()
        assert len(reports) == 1 and reports[0]["document_title"] == "Informe A"
        full = client.get(f"/api/reports/{reports[0]['id']}").json()
        assert full["client_logo"][0] == PNG_URL
        findings = client.get(f"/api/reports/{reports[0]['id']}/findings").json()
        assert [f["title"] for f in findings] == ["Hallazgo 0", "Hallazgo 1"]
        assert [f["severity"] for f in findings] == ["crit", "low"]
        assert findings[0]["images"] == [PNG_URL, PNG_URL] and findings[0]["image_captions"] == ["a", "b"]
        assert [t["slug"] for t in client.get("/api/themes").json()] == ["mio"]

    def test_merge_is_idempotent_and_skips_existing_slugs(self, client):
        _make_report(client)
        client.post("/api/themes", json={"slug": "mio", "name": "Mio", "html_template": "", "custom_css": ""})
        blob = _export(client)
        res = _import(client, blob, mode="merge").json()
        assert res["skipped"] == {"reports": 1, "themes": 1, "finding_templates": 0}
        assert res["imported"]["reports"] == 0 and res["imported"]["findings"] == 0
        assert len(client.get("/api/reports").json()) == 1          # re-importar la misma copia no duplica
        assert len(client.get("/api/themes").json()) == 1

    def test_merge_adds_a_report_that_changed_since_the_backup(self, client):
        r = _make_report(client)
        blob = _export(client)
        client.put(f"/api/reports/{r['id']}", json={"document_title": "Renombrado", "client_company": "ACME"})
        res = _import(client, blob, mode="merge").json()
        assert res["imported"]["reports"] == 1 and res["imported"]["findings"] == 2
        assert sorted(x["document_title"] for x in client.get("/api/reports").json()) == ["Informe A", "Renombrado"]

    def test_replace_wipes_previous_content(self, client):
        _make_report(client, "Antiguo")
        blob = _export(client)
        _make_report(client, "Extra")
        _import(client, blob, mode="replace")
        titles = [r["document_title"] for r in client.get("/api/reports").json()]
        assert titles == ["Antiguo"]

    def test_users_and_api_keys_untouched_by_replace(self, client, db_session):
        db_session.add(models.User(username="keeper", password_hash="pbkdf2_sha256$1$aa$bb"))
        db_session.commit()
        blob = _export(client)
        _import(client, blob, mode="replace")
        db_session.expire_all()
        assert db_session.query(models.User).filter_by(username="keeper").count() == 1

    def test_dry_run_does_not_write(self, client):
        _make_report(client)
        blob = _export(client)
        res = _import(client, blob, mode="replace", dry_run=True).json()
        assert res["dry_run"] is True and res["counts"]["reports"] == 1
        assert len(client.get("/api/reports").json()) == 1          # intacto (no duplicó ni borró)

    def test_settings_applied_only_on_replace(self, client):
        client.put("/api/settings", json={"lang": "en", "report_theme": "default", "pdf_print_theme": "default", "pdf_show_severity_bars": False, "pdf_content_width": 900})
        blob = _export(client)
        client.put("/api/settings", json={"lang": "es", "report_theme": "", "pdf_print_theme": "", "pdf_show_severity_bars": True, "pdf_content_width": 820})
        _import(client, blob, mode="merge")
        assert client.get("/api/settings").json()["lang"] == "es"
        _import(client, blob, mode="replace")
        s = client.get("/api/settings").json()
        assert s["lang"] == "en" and s["pdf_content_width"] == 900 and s["pdf_show_severity_bars"] is False


class TestRejectsBadArchives:
    def test_not_a_zip(self, client):
        r = _import(client, b"SQLite format 3\x00" + b"0" * 100)
        assert r.status_code == 400

    def test_old_sqlite_endpoints_are_gone(self, client):
        assert client.get("/api/database/export").status_code in (404, 405)
        assert client.post("/api/database/import", files={"file": ("x.db", b"x")}).status_code in (404, 405)

    def test_missing_manifest(self, client):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("data/reports.json", "[]")
        assert _import(client, buf.getvalue()).status_code == 400

    def test_wrong_format_and_newer_version(self, client):
        assert _import(client, _zip({}, manifest={"format": "otra-cosa", "format_version": 1, "files": {}})).status_code == 400
        r = _import(client, _zip({}, manifest={"format": "pwnly-backup", "format_version": 99, "files": {}}))
        assert r.status_code == 400 and "Actualiza" in r.json()["detail"]

    def test_tampered_content_detected(self, client):
        good = _zip({"data/reports.json": b"[]"})
        m = json.loads(zipfile.ZipFile(io.BytesIO(good)).read("manifest.json"))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps(m))
            zf.writestr("data/reports.json", b'[{"document_title":"inyectado"}]')   # distinto al hash declarado
        r = _import(client, buf.getvalue())
        assert r.status_code == 400 and "integridad" in r.json()["detail"]

    def test_path_traversal_entry_rejected(self, client):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps({"format": "pwnly-backup", "format_version": 1, "files": {}}))
            zf.writestr("../../etc/evil", b"x")
        assert _import(client, buf.getvalue()).status_code == 400

    def test_zip_bomb_limits(self, client, monkeypatch):
        monkeypatch.setattr(backup, "MAX_TOTAL_UNCOMPRESSED", 1000)
        blob = _zip({"data/reports.json": b"[" + b" " * 5000 + b"]"})
        assert _import(client, blob).status_code == 413

    def test_invalid_entity_aborts_everything(self, client):
        reports = json.dumps([{"document_title": "ok", "findings": []}, {"document_title": "mal", "classification": "no-es-int", "findings": []}]).encode()
        r = _import(client, _zip({"data/reports.json": reports}), mode="replace")
        assert r.status_code == 400
        assert client.get("/api/reports").json() == []                # nada se escribió

    def test_invalid_mode(self, client):
        assert _import(client, _zip({}), mode="drop-all").status_code == 400

    def test_fake_image_is_dropped_with_warning(self, client):
        fake = b"<script>alert(1)</script>"
        name = f"assets/{hashlib.sha256(fake).hexdigest()}.png"
        reports = json.dumps([{"document_title": "R", "client_logo": [name, ""], "findings": [{"title": "F", "images": [name]}]}]).encode()
        res = _import(client, _zip({"data/reports.json": reports, name: fake})).json()
        assert any("no es un formato de imagen" in w for w in res["warnings"])
        rid = client.get("/api/reports").json()[0]["id"]
        assert client.get(f"/api/reports/{rid}/findings").json()[0]["images"] == [""]   # el hueco se conserva

    def test_unsafe_theme_html_is_sanitized(self, client):
        themes = json.dumps([{"slug": "x", "name": "X", "html_template": "<h1>ok</h1><script>alert(1)</script>", "custom_css": ""}]).encode()
        _import(client, _zip({"data/themes.json": themes}))
        html = client.get("/api/themes").json()[0]["html_template"]
        assert "<script" not in html.lower() and "ok" in html

    def test_builtin_default_theme_is_not_imported(self, client):
        themes = json.dumps([{"slug": "default", "name": "D", "html_template": "", "custom_css": ""}]).encode()
        _import(client, _zip({"data/themes.json": themes}))
        assert client.get("/api/themes").json() == []

    def test_unknown_extra_files_ignored_with_warning(self, client):
        blob = _zip({"data/reports.json": b"[]"})
        buf = io.BytesIO(blob)
        with zipfile.ZipFile(buf, "a") as zf:
            zf.writestr("notas.txt", b"hola")
        res = _import(client, buf.getvalue()).json()
        assert any("notas.txt" in w for w in res["warnings"])


class TestCaptionAlignment:
    def test_failed_image_keeps_its_slot_so_captions_stay_aligned(self, client):
        fake = b"no soy una imagen"
        bad = f"assets/{hashlib.sha256(fake).hexdigest()}.png"
        good_name = f"assets/{hashlib.sha256(PNG).hexdigest()}.png"
        reports = json.dumps([{"document_title": "R", "findings": [
            {"title": "F", "images": [bad, good_name], "image_captions": ["rota", "buena"]}]}]).encode()
        _import(client, _zip({"data/reports.json": reports, bad: fake, good_name: PNG}))
        rid = client.get("/api/reports").json()[0]["id"]
        f = client.get(f"/api/reports/{rid}/findings").json()[0]
        assert f["images"] == ["", PNG_URL] and f["image_captions"] == ["rota", "buena"]
