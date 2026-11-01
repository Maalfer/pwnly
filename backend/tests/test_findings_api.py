"""Tests para la gestión de hallazgos vía API REST (v2.4.0).

Cubre el flujo de gestión de hallazgos vía API REST: obtener un hallazgo
concreto, actualización parcial con PATCH y creación en lote.
"""


def _create_report(client):
    return client.post("/api/reports", json={
        "document_title": "API Findings Report",
        "client_company": "ACME",
        "target_asset": "https://app.example.com",
        "auditor_company": "Auditor",
        "auditor_name": "Tester",
        "date": "2026-11-01",
        "lang": "es",
    }).json()


class TestFindingsApi:
    def test_get_single_finding(self, client):
        report = _create_report(client)
        created = client.post(f"/api/reports/{report['id']}/findings", json={
            "title": "IDOR",
            "severity": "high",
            "cwe": "CWE-639",
        }).json()

        response = client.get(f"/api/findings/{created['id']}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == created["id"]
        assert data["title"] == "IDOR"

    def test_get_missing_finding_returns_404(self, client):
        assert client.get("/api/findings/9999").status_code == 404

    def test_patch_only_updates_sent_fields(self, client):
        report = _create_report(client)
        created = client.post(f"/api/reports/{report['id']}/findings", json={
            "title": "XSS",
            "severity": "high",
            "description": "Descripción original",
            "poc": "Payload original",
            "cwe": "CWE-79",
        }).json()

        response = client.patch(f"/api/findings/{created['id']}", json={
            "status": "remediated",
            "retest_notes": "Corregido",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "remediated"
        assert data["retest_notes"] == "Corregido"
        # Los campos no enviados se conservan intactos.
        assert data["title"] == "XSS"
        assert data["severity"] == "high"
        assert data["description"] == "Descripción original"
        assert data["poc"] == "Payload original"
        assert data["cwe"] == "CWE-79"

    def test_patch_sanitizes_severity(self, client):
        report = _create_report(client)
        created = client.post(f"/api/reports/{report['id']}/findings", json={
            "title": "Test", "severity": "low",
        }).json()

        data = client.patch(f"/api/findings/{created['id']}", json={
            "severity": "<script>alert(1)</script>",
        }).json()
        assert data["severity"] == "info"

    def test_patch_rejects_empty_title(self, client):
        report = _create_report(client)
        created = client.post(f"/api/reports/{report['id']}/findings", json={
            "title": "Test", "severity": "low",
        }).json()

        response = client.patch(f"/api/findings/{created['id']}", json={"title": "   "})
        assert response.status_code == 422

    def test_patch_missing_finding_returns_404(self, client):
        response = client.patch("/api/findings/9999", json={"status": "open"})
        assert response.status_code == 404

    def test_bulk_create_appends_in_order(self, client):
        report = _create_report(client)
        client.post(f"/api/reports/{report['id']}/findings", json={
            "title": "Primero", "severity": "low",
        })

        response = client.post(f"/api/reports/{report['id']}/findings/bulk", json=[
            {"title": "Segundo", "severity": "med"},
            {"title": "Tercero", "severity": "high"},
        ])
        assert response.status_code == 200
        created = response.json()
        assert [f["title"] for f in created] == ["Segundo", "Tercero"]
        assert [f["order_index"] for f in created] == [1, 2]

        listed = client.get(f"/api/reports/{report['id']}/findings").json()
        assert [f["title"] for f in listed] == ["Primero", "Segundo", "Tercero"]

    def test_bulk_create_missing_report_returns_404(self, client):
        response = client.post("/api/reports/9999/findings/bulk", json=[
            {"title": "Test", "severity": "low"},
        ])
        assert response.status_code == 404
