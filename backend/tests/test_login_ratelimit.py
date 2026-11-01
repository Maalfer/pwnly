"""Anti fuerza bruta del login: X-Forwarded-For no debe permitir evadir el límite."""
import pytest

import main


@pytest.fixture(autouse=True)
def _reset_login_state():
    main._login_fails.clear()
    yield
    main._login_fails.clear()


def _login(client, user="victim", pw="wrong-pass", xff=None):
    headers = {"X-Forwarded-For": xff} if xff else {}
    return client.post("/api/auth/login", json={"username": user, "password": pw}, headers=headers)


class TestLoginRateLimit:
    def test_blocks_after_max_fails(self, client):
        for _ in range(main._LOGIN_MAX_FAILS):
            assert _login(client).status_code == 401
        r = _login(client)
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    def test_rotating_x_forwarded_for_does_not_bypass(self, client):
        # Cada petición con una "IP" distinta en la cabecera: debe seguir bloqueando.
        codes = [_login(client, xff=f"10.10.10.{i}").status_code for i in range(main._LOGIN_MAX_FAILS + 3)]
        assert codes[: main._LOGIN_MAX_FAILS] == [401] * main._LOGIN_MAX_FAILS
        assert set(codes[main._LOGIN_MAX_FAILS:]) == {429}

    def test_per_username_limit_stops_ip_rotation(self, client, monkeypatch):
        # Aunque se rote la IP real (proxy de confianza), el límite por usuario corta.
        monkeypatch.setattr(main, "_TRUSTED_PROXIES", {"testclient"})
        n = main._LOGIN_MAX_FAILS_USER
        codes = [_login(client, xff=f"203.0.113.{i}").status_code for i in range(n + 2)]
        assert codes[:n] == [401] * n
        assert set(codes[n:]) == {429}

    def test_trusted_proxy_uses_rightmost_untrusted_hop(self, monkeypatch):
        from starlette.requests import Request
        monkeypatch.setattr(main, "_TRUSTED_PROXIES", {"192.0.2.1"})

        def req(peer, xff):
            return Request({"type": "http", "method": "POST", "path": "/", "scheme": "http",
                            "server": ("t", 80), "client": (peer, 1),
                            "headers": [(b"x-forwarded-for", xff.encode())]})

        # Cliente falsifica la 1ª entrada; el proxy añade la IP real al final.
        assert main._client_ip(req("192.0.2.1", "1.2.3.4, 198.51.100.7")) == "198.51.100.7"
        # Conexión directa (no es proxy de confianza): se ignora la cabecera.
        assert main._client_ip(req("198.51.100.9", "1.2.3.4")) == "198.51.100.9"

    def test_tracked_keys_are_bounded(self, client, monkeypatch):
        monkeypatch.setattr(main, "_LOGIN_MAX_TRACKED", 50)
        for i in range(200):
            _login(client, user=f"user{i:03d}")
        assert len(main._login_fails) <= 50 + 2

    def test_successful_login_resets_counters(self, client):
        client.post("/api/auth/setup", json={"username": "owner", "password": "s3cret-pass"})
        for _ in range(main._LOGIN_MAX_FAILS - 1):
            _login(client, user="owner")
        assert _login(client, user="owner", pw="s3cret-pass").status_code == 200
        assert _login(client, user="owner").status_code == 401  # contador reiniciado
