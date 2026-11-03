"""El saneado de temas debe bloquear lo peligroso SIN romper CSS/HTML legítimo
(incluido el tema por defecto, que los usuarios duplican y se guarda por la API)."""
import os
import re

import schemas

JS = os.path.join(os.path.dirname(__file__), "..", "..", "js", "app.js")


def _default_theme():
    src = open(JS, encoding="utf-8").read()
    html = re.search(r"const DEFAULT_THEME_TEMPLATE_HTML = `(.*?)`;", src, re.S).group(1)
    css = re.search(r"const DEFAULT_THEME_TEMPLATE_CSS = `(.*?)`;", src, re.S).group(1)
    return html, css


class TestCssSanitizer:
    def test_long_css_is_not_truncated(self):
        css = ".a{color:red}\n" * 2000            # ~28 KB (el límite antiguo era 8000)
        assert schemas.sanitize_css_source(css) == css

    def test_child_combinator_is_preserved(self):
        css = ".toc > li > a { color: #111; }"
        assert schemas.sanitize_css_source(css) == css

    def test_cannot_close_the_style_element(self):
        out = schemas.sanitize_css_source("a{color:red}</style><script>alert(1)</script>")
        assert "<" not in out and "style" not in out.lower().replace("a{color:red}", "") and "script" not in out.lower()

    def test_blocks_external_requests_and_scripts(self):
        out = schemas.sanitize_css_source("@import url(http://evil/x.css); a{background:url(http://evil/p.png); behavior:url(x.htc)} b{width:expression(alert(1))}")
        assert "@import" not in out and "http://evil" not in out and "expression" not in out and "behavior" not in out

    def test_escape_obfuscation_is_still_blocked(self):
        out = schemas.sanitize_css_source(r"a{background:\75 rl(http://evil/p.png)}")
        assert "evil" not in out

    def test_data_and_fragment_urls_are_allowed(self):
        css = "a{background:url(data:image/png;base64,AAAA)} b{fill:url(#grad)}"
        assert schemas.sanitize_css_source(css) == css

    def test_legit_css_escapes_are_preserved(self):
        css = 'q::before{content:"\\201C"} .md\\:flex{display:flex}'
        assert schemas.sanitize_css_source(css) == css

    def test_page_rules_with_margin_boxes_are_preserved(self):
        css = '@page { size: A4; margin: 18mm 16mm; @bottom-center { content: counter(page) " / " counter(pages); } }'
        assert schemas.sanitize_css_source(css) == css


class TestHtmlSanitizer:
    def test_removes_scripts_handlers_and_js_urls(self):
        out = schemas.sanitize_html_template('<a href="javascript:alert(1)" onclick="x()">a</a><script>x</script>')
        assert "script" not in out.lower() and "onclick" not in out and "javascript:" not in out


class TestDefaultThemeSurvivesSanitizers:
    """Duplicar el tema por defecto lo guarda vía API (que sanea): no puede salir distinto."""

    def test_default_theme_is_unchanged_by_sanitizers(self):
        html, css = _default_theme()
        assert len(css) > 8000                                     # regresión: antes se truncaba
        assert schemas.sanitize_css_source(css) == css
        assert schemas.sanitize_html_template(html) == html

    def test_duplicating_the_default_theme_via_the_api_keeps_it_intact(self, client):
        html, css = _default_theme()
        r = client.post("/api/themes", json={"slug": "copia", "name": "Copia", "html_template": html, "custom_css": css})
        assert r.status_code == 200
        saved = client.get("/api/themes").json()[0]
        assert saved["custom_css"] == css and saved["html_template"] == html
