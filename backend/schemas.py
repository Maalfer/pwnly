from pydantic import BaseModel, field_validator
from typing import List, Optional
from datetime import datetime
import re


# Logos y evidencias solo pueden ser data URLs de imagen. Cualquier URL remota
# se rechaza para evitar SSRF al generar el PDF y XSS al romper el atributo src.
_DATA_IMAGE_RE = re.compile(r'^data:image/[a-zA-Z0-9.+-]+;base64,[A-Za-z0-9+/=\s]+$')

# Caracteres permitidos en el nombre de usuario (sin comillas ni metacaracteres).
_USERNAME_RE = re.compile(r'^[A-Za-z0-9_.\-]{3,32}$')

# Únicos valores de severidad admitidos. El frontend los interpola directamente
# en atributos `class`/`style` (severity-<x>, var(--severity-<x>)), por lo que
# cualquier otro valor permitiría romper el atributo e inyectar HTML/JS (XSS).
# Se sanea aquí (entrada y salida) para neutralizar también datos ya guardados.
SEVERITY_LEVELS = ("crit", "high", "med", "low", "info")


def sanitize_severity(value) -> str:
    v = (value or "").strip().lower() if isinstance(value, str) else ""
    return v if v in SEVERITY_LEVELS else "info"


def is_safe_image_src(value) -> bool:
    return isinstance(value, str) and bool(_DATA_IMAGE_RE.match(value.strip()))


def sanitize_image_list(values, keep_slots: bool = False) -> List[str]:
    cleaned: List[str] = []
    for v in (values or []):
        if v == '' or is_safe_image_src(v):
            cleaned.append(v)
        elif keep_slots:
            cleaned.append('')
    return cleaned


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class AuthResponse(BaseModel):
    token: str
    username: str
    message: Optional[str] = None


class CreateUserRequest(BaseModel):
    username: str
    password: str

    @field_validator('username')
    @classmethod
    def _valid_username(cls, v):
        # Allowlist estricta: el username se refleja en handlers JS del frontend,
        # así que solo permitimos caracteres seguros para cerrar la clase de XSS.
        v = (v or '').strip()
        if not _USERNAME_RE.match(v):
            raise ValueError('El usuario solo admite letras, números y . _ - (3 a 32 caracteres)')
        return v


class UserInfo(BaseModel):
    id: int
    username: str
    created_at: datetime

    class Config:
        from_attributes = True


def _clean_str_list(values, limit: int = 50, maxlen: int = 500) -> List[str]:
    """Lista de cadenas saneada: descarta vacíos, recorta longitud y nº de ítems."""
    out: List[str] = []
    for v in (values or []):
        if not isinstance(v, str):
            continue
        v = v.strip()
        if v:
            out.append(v[:maxlen])
        if len(out) >= limit:
            break
    return out


class FindingBase(BaseModel):
    template_key: str = "custom"
    title: str
    severity: str = "med"
    description: str = ""
    cvss: str = ""
    cvss_vector: str = ""
    poc: str = ""
    exploit: str = ""
    impact: str = ""
    remediation: str = ""
    reference: str = ""
    references: List[str] = []
    cve: str = ""
    cwe: str = ""
    status: str = "open"
    affected_assets: str = ""
    likelihood: str = ""
    impact_rating: str = ""
    owasp: str = ""
    compliance: List[str] = []
    retest_notes: str = ""
    fields_visibility: dict = {}
    images: List[str] = []
    image_captions: List[str] = []
    order_index: int = 0

    @field_validator('severity')
    @classmethod
    def _sanitize_severity(cls, v):
        return sanitize_severity(v)

    @field_validator('images')
    @classmethod
    def _sanitize_images(cls, v):
        return sanitize_image_list(v)

    @field_validator('references', 'compliance', 'image_captions')
    @classmethod
    def _sanitize_str_lists(cls, v):
        return _clean_str_list(v)


class FindingCreate(FindingBase):
    pass


class FindingUpdate(FindingBase):
    pass


class FindingPatch(BaseModel):
    """Actualización parcial de un hallazgo (solo los campos enviados).

    La API REST expone PATCH para que scripts e integraciones puedan modificar
    un único campo (p. ej. el estado de remediación) sin reenviar el hallazgo
    completo ni resetear los campos omitidos.
    """
    template_key: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    cvss: Optional[str] = None
    cvss_vector: Optional[str] = None
    poc: Optional[str] = None
    exploit: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    reference: Optional[str] = None
    references: Optional[List[str]] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    status: Optional[str] = None
    affected_assets: Optional[str] = None
    likelihood: Optional[str] = None
    impact_rating: Optional[str] = None
    owasp: Optional[str] = None
    compliance: Optional[List[str]] = None
    retest_notes: Optional[str] = None
    fields_visibility: Optional[dict] = None
    images: Optional[List[str]] = None
    image_captions: Optional[List[str]] = None
    order_index: Optional[int] = None

    @field_validator('severity')
    @classmethod
    def _sanitize_severity(cls, v):
        return sanitize_severity(v) if v is not None else v

    @field_validator('images')
    @classmethod
    def _sanitize_images(cls, v):
        return sanitize_image_list(v) if v is not None else v

    @field_validator('references', 'compliance', 'image_captions')
    @classmethod
    def _sanitize_str_lists(cls, v):
        return _clean_str_list(v) if v is not None else v


class FindingResponse(FindingBase):
    id: int
    report_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RevisionEntry(BaseModel):
    version: str = ""
    date: str = ""
    author: str = ""
    changes: str = ""


class ReportBase(BaseModel):
    document_title: str = "Reporte Técnico de Vulnerabilidades"
    client_company: str = "Empresa Cliente S.A."
    target_asset: str = "Aplicación Principal"
    auditor_company: str = "Empresa Auditora LLC"
    auditor_name: str = "Juan Pérez"
    auditor_phone: str = ""
    auditor_email: str = ""
    classification: int = 2
    tlp_level: str = "amber"
    classification_mode: str = "internal"
    version: str = "1.0"
    date: str = ""
    lang: str = "es"
    theme: str = "corporate"  # corporate, ctf, certification (legacy)
    client_logo: List[str] = []
    has_incidents: bool = False
    incidents_text: str = ""
    audit_summary: str = ""
    tests_performed: str = ""
    recommended_solutions: str = ""
    audit_type: str = "pentesting_web"
    scope_in: str = ""
    scope_out: str = ""
    methodology_notes: str = ""
    methodology_standards: List[str] = []
    tools_used: str = ""
    engagement_start: str = ""
    engagement_end: str = ""
    revision_history: List[RevisionEntry] = []
    show_scope_section: int = 1  # 1=incluir, 0=ocultar
    scope_fields_visibility: dict = {}

    @field_validator('client_logo')
    @classmethod
    def _sanitize_client_logo(cls, v):
        return sanitize_image_list(v, keep_slots=True)

    @field_validator('methodology_standards')
    @classmethod
    def _sanitize_methodology(cls, v):
        return _clean_str_list(v, limit=30, maxlen=80)


class ReportCreate(ReportBase):
    pass


class ReportUpdate(ReportBase):
    pass


class ReportResponse(ReportBase):
    id: int
    created_at: datetime
    updated_at: datetime
    findings: List[FindingResponse] = []

    class Config:
        from_attributes = True


class ReportList(BaseModel):
    id: int
    document_title: str
    client_company: str
    target_asset: str
    date: str
    created_at: datetime
    findings_count: int = 0

    class Config:
        from_attributes = True


# --------------------------------------------------------------------------- #
# Temas de informe (plantilla HTML + CSS creados íntegramente por el usuario)
# --------------------------------------------------------------------------- #
# Slug seguro: se usa como identificador del tema (y en nombres de fichero al
# exportar), así que sólo permitimos caracteres inertes.
_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,48}$')


def _decode_css_escapes(css: str) -> str:
    """Resuelve los escapes CSS (\\XX hexadecimal y \\X literal) tal y como
    los interpreta el tokenizador de cualquier navegador, ANTES de aplicar
    el blocklist. Sin esto, payloads como "\\75 rl(" evaden la detección de
    "url(" porque la subcadena literal nunca aparece en el texto crudo.
    """
    def _hex(m):
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return ''
    css = re.sub(r'\\([0-9a-fA-F]{1,6})\s?', _hex, css)
    css = re.sub(r'\\(.)', r'\1', css, flags=re.DOTALL)
    return css


MAX_THEME_CSS = 200_000   # alineado con el límite de la plantilla HTML


def _strip_dangerous_css(css: str) -> str:
    """Elimina construcciones peligrosas (peticiones externas, JS, HTML)."""
    css = re.sub(r'@import[^;]*;?', '', css, flags=re.IGNORECASE)
    css = re.sub(r'expression\s*\([^)]*\)', '', css, flags=re.IGNORECASE)
    css = re.sub(r'(javascript|vbscript)\s*:', '', css, flags=re.IGNORECASE)
    css = re.sub(r'-moz-binding\s*:[^;]*;?', '', css, flags=re.IGNORECASE)
    css = re.sub(r'behavior\s*:[^;]*;?', '', css, flags=re.IGNORECASE)

    # url(...) sólo se permite con data: o fragmentos (#id); el resto -> none.
    def _url(m):
        inner = m.group(1).strip().strip('\'"').lower()
        return m.group(0) if (inner.startswith('data:') or inner.startswith('#')) else 'none'
    return re.sub(r'url\(([^)]*)\)', _url, css, flags=re.IGNORECASE)


def sanitize_css_source(css) -> str:
    """Sanea CSS libre escrito por el usuario antes de inyectarlo en un <style>.

    Elimina lo que permitiría romper el <style>, inyectar HTML/JS o hacer
    peticiones externas (SSRF al imprimir): etiquetas, @import, expression(),
    javascript:, behavior y url() que no sean data: o fragmentos locales.

    Se conserva el CSS legítimo: el combinador hijo ">", los escapes CSS válidos y
    hojas largas (hasta MAX_THEME_CSS caracteres).
    """
    if not isinstance(css, str):
        return ''
    css = css[:MAX_THEME_CSS]
    # Fuera etiquetas HTML completas (</style>, <script>...) y cualquier "<" suelto: es lo único
    # que puede cerrar el <style>. El ">" del combinador hijo no se toca.
    css = re.sub(r'<\s*/?\s*[A-Za-z!][^>]*>', '', css).replace('<', '')
    # Los escapes (\75 -> "u") pueden reconstruir palabras bloqueadas ("\75 rl("). Se
    # comprueba la versión decodificada: si al decodificar aparece algo bloqueado, se
    # usa esa versión saneada; si no, se conserva el original (con sus escapes legítimos,
    # p. ej. content: "\201C").
    decoded = _decode_css_escapes(css)
    cleaned_decoded = _strip_dangerous_css(decoded)
    if cleaned_decoded != decoded:
        return cleaned_decoded
    return _strip_dangerous_css(css)


def sanitize_html_template(html) -> str:
    """Sanea la plantilla HTML libre del tema (motor {{variable}}/{{#each}}/{{#if}}
    sobre los datos del reporte, ver js/theme-engine.js).

    El usuario tiene control total de la maquetación, pero la plantilla puede
    acabar en un informe HTML autocontenido abierto por un tercero (el
    cliente de la auditoría), así que quitamos lo ejecutable: <script>,
    atributos de evento (onClick=...) y URIs javascript:/vbscript:. El motor
    de plantillas procesa el texto ya saneado, así que los tokens {{...}} no
    se ven afectados por nada de esto.
    """
    if not isinstance(html, str):
        return ''
    html = html[:200000]
    html = re.sub(r'<script\b[^>]*>.*?</script\s*>', '', html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r'<script\b[^>]*/?>', '', html, flags=re.IGNORECASE)
    html = re.sub(r'\son[a-zA-Z]+\s*=\s*"[^"]*"', '', html, flags=re.IGNORECASE)
    html = re.sub(r"\son[a-zA-Z]+\s*=\s*'[^']*'", '', html, flags=re.IGNORECASE)
    html = re.sub(r'\son[a-zA-Z]+\s*=\s*[^\s>]+', '', html, flags=re.IGNORECASE)
    html = re.sub(r'(href|src)\s*=\s*"(\s*(javascript|vbscript)\s*:[^"]*)"', r'\1="#"', html, flags=re.IGNORECASE)
    html = re.sub(r"(href|src)\s*=\s*'(\s*(javascript|vbscript)\s*:[^']*)'", r"\1='#'", html, flags=re.IGNORECASE)
    return html


class ThemeBase(BaseModel):
    slug: str
    name: str
    html_template: str = ""
    custom_css: str = ""

    @field_validator('slug')
    @classmethod
    def _valid_slug(cls, v):
        v = (v or '').strip().lower()
        if not _SLUG_RE.match(v):
            raise ValueError('Slug inválido (solo minúsculas, números y guiones)')
        return v

    @field_validator('html_template')
    @classmethod
    def _clean_html(cls, v):
        return sanitize_html_template(v)

    @field_validator('custom_css')
    @classmethod
    def _clean_css(cls, v):
        return sanitize_css_source(v)


class ThemeCreate(ThemeBase):
    pass


class ThemeResponse(ThemeBase):
    id: int

    class Config:
        from_attributes = True


# --------------------------------------------------------------------------- #
# Plantillas de hallazgo del usuario
# --------------------------------------------------------------------------- #
class FindingTemplateBase(BaseModel):
    slug: str
    name: str
    title: str = ""
    severity: str = "med"
    cvss: str = ""
    cvss_vector: str = ""
    description: str = ""
    poc: str = ""
    exploit: str = ""
    impact: str = ""
    remediation: str = ""
    reference: str = ""
    cwe: str = ""
    cve: str = ""
    owasp: str = ""

    @field_validator('slug')
    @classmethod
    def _valid_slug(cls, v):
        v = (v or '').strip().lower()
        if not _SLUG_RE.match(v):
            raise ValueError('Slug inválido (solo minúsculas, números y guiones)')
        return v

    @field_validator('severity')
    @classmethod
    def _sanitize_severity(cls, v):
        return sanitize_severity(v)


class FindingTemplateCreate(FindingTemplateBase):
    pass


class FindingTemplateResponse(FindingTemplateBase):
    id: int

    class Config:
        from_attributes = True


class AppSettingsBase(BaseModel):
    lang: str = "es"
    report_theme: str = ""
    pdf_print_theme: str = ""
    pdf_show_severity_bars: bool = True
    pdf_content_width: int = 820

    @field_validator('lang')
    @classmethod
    def _valid_lang(cls, v):
        return v if v in ('es', 'en') else 'es'

    @field_validator('pdf_content_width')
    @classmethod
    def _clamp_width(cls, v):
        try:
            v = int(v)
        except (TypeError, ValueError):
            return 820
        return max(400, min(1400, v))


class AppSettingsUpdate(AppSettingsBase):
    pass


class AppSettingsResponse(AppSettingsBase):
    class Config:
        from_attributes = True


# --------------------------------------------------------------------------- #
# API Keys (acceso programático a la API REST)
# --------------------------------------------------------------------------- #
class ApiKeyCreate(BaseModel):
    label: str = "API Key"


class ApiKeyInfo(BaseModel):
    id: int
    label: str
    prefix: str
    created_at: datetime
    last_used_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ApiKeyCreated(ApiKeyInfo):
    """Igual que ApiKeyInfo pero incluye el secreto completo (solo al crear)."""
    key: str
