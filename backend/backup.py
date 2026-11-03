"""
Copias de seguridad de Pwnly (exportar / importar).

La base de datos SQLite es la ÚNICA fuente de verdad de la aplicación; nunca se
exporta como fichero. Una copia de seguridad es un archivo ZIP portable y
versionado, legible por humanos y herramientas:

    pwnly-backup-YYYYMMDD-HHMMSS.zip
    ├── manifest.json            formato, versión, fecha, recuentos y SHA-256 de cada fichero
    ├── data/
    │   ├── reports.json         reportes con sus hallazgos anidados
    │   ├── themes.json          temas de informe del usuario (HTML + CSS)
    │   ├── finding_templates.json
    │   └── settings.json        preferencias de la aplicación
    └── assets/
        └── <sha256>.<ext>       imágenes (logos y evidencias), deduplicadas por contenido

Decisiones de diseño:
  * Las imágenes salen de los JSON como ficheros binarios (nada de data URLs de
    megabytes dentro del JSON) y se direccionan por contenido: la misma imagen
    usada diez veces se guarda una sola vez.
  * NO se exportan usuarios, hashes de contraseña ni API keys: las credenciales
    pertenecen a la instancia y no deben viajar en un archivo portable.
  * El formato lleva `format_version`; una copia más nueva que la app se rechaza
    con un mensaje claro y las desconocidas se toleran (campos extra ignorados).
  * Importar es "todo o nada": se valida el archivo completo (estructura, límites,
    hashes y esquemas) ANTES de tocar la base de datos y se aplica en una única
    transacción; si algo falla se hace rollback y no cambia nada.
  * El archivo se trata como no confiable: límites de tamaño/entradas (zip-bomb),
    nombres de entrada estrictos, lectura acotada, imágenes verificadas por firma
    binaria y todo el contenido pasa por los mismos esquemas/sanitizadores que
    la API normal.
"""
import base64
import binascii
import hashlib
import json
import os
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from pydantic import ValidationError
from sqlalchemy.orm import Session

import models
import schemas

FORMAT = "pwnly-backup"
FORMAT_VERSION = 1
APP_VERSION = "1.0.0"

# --- Límites defensivos (el archivo importado no es de fiar) ----------------- #
MAX_UPLOAD_BYTES = 256 * 1024 * 1024        # ZIP subido
MAX_TOTAL_UNCOMPRESSED = 768 * 1024 * 1024  # suma de todas las entradas descomprimidas
MAX_ENTRIES = 20000
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_ASSET_BYTES = 25 * 1024 * 1024
MAX_REPORTS = 10000
MAX_FINDINGS_PER_REPORT = 5000
MAX_THEMES = 500
MAX_TEMPLATES = 5000

MANIFEST_PATH = "manifest.json"
DATA_FILES = {
    "reports": "data/reports.json",
    "themes": "data/themes.json",
    "finding_templates": "data/finding_templates.json",
    "settings": "data/settings.json",
}
ASSET_PREFIX = "assets/"

# mime -> extensión (solo formatos de imagen que la app admite como data URL)
_MIME_EXT = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/gif": "gif",
    "image/webp": "webp",
    "image/svg+xml": "svg",
    "image/bmp": "bmp",
}
_EXT_MIME = {"png": "image/png", "jpg": "image/jpeg", "gif": "image/gif",
             "webp": "image/webp", "svg": "image/svg+xml", "bmp": "image/bmp"}

_DATA_URL_RE = re.compile(r"^data:(image/[a-zA-Z0-9.+-]+);base64,(.*)$", re.DOTALL)
_ASSET_NAME_RE = re.compile(r"^assets/[0-9a-f]{64}\.(png|jpg|gif|webp|svg|bmp)$")
_ENTRY_NAME_RE = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")


class BackupError(Exception):
    """Error de validación mostrable al usuario (código HTTP incluido)."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# =========================================================================== #
# Utilidades
# =========================================================================== #
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iso(dt) -> Optional[str]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value) -> Optional[datetime]:
    """ISO-8601 -> datetime UTC ingenuo (como guarda la BD). Tolerante: None si no es válido."""
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _sniff_image_ext(data: bytes) -> Optional[str]:
    """Extensión según la firma binaria real (no nos fiamos del nombre ni del mime declarado)."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"BM"):
        return "bmp"
    head = data[:2048].lstrip().lower()
    if head.startswith((b"<svg", b"<?xml")) and b"<svg" in data[:4096].lower():
        return "svg"
    return None


# =========================================================================== #
# EXPORTAR
# =========================================================================== #
def _externalize(value, assets: Dict[str, bytes]):
    """data URL de imagen -> 'assets/<sha256>.<ext>' (guardando los bytes en `assets`).
    Cualquier otro valor se devuelve tal cual (no se pierde información)."""
    if not isinstance(value, str):
        return value
    m = _DATA_URL_RE.match(value.strip())
    if not m:
        return value
    ext = _MIME_EXT.get(m.group(1).lower())
    if not ext:
        return value
    try:
        raw = base64.b64decode("".join(m.group(2).split()), validate=True)
    except (binascii.Error, ValueError):
        return value
    if not raw or len(raw) > MAX_ASSET_BYTES:
        return value
    name = f"{ASSET_PREFIX}{_sha256(raw)}.{ext}"
    assets[name] = raw
    return name


_SKIP_COLS = {"id", "report_id"}


def _row(obj) -> dict:
    """Volcado de las columnas de una fila (sin ids/FK). Los NULL se omiten para que al
    importar se apliquen los valores por defecto del esquema. Al derivarse de las
    columnas del modelo, cualquier campo nuevo entra solo en la copia."""
    out = {}
    for col in obj.__table__.columns:
        if col.name in _SKIP_COLS:
            continue
        v = getattr(obj, col.name)
        if v is None:
            continue
        out[col.name] = _iso(v) if isinstance(v, datetime) else v
    return out


def _as_list(v) -> list:
    return v if isinstance(v, list) else []


def _report_to_dict(report: "models.Report", assets: Dict[str, bytes]) -> dict:
    data = _row(report)
    data["client_logo"] = [_externalize(v, assets) for v in _as_list(data.get("client_logo"))]
    findings = sorted(report.findings, key=lambda f: (f.order_index or 0, f.id or 0))
    out = []
    for f in findings:
        fd = _row(f)
        fd["images"] = [_externalize(v, assets) for v in _as_list(fd.get("images"))]
        out.append(fd)
    data["findings"] = out
    return data


def _dump_json(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False).encode("utf-8")


def build_archive(db: Session, dest_path: str) -> dict:
    """Genera el ZIP de copia de seguridad en `dest_path`. Devuelve el manifiesto."""
    assets: Dict[str, bytes] = {}

    reports = [
        _report_to_dict(r, assets)
        for r in db.query(models.Report).order_by(models.Report.created_at, models.Report.id).all()
    ]
    themes = [_row(t) for t in db.query(models.Theme).order_by(models.Theme.id).all()]
    templates = [_row(t) for t in db.query(models.FindingTemplate).order_by(models.FindingTemplate.id).all()]
    settings_row = db.query(models.AppSettings).first()
    settings = _row(settings_row) if settings_row else schemas.AppSettingsBase().model_dump(mode="json")
    settings.pop("updated_at", None)
    settings.pop("id", None)

    files: Dict[str, bytes] = {
        DATA_FILES["reports"]: _dump_json(reports),
        DATA_FILES["themes"]: _dump_json(themes),
        DATA_FILES["finding_templates"]: _dump_json(templates),
        DATA_FILES["settings"]: _dump_json(settings),
    }
    files.update(assets)

    manifest = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "app": "pwnly",
        "app_version": APP_VERSION,
        "created_at": _iso(datetime.now(timezone.utc)),
        "counts": {
            "reports": len(reports),
            "findings": sum(len(r["findings"]) for r in reports),
            "themes": len(themes),
            "finding_templates": len(templates),
            "assets": len(assets),
        },
        # Lo que NO viaja en la copia: pertenece a la instancia, no al contenido.
        "excluded": ["users", "password_hashes", "api_keys", "sessions"],
        "files": {
            path: {"sha256": _sha256(blob), "size": len(blob)}
            for path, blob in sorted(files.items())
        },
    }

    with zipfile.ZipFile(dest_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr(MANIFEST_PATH, _dump_json(manifest))
        for path in sorted(files):
            # Las imágenes ya están comprimidas: se guardan sin recomprimir.
            comp = zipfile.ZIP_STORED if path.startswith(ASSET_PREFIX) else zipfile.ZIP_DEFLATED
            zi = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, files[path], compress_type=comp)
    return manifest


# =========================================================================== #
# IMPORTAR — lectura y validación (no toca la BD)
# =========================================================================== #
class ParsedBackup:
    def __init__(self):
        self.manifest: dict = {}
        self.reports: List[Tuple[schemas.ReportCreate, List[schemas.FindingCreate], dict]] = []
        self.themes: List[Tuple[schemas.ThemeCreate, dict]] = []
        self.templates: List[Tuple[schemas.FindingTemplateCreate, dict]] = []
        self.settings: Optional[schemas.AppSettingsBase] = None
        self.warnings: List[str] = []

    def summary(self) -> dict:
        m = self.manifest
        return {
            "format": m.get("format"),
            "format_version": m.get("format_version"),
            "app_version": m.get("app_version"),
            "created_at": m.get("created_at"),
            "counts": {
                "reports": len(self.reports),
                "findings": sum(len(f) for _, f, _ in self.reports),
                "themes": len(self.themes),
                "finding_templates": len(self.templates),
                "assets": sum(1 for p in (m.get("files") or {}) if p.startswith(ASSET_PREFIX)),
            },
            "reports": [
                {"title": r.document_title, "client": r.client_company, "findings": len(f)}
                for r, f, _ in self.reports[:50]
            ],
            "excluded": m.get("excluded", []),
            "warnings": self.warnings[:20],
        }


def _read_bounded(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    """Lee una entrada con tope REAL (la cabecera del ZIP puede mentir sobre el tamaño)."""
    with zf.open(info, "r") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise BackupError(f"La entrada «{info.filename}» supera el tamaño máximo permitido", 413)
    return data


def _validate_zip_structure(zf: zipfile.ZipFile) -> Dict[str, zipfile.ZipInfo]:
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise BackupError("El archivo contiene demasiadas entradas", 413)
    total = 0
    by_name: Dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        name = info.filename
        if info.is_dir():
            continue
        # Nombres estrictos: nada de rutas absolutas, '..', backslashes ni caracteres raros.
        if (name.startswith("/") or ".." in name.split("/") or "\\" in name
                or not _ENTRY_NAME_RE.match(name)):
            raise BackupError("El archivo contiene nombres de entrada no válidos", 400)
        if name in by_name:
            raise BackupError("El archivo contiene entradas duplicadas", 400)
        if info.flag_bits & 0x1:
            raise BackupError("El archivo ZIP está cifrado con contraseña propia; exporta una copia nueva desde Pwnly", 400)
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED:
            raise BackupError("El contenido descomprimido supera el límite permitido", 413)
        by_name[name] = info
    return by_name


def _internalize(value, zf, by_name, manifest_files, assets_cache: dict, warnings: List[str]):
    """'assets/<hash>.<ext>' -> data URL (verificando existencia, hash y firma de imagen).
    Los data URLs en línea (copias antiguas/manuales) se aceptan y pasan por el esquema."""
    if not isinstance(value, str) or not value.startswith(ASSET_PREFIX):
        return value
    if not _ASSET_NAME_RE.match(value) or value not in by_name or value not in manifest_files:
        warnings.append(f"Imagen referenciada no encontrada en la copia: {value[:80]}")
        return ""
    if value not in assets_cache:
        raw = _read_bounded(zf, by_name[value], MAX_ASSET_BYTES)
        ext = _sniff_image_ext(raw)
        name_ext = value.rsplit(".", 1)[-1]
        if ext is None or ext != name_ext:
            warnings.append(f"Imagen descartada (no es un formato de imagen válido): {value[:80]}")
            assets_cache[value] = ""
        else:
            b64 = base64.b64encode(raw).decode("ascii")
            assets_cache[value] = f"data:{_EXT_MIME[ext]};base64,{b64}"
    return assets_cache[value]


def _load_json(zf, by_name, manifest_files, path, default):
    if path not in manifest_files:
        return default
    if path not in by_name:
        raise BackupError(f"Falta el fichero «{path}» declarado en el manifiesto", 400)
    raw = _read_bounded(zf, by_name[path], MAX_JSON_BYTES)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise BackupError(f"El fichero «{path}» no es un JSON válido", 400)


def _fmt_validation(e: ValidationError) -> str:
    first = e.errors()[0] if e.errors() else {}
    loc = ".".join(str(x) for x in first.get("loc", ()))
    return f"{loc}: {first.get('msg', 'valor no válido')}"


def read_archive(path: str) -> ParsedBackup:
    """Lee y valida por completo un ZIP de copia. Lanza BackupError; no toca la BD."""
    if not zipfile.is_zipfile(path):
        raise BackupError("El archivo no es una copia de seguridad de Pwnly (.zip) válida", 400)
    try:
        zf = zipfile.ZipFile(path, "r")
    except (zipfile.BadZipFile, OSError):
        raise BackupError("El archivo ZIP está dañado", 400)

    with zf:
        by_name = _validate_zip_structure(zf)

        if MANIFEST_PATH not in by_name:
            raise BackupError("No es una copia de Pwnly: falta manifest.json", 400)
        try:
            manifest = json.loads(_read_bounded(zf, by_name[MANIFEST_PATH], MAX_JSON_BYTES).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise BackupError("manifest.json no es un JSON válido", 400)
        if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
            raise BackupError("No es una copia de seguridad de Pwnly", 400)
        version = manifest.get("format_version")
        if not isinstance(version, int) or version < 1:
            raise BackupError("Versión de formato no válida en el manifiesto", 400)
        if version > FORMAT_VERSION:
            raise BackupError(
                f"Esta copia usa el formato v{version}, más reciente que el que entiende esta versión de Pwnly (v{FORMAT_VERSION}). Actualiza Pwnly para importarla.",
                400,
            )
        files = manifest.get("files")
        if not isinstance(files, dict):
            raise BackupError("El manifiesto no declara sus ficheros", 400)

        # Integridad: cada fichero declarado debe existir y coincidir en tamaño y SHA-256.
        manifest_files: Dict[str, dict] = {}
        for p, meta in files.items():
            if not isinstance(p, str) or not isinstance(meta, dict):
                raise BackupError("Manifiesto con entradas no válidas", 400)
            if p not in by_name:
                raise BackupError(f"Falta el fichero «{p}» declarado en el manifiesto", 400)
            limit = MAX_ASSET_BYTES if p.startswith(ASSET_PREFIX) else MAX_JSON_BYTES
            blob = _read_bounded(zf, by_name[p], limit)
            if _sha256(blob) != meta.get("sha256"):
                raise BackupError(f"Fallo de integridad en «{p}»: la copia está corrupta o fue modificada", 400)
            manifest_files[p] = meta

        parsed = ParsedBackup()
        parsed.manifest = manifest
        for p in by_name:
            if p != MANIFEST_PATH and p not in manifest_files:
                parsed.warnings.append(f"Entrada ignorada (no figura en el manifiesto): {p[:80]}")

        reports_raw = _load_json(zf, by_name, manifest_files, DATA_FILES["reports"], [])
        themes_raw = _load_json(zf, by_name, manifest_files, DATA_FILES["themes"], [])
        templates_raw = _load_json(zf, by_name, manifest_files, DATA_FILES["finding_templates"], [])
        settings_raw = _load_json(zf, by_name, manifest_files, DATA_FILES["settings"], None)

        for name, raw, cap in (("reports", reports_raw, MAX_REPORTS), ("themes", themes_raw, MAX_THEMES),
                               ("finding_templates", templates_raw, MAX_TEMPLATES)):
            if not isinstance(raw, list):
                raise BackupError(f"data/{name}.json debe contener una lista", 400)
            if len(raw) > cap:
                raise BackupError(f"Demasiados elementos en data/{name}.json", 413)

        assets_cache: dict = {}
        for i, rd in enumerate(reports_raw):
            if not isinstance(rd, dict):
                raise BackupError(f"Reporte #{i + 1} no válido", 400)
            findings_raw = rd.get("findings") or []
            if not isinstance(findings_raw, list) or len(findings_raw) > MAX_FINDINGS_PER_REPORT:
                raise BackupError(f"Hallazgos del reporte #{i + 1} no válidos", 400)
            try:
                rd2 = dict(rd)
                rd2["client_logo"] = [
                    _internalize(v, zf, by_name, manifest_files, assets_cache, parsed.warnings)
                    for v in _as_list(rd.get("client_logo"))
                ]
                report = schemas.ReportCreate.model_validate(rd2)
                findings = []
                for j, fd in enumerate(findings_raw):
                    if not isinstance(fd, dict):
                        raise BackupError(f"Hallazgo #{j + 1} del reporte #{i + 1} no válido", 400)
                    fd2 = dict(fd)
                    fd2["images"] = [
                        _internalize(v, zf, by_name, manifest_files, assets_cache, parsed.warnings)
                        for v in _as_list(fd.get("images"))
                    ]
                    f = schemas.FindingCreate.model_validate(fd2)
                    findings.append((f, fd))
            except ValidationError as e:
                raise BackupError(f"Reporte #{i + 1} («{str(rd.get('document_title', ''))[:60]}») no válido: {_fmt_validation(e)}", 400)
            meta = {"created_at": _parse_iso(rd.get("created_at")), "updated_at": _parse_iso(rd.get("updated_at"))}
            parsed.reports.append((report, [(f, {"created_at": _parse_iso(fd.get("created_at")),
                                                  "updated_at": _parse_iso(fd.get("updated_at"))}) for f, fd in findings], meta))

        for i, td in enumerate(themes_raw):
            if not isinstance(td, dict):
                raise BackupError(f"Tema #{i + 1} no válido", 400)
            try:
                theme = schemas.ThemeCreate.model_validate(td)
            except ValidationError as e:
                raise BackupError(f"Tema #{i + 1} no válido: {_fmt_validation(e)}", 400)
            if theme.slug == "default":
                parsed.warnings.append("El tema «default» es el integrado y no se importa")
                continue
            parsed.themes.append((theme, {"created_at": _parse_iso(td.get("created_at")),
                                          "updated_at": _parse_iso(td.get("updated_at"))}))

        for i, td in enumerate(templates_raw):
            if not isinstance(td, dict):
                raise BackupError(f"Plantilla #{i + 1} no válida", 400)
            try:
                tpl = schemas.FindingTemplateCreate.model_validate(td)
            except ValidationError as e:
                raise BackupError(f"Plantilla #{i + 1} no válida: {_fmt_validation(e)}", 400)
            parsed.templates.append((tpl, {"created_at": _parse_iso(td.get("created_at")),
                                           "updated_at": _parse_iso(td.get("updated_at"))}))

        if settings_raw is not None:
            if not isinstance(settings_raw, dict):
                raise BackupError("data/settings.json no válido", 400)
            try:
                parsed.settings = schemas.AppSettingsBase.model_validate(settings_raw)
            except ValidationError as e:
                raise BackupError(f"Ajustes no válidos: {_fmt_validation(e)}", 400)

        return parsed


# =========================================================================== #
# IMPORTAR — aplicación (una sola transacción)
# =========================================================================== #
def apply_backup(db: Session, parsed: ParsedBackup, mode: str) -> dict:
    """Aplica la copia ya validada. mode: 'merge' (añadir) | 'replace' (reemplazar el contenido).
    Los usuarios y API keys NUNCA se tocan. Todo o nada: ante un error, rollback."""
    if mode not in ("merge", "replace"):
        raise BackupError("Modo de importación no válido", 400)

    skipped = {"themes": 0, "finding_templates": 0}
    try:
        if mode == "replace":
            db.query(models.Finding).delete(synchronize_session=False)
            db.query(models.Report).delete(synchronize_session=False)
            db.query(models.Theme).delete(synchronize_session=False)
            db.query(models.FindingTemplate).delete(synchronize_session=False)
            db.flush()

        for report, findings, meta in parsed.reports:
            row = models.Report(**report.model_dump())
            if meta["created_at"]:
                row.created_at = meta["created_at"]
            if meta["updated_at"]:
                row.updated_at = meta["updated_at"]
            db.add(row)
            db.flush()
            for idx, (f, fmeta) in enumerate(findings):
                frow = models.Finding(**f.model_dump(exclude={"order_index"}), report_id=row.id, order_index=f.order_index or idx)
                if fmeta["created_at"]:
                    frow.created_at = fmeta["created_at"]
                if fmeta["updated_at"]:
                    frow.updated_at = fmeta["updated_at"]
                db.add(frow)

        existing_themes = {s for (s,) in db.query(models.Theme.slug).all()}
        for theme, meta in parsed.themes:
            if theme.slug in existing_themes:
                skipped["themes"] += 1
                continue
            row = models.Theme(**theme.model_dump())
            if meta["created_at"]:
                row.created_at = meta["created_at"]
            db.add(row)
            existing_themes.add(theme.slug)

        existing_tpls = {s for (s,) in db.query(models.FindingTemplate.slug).all()}
        for tpl, meta in parsed.templates:
            if tpl.slug in existing_tpls:
                skipped["finding_templates"] += 1
                continue
            row = models.FindingTemplate(**tpl.model_dump())
            if meta["created_at"]:
                row.created_at = meta["created_at"]
            db.add(row)
            existing_tpls.add(tpl.slug)

        settings_applied = False
        if mode == "replace" and parsed.settings is not None:
            s = db.query(models.AppSettings).first()
            if s is None:
                s = models.AppSettings(id=1)
                db.add(s)
            data = parsed.settings.model_dump()
            s.lang = data["lang"]
            s.report_theme = data["report_theme"]
            s.pdf_print_theme = data["pdf_print_theme"]
            s.pdf_show_severity_bars = 1 if data["pdf_show_severity_bars"] else 0
            s.pdf_content_width = data["pdf_content_width"]
            settings_applied = True

        db.commit()
    except Exception:
        db.rollback()
        raise

    s = parsed.summary()
    return {
        "mode": mode,
        "imported": s["counts"],
        "skipped": skipped,
        "settings_applied": settings_applied,
        "warnings": s["warnings"],
    }


# =========================================================================== #
# Subida segura a disco temporal
# =========================================================================== #
def save_upload_to_temp(fileobj, max_bytes: int = MAX_UPLOAD_BYTES) -> str:
    """Copia el upload a un fichero temporal (0600) con tope de tamaño real."""
    fd, path = tempfile.mkstemp(suffix=".zip", prefix="pwnly-import-")
    size = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = fileobj.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise BackupError("El archivo supera el tamaño máximo permitido (256 MB)", 413)
                out.write(chunk)
    except Exception:
        try:
            os.remove(path)
        except OSError:
            pass
        raise
    return path
