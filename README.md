<p align="center">
  <img src="https://raw.githubusercontent.com/Maalfer/pwnly/main/assets/images/pwnly.png?v=2" alt="Pwnly Banner" width="100%">
</p>

<p align="center">
  <img src="assets/logo.png?v=2" alt="Pwnly Logo" width="110" height="110">
</p>

<h1 align="center">Pwnly</h1>

<p align="center">
  <strong>Generador interactivo de reportes de pentesting.</strong><br>
  Registra vulnerabilidades, visualiza estadísticas de riesgo en tiempo real y exporta informes corporativos como HTML autocontenido o PDF (impresión nativa del navegador).
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.4.0-blue.svg" alt="Version 2.4.0">
  <img src="https://img.shields.io/badge/Maintained%3F-yes-green.svg" alt="Maintained">
  <img src="https://img.shields.io/badge/PRs-welcome-blue.svg" alt="PRs Welcome">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License MIT">
</p>

<p align="center">
  <strong>Versión actual: 2.4.0</strong>
</p>

## Estructura del Proyecto

```
pwnly/
├── index.html              # Frontend SPA
├── run.py                  # Script para iniciar el servidor
├── requirements.txt        # Dependencias Python
├── Dockerfile              # Imagen Docker
├── css/
│   └── styles.css          # Estilos CSS vanilla
├── js/
│   └── app.js              # Aplicación Vanilla JavaScript
├── assets/                 # Imágenes y recursos estáticos
├── demo/                   # Capturas de pantalla
├── docs/                   # Landing page y documentación de la API
└── backend/                # API FastAPI
    ├── main.py             # Endpoints y lógica principal
    ├── models.py           # Modelos SQLAlchemy
    ├── schemas.py          # Esquemas Pydantic
    ├── database.py         # Configuración SQLite
    ├── migrations.py       # Migraciones de base de datos
    └── tests/              # Tests pytest
        ├── conftest.py
        ├── test_api_info.py
        ├── test_reports.py
        ├── test_findings.py
        ├── test_findings_reorder.py
        ├── test_findings_delete_reorder.py
        ├── test_pdf_export.py
        ├── test_database_io.py
        └── test_static_files.py
```

## 🐳 Instalación y Uso (Docker - Recomendado)

Docker es la forma **más rápida y sencilla** de ejecutar Pwnly. Desde la v2.0.0 la imagen es ligera: ya no incluye navegadores, porque la exportación a HTML/PDF se hace en el navegador del usuario.

### Comando rápido (copiar y pegar)

```bash
# 1. Construir imagen
docker build -t pwnly:latest .

# 2. Ejecutar contenedor
docker run -d \
  -p 8000:8000 \
  -v pwnly_data:/app/data \
  --name pwnly \
  pwnly:latest
```

El servidor estará disponible en: `http://localhost:8000`

---

## 🖥️ Instalación Manual (Sin Docker)

Si prefieres no usar Docker, puedes instalar manualmente:

### 1. Instalar dependencias del backend

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 run.py
```

El servidor estará disponible en: `http://localhost:8000`

---

## Base de Datos

Los datos se almacenan en `pwnly.db` (SQLite) con dos tablas:

- **reports** - Datos generales del reporte (cliente, fecha, etc.)
- **findings** - Vulnerabilidades asociadas a cada reporte

## API REST

Los reportes y hallazgos se pueden gestionar por completo desde la API REST, sin
depender de la interfaz web ni de integraciones externas. Es el mismo mecanismo
que usa el frontend, por lo que cualquier cambio queda reflejado al instante.

1. Entra en **Cuenta → API / Integraciones** y genera una API key (`pwn_...`).
2. Envía la clave en cada petición:

```bash
curl -H "Authorization: Bearer pwn_TU_CLAVE" \
     https://tu-dominio/api/reports
```

Endpoints principales:

| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/api/reports` | Listar reportes |
| `POST` | `/api/reports` | Crear reporte |
| `GET` | `/api/reports/{id}/findings` | Listar hallazgos del reporte |
| `GET` | `/api/findings/{id}` | Obtener un hallazgo |
| `POST` | `/api/reports/{id}/findings` | Crear hallazgo |
| `POST` | `/api/reports/{id}/findings/bulk` | Crear hallazgos en lote |
| `PATCH` | `/api/findings/{id}` | Actualizar campos concretos de un hallazgo |
| `PUT` | `/api/findings/{id}` | Reemplazar un hallazgo completo |
| `DELETE` | `/api/findings/{id}` | Eliminar un hallazgo |

La referencia completa, con ejemplos de cURL y todos los campos disponibles,
está en [`docs/API.md`](docs/API.md).

## Funcionalidades de Persistencia

### Guardado automático
- Los datos del reporte se guardan automáticamente 2 segundos después de cada cambio
- Los hallazgos se guardan inmediatamente al agregarlos

### Mis Reportes
- Desde el navbar puedes acceder a "Mis Reportes"
- Lista todos los reportes guardados con su fecha y número de hallazgos
- Clic para cargar un reporte existente
- Botón para eliminar reportes permanentemente

### Nuevo Reporte
- Desde "Mis Reportes" puedes crear reportes nuevos
- Cada reporte es independiente con sus propios hallazgos

## Testing

Pwnly incluye una suite completa de tests para garantizar que todas las funcionalidades funcionen correctamente.

### Ejecutar todos los tests

```bash
# Desde la raíz del proyecto
python -m pytest backend/tests/ -v

# O desde el directorio backend
cd backend
python -m pytest tests/ -v
```

### Tests específicos

```bash
# Solo tests de reportes
python -m pytest backend/tests/test_reports.py -v

# Solo tests de hallazgos
python -m pytest backend/tests/test_findings.py -v

# Tests con cobertura
python -m pytest backend/tests/ -v --cov=backend --cov-report=html
```

### Antes de hacer git push

**Recomendación:** Ejecutar siempre los tests antes de subir cambios:

```bash
python -m pytest backend/tests/ -v
```

La suite de tests incluye:
- **API Info**: Verificación de endpoints básicos
- **Reportes**: CRUD completo de reportes
- **Hallazgos**: CRUD y reordenamiento de hallazgos
- **Reordenamiento**: Tests específicos para orden de hallazgos
- **Ajustes**: Preferencias globales persistidas en la BD
- **Base de Datos**: Import/export de backups SQLite
- **Archivos Estáticos**: CSS, JS y assets

## 🛠️ Tecnologías

<p align="center">
  <img src="https://img.shields.io/badge/JavaScript-ES6+-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/CSS-Vanilla-1572B6?style=for-the-badge&logo=css3&logoColor=white" alt="CSS">
  <img src="https://img.shields.io/badge/FastAPI-Async-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/SQLite-ORM-07405E?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
</p>

| | |
| :--- | :--- |
| ⚡ **Frontend ultraligero** | Vanilla JavaScript (ES6+) + CSS puro, sin frameworks. Navegación SPA instantánea y tipografía *Inter* optimizada para largas sesiones de auditoría. |
| 🚀 **Backend asíncrono** | FastAPI sobre Uvicorn/Gunicorn. Peticiones concurrentes y guardado automático de reportes imperceptible para el auditor. |
| 🗄️ **Persistencia robusta** | SQLite + SQLAlchemy (ORM) + Pydantic. Cada vulnerabilidad y reporte queda validado contra un esquema estricto. |
| 📦 **Despliegue instantáneo** | Imagen Docker aislada y portable: Windows, Linux o macOS con un único comando, datos persistidos en volúmenes. |

## ⭐ Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Maalfer/pwnly&type=Date&theme=dark" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Maalfer/pwnly&type=Date" />
  <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Maalfer/pwnly&type=Date" width="100%">
</picture>
