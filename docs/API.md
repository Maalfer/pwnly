# Pwnly REST API

Gestiona reportes y hallazgos de Pwnly desde scripts, pipelines de CI o
cualquier cliente HTTP. La API es la misma que consume la interfaz web: todo
cambio se refleja inmediatamente en la aplicación y en los informes exportados.

## Autenticación

1. Abre **Cuenta → API / Integraciones** en Pwnly.
2. Pulsa **Generar nueva API Key** y copia el valor (`pwn_...`). Solo se muestra
   una vez.
3. Envía la clave en la cabecera `Authorization` de cada petición:

```http
Authorization: Bearer pwn_TU_CLAVE
```

Las API keys no caducan por defecto y se pueden revocar en cualquier momento
desde la misma página. Cada uso actualiza el campo `last_used_at`.

La API también acepta la cookie de sesión del navegador, pero para scripts e
integraciones usa siempre una API key.

## URL base

```
https://tu-dominio
```

En local: `http://localhost:8000`.

Todas las peticiones y respuestas usan `application/json`.

## Endpoints

### Reportes

| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/api/reports` | Lista todos los reportes con su número de hallazgos |
| `GET` | `/api/reports/{report_id}` | Obtiene un reporte completo, incluidos sus hallazgos |
| `POST` | `/api/reports` | Crea un reporte |
| `PUT` | `/api/reports/{report_id}` | Reemplaza los metadatos de un reporte |
| `DELETE` | `/api/reports/{report_id}` | Elimina el reporte y todos sus hallazgos |

### Hallazgos

| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/api/reports/{report_id}/findings` | Lista los hallazgos del reporte, ordenados |
| `GET` | `/api/findings/{finding_id}` | Obtiene un hallazgo |
| `POST` | `/api/reports/{report_id}/findings` | Crea un hallazgo |
| `POST` | `/api/reports/{report_id}/findings/bulk` | Crea varios hallazgos en una llamada |
| `PUT` | `/api/findings/{finding_id}` | Reemplaza el hallazgo completo |
| `PATCH` | `/api/findings/{finding_id}` | Actualiza solo los campos enviados |
| `DELETE` | `/api/findings/{finding_id}` | Elimina el hallazgo y reordena el resto |
| `POST` | `/api/reports/{report_id}/findings/reorder` | Reordena los hallazgos (lista de IDs) |

### Plantillas de hallazgo

| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/api/finding-templates` | Lista las plantillas guardadas |
| `POST` | `/api/finding-templates` | Crea o actualiza una plantilla por `slug` |
| `DELETE` | `/api/finding-templates/{template_id}` | Elimina una plantilla |

## Crear un reporte

```bash
curl -X POST "https://tu-dominio/api/reports" \
  -H "Authorization: Bearer pwn_TU_CLAVE" \
  -H "Content-Type: application/json" \
  -d '{
    "document_title": "Auditoría web — ACME",
    "client_company": "ACME S.A.",
    "target_asset": "https://app.acme.example",
    "auditor_company": "Mi Consultora",
    "auditor_name": "Mario",
    "auditor_email": "mario@example.com",
    "date": "2026-11-01",
    "lang": "es",
    "audit_type": "pentesting_web",
    "classification": 3,
    "tlp_level": "amber"
  }'
```

La respuesta incluye el `id` del reporte:

```json
{
  "id": 12,
  "document_title": "Auditoría web — ACME",
  "...": "..."
}
```

### Campos principales del reporte

| Campo | Tipo | Valores / notas |
| :--- | :--- | :--- |
| `document_title` | string | Título del documento |
| `client_company` | string | Empresa cliente |
| `target_asset` | string | Activo o sistema auditado |
| `auditor_company` | string | Empresa auditora |
| `auditor_name` | string | Auditor responsable |
| `auditor_email` | string | Email de contacto |
| `date` | string | `YYYY-MM-DD` |
| `version` | string | Versión del documento, p. ej. `1.0` |
| `lang` | string | `es` o `en` |
| `audit_type` | string | `pentesting_web`, `pentesting_infra`, `red_team`, `caja_negra`, `caja_blanca`, `caja_gris`, `phishing`, `wireless`, `social_engineering`, `otro` |
| `classification` | int | `1` Público, `2` Interno, `3` Confidencial, `4` Restringido |
| `tlp_level` | string | `clear`, `green`, `amber`, `amber+strict`, `red` |
| `classification_mode` | string | `internal`, `tlp`, `both` |
| `scope_in` / `scope_out` | string | Activos incluidos/excluidos, uno por línea |
| `audit_summary` | string | Resumen ejecutivo |
| `tests_performed` | string | Pruebas realizadas |
| `recommended_solutions` | string | Recomendaciones globales |
| `methodology_notes` | string | Notas de metodología |
| `methodology_standards` | string[] | `owasp_wstg`, `ptes`, `nist_800_115`, etc. |
| `tools_used` | string | Herramientas utilizadas |
| `engagement_start` / `engagement_end` | string | `YYYY-MM-DD` |
| `revision_history` | object[] | `{version, date, author, changes}` |
| `has_incidents` | bool | Si hubo incidentes |
| `incidents_text` | string | Descripción de los incidentes |

## Crear un hallazgo

```bash
curl -X POST "https://tu-dominio/api/reports/12/findings" \
  -H "Authorization: Bearer pwn_TU_CLAVE" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "SQL Injection en /api/users",
    "severity": "crit",
    "description": "El parámetro id se concatena directamente en la consulta SQL.",
    "poc": "GET /api/users?id=1%27%20OR%201=1--",
    "exploit": "sqlmap -u \"https://app.acme.example/api/users?id=1\" --batch",
    "impact": "Acceso no autorizado a toda la base de datos de usuarios.",
    "remediation": "Usar consultas parametrizadas y validar el tipo del parámetro.",
    "cvss": "9.8",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cve": "N/A",
    "cwe": "CWE-89",
    "owasp": "A03:2021 – Injection",
    "affected_assets": "https://app.acme.example/api/users",
    "status": "open",
    "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
    "compliance": ["PCI-DSS 6.5.1", "ISO 27001 A.14"]
  }'
```

### Campos principales del hallazgo

| Campo | Tipo | Valores / notas |
| :--- | :--- | :--- |
| `title` | string | **Obligatorio** |
| `severity` | string | `crit`, `high`, `med`, `low`, `info` |
| `description` | string | Descripción técnica |
| `poc` | string | Pasos de reproducción |
| `exploit` | string | Código o comando de explotación |
| `impact` | string | Impacto de negocio |
| `remediation` | string | Remediación recomendada |
| `cvss` | string | Puntuación, p. ej. `9.8` |
| `cvss_vector` | string | Vector CVSS 3.1 completo |
| `cve` | string | Identificador CVE o `N/A` |
| `cwe` | string | Identificador CWE |
| `owasp` | string | Categoría OWASP |
| `status` | string | `open`, `remediated`, `accepted_risk`, `false_positive` |
| `affected_assets` | string | Activos afectados, uno por línea |
| `likelihood` / `impact_rating` | string | `high`, `med`, `low` |
| `references` | string[] | URLs de referencia |
| `compliance` | string[] | Referencias normativas |
| `retest_notes` | string | Notas del re-test |
| `images` | string[] | Data URLs `data:image/...;base64,...` |
| `order_index` | int | Posición en el informe (opcional) |
| `fields_visibility` | object | Visibilidad de campos en el informe |

## Crear hallazgos en lote

Útil para importar los resultados de un escáner. Los hallazgos se añaden al
final del reporte en el mismo orden de la lista; no hace falta calcular
`order_index`.

```bash
curl -X POST "https://tu-dominio/api/reports/12/findings/bulk" \
  -H "Authorization: Bearer pwn_TU_CLAVE" \
  -H "Content-Type: application/json" \
  -d '[
    {"title": "XSS reflejado", "severity": "high", "cwe": "CWE-79"},
    {"title": "Cabeceras de seguridad ausentes", "severity": "low", "cwe": "CWE-693"},
    {"title": "Divulgación de versión", "severity": "info"}
  ]'
```

## Actualizar un hallazgo

`PUT` reemplaza el hallazgo completo (los campos omitidos vuelven a su valor por
defecto). Para cambios puntuales usa `PATCH`, que solo modifica lo enviado:

```bash
curl -X PATCH "https://tu-dominio/api/findings/34" \
  -H "Authorization: Bearer pwn_TU_CLAVE" \
  -H "Content-Type: application/json" \
  -d '{"status": "remediated", "retest_notes": "Corregido en el sprint 12"}'
```

## Reordenar hallazgos

```bash
curl -X POST "https://tu-dominio/api/reports/12/findings/reorder" \
  -H "Authorization: Bearer pwn_TU_CLAVE" \
  -H "Content-Type: application/json" \
  -d '[34, 32, 33]'
```

El cuerpo es la lista de IDs en el orden final. Los hallazgos del reporte que no
aparezcan en la lista conservan su posición original.

## Eliminar

```bash
# Hallazgo
curl -X DELETE "https://tu-dominio/api/findings/34" \
  -H "Authorization: Bearer pwn_TU_CLAVE"

# Reporte completo (incluye sus hallazgos)
curl -X DELETE "https://tu-dominio/api/reports/12" \
  -H "Authorization: Bearer pwn_TU_CLAVE"
```

## Códigos de estado

| Código | Significado |
| :--- | :--- |
| `200` | Operación correcta |
| `401` | API key ausente, inválida o revocada |
| `404` | Reporte o hallazgo inexistente |
| `422` | Datos inválidos (campo obligatorio, severidad no permitida, etc.) |
| `500` | Error interno |

Los errores devuelven `{"detail": "..."}`.

## Flujo típico de automatización

1. `POST /api/reports` para crear el engagement y guardar el `id`.
2. `POST /api/reports/{id}/findings/bulk` con todos los hallazgos del escáner.
3. `PATCH /api/findings/{id}` para actualizar estados durante el re-test.
4. `GET /api/reports/{id}` para descargar el reporte completo en JSON o abrir
   `/?report_id={id}` para revisarlo y exportarlo desde la interfaz.
