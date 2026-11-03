# Copias de seguridad

Pwnly guarda todo en **una única base de datos interna** (SQLite). Esa base de datos
no se exporta ni se importa como fichero: para mover o respaldar tu información se usa una
**copia de seguridad portable**, un `.zip` con JSON y las imágenes como ficheros independientes.

Desde la interfaz: **Mis Reportes → Exportar copia / Importar copia**.

## Formato (`format_version: 1`)

```
pwnly-backup-YYYYMMDD-HHMMSS.zip
├── manifest.json              formato, versión, fecha, recuentos y SHA-256 de cada fichero
├── data/
│   ├── reports.json           reportes con sus hallazgos anidados
│   ├── themes.json            temas de informe del usuario (HTML + CSS)
│   ├── finding_templates.json plantillas de hallazgo del usuario
│   └── settings.json          preferencias de la aplicación
└── assets/
    └── <sha256>.<png|jpg|gif|webp|svg|bmp>   imágenes (logos y evidencias)
```

- Las imágenes **no** van dentro del JSON: los reportes las referencian como
  `"assets/<sha256>.<ext>"`. Se direccionan por contenido, así que la misma imagen usada
  varias veces se guarda **una sola vez**.
- `manifest.json` incluye el SHA-256 y el tamaño de cada fichero; al importar se verifica
  la integridad de todo el archivo.
- Las fechas son ISO-8601 en UTC. Los campos desconocidos se ignoran, de modo que una copia
  sigue importándose si la app añade campos nuevos. Una copia con un `format_version` más
  nuevo que el soportado se rechaza con un mensaje claro.

## Qué NO incluye

Usuarios, hashes de contraseña, API keys y sesiones. Las credenciales pertenecen a la
instancia, no al contenido, y no deben viajar en un archivo portable. La importación **nunca**
modifica tus cuentas. El tema por defecto (`default`) está integrado en la app y tampoco se exporta.

## Cifrado opcional

Al exportar puedes definir una contraseña (mínimo 8 caracteres). El cifrado se hace **en el
navegador**: PBKDF2-SHA256 (310 000 iteraciones) → AES-256-GCM. El archivo resultante
(`.zip.enc`, cabecera `PWNLYBK1`) se descifra en el navegador al importarlo; el servidor solo
ve el ZIP ya descifrado. Si pierdes la contraseña, no hay forma de recuperar la copia.

## Importar

1. Se sube el archivo y se **valida por completo sin escribir nada** (vista previa con fecha,
   versión de Pwnly, recuentos, reportes incluidos y avisos).
2. Eliges el modo:
   - **Añadir a lo existente** (recomendado): los reportes se añaden como copias nuevas;
     temas y plantillas con el mismo identificador se omiten. No se borra nada.
   - **Reemplazar todo el contenido**: elimina reportes, temas y plantillas actuales y restaura
     los de la copia, incluidos los ajustes. Pide confirmación explícita.
3. La importación es **todo o nada**: se aplica en una única transacción y, si algo falla,
   no cambia nada.

### Seguridad

El archivo importado se trata como no confiable: límites de tamaño y de número de entradas
(contra zip-bombs), nombres de entrada estrictos (sin rutas absolutas ni `..`), lectura acotada
de cada entrada, imágenes verificadas por su firma binaria (no por la extensión), y todo el
contenido pasa por los mismos esquemas y saneadores que la API normal (temas HTML/CSS, severidades,
imágenes). Una entidad inválida aborta la importación completa.

| Límite | Valor |
| :--- | :--- |
| ZIP subido | 256 MB |
| Descomprimido (total) | 768 MB |
| Entradas | 20 000 |
| JSON | 64 MB |
| Imagen | 25 MB |

## API

| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/api/backup/export` | Descarga el ZIP de copia de seguridad |
| `POST` | `/api/backup/import` | Importa un ZIP (`multipart/form-data`) |

Campos de `POST /api/backup/import`: `file` (el ZIP), `mode` (`merge` por defecto, o `replace`) y
`dry_run` (`true` solo valida y devuelve el resumen, sin escribir).

```bash
# Exportar
curl -OJ -H "Authorization: Bearer pwn_TU_CLAVE" https://tu-dominio/api/backup/export

# Validar sin importar
curl -F file=@pwnly-backup.zip -F dry_run=true -H "Authorization: Bearer pwn_TU_CLAVE" \
  https://tu-dominio/api/backup/import

# Importar añadiendo
curl -F file=@pwnly-backup.zip -F mode=merge -H "Authorization: Bearer pwn_TU_CLAVE" \
  https://tu-dominio/api/backup/import
```

Errores: `400` archivo inválido/corrupto/formato no soportado, `413` supera los límites,
`422` parámetros no válidos.
