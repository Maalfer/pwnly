# Temas de informe

Un tema es una **plantilla HTML** (motor `{{...}}`) más una **hoja de estilos CSS**. Solo afecta al informe
(vista previa, PDF y HTML exportado); la interfaz de la aplicación es independiente. El CSS del tema queda
confinado al informe y nunca puede alterar la interfaz.

## Tema por defecto

Siempre existe, es de solo lectura y vive en la aplicación (no en la base de datos). Úsalo como referencia:
**Temas → Duplicar** crea una copia editable, y **Temas → Volver al tema por defecto** (o *Restablecer*, dentro
del editor) deshace cualquier cambio que haya salido mal.

Está pensado para generar un PDF **accesible**:

- PDF etiquetado (Chrome/Edge lo hacen al "Guardar como PDF"): `h1` en portada, `h2` por sección, `h3` por hallazgo,
  `h4` por apartado; `nav` para el índice, `section`/`article`/`aside`/`figure`; listas y tablas reales.
- Tablas con `<caption>`, `<th scope>` y datos tabulares (resumen de hallazgos, matriz de riesgo, control de versiones).
- Imágenes con texto alternativo descriptivo y pie de figura (`F-01.1 — …`).
- Contraste mínimo AA (4,5:1): insignias de severidad con texto blanco sobre colores oscuros; la severidad
  siempre va con su etiqueta de texto (nunca solo con color).
- Documento con idioma (`lang`) y título (el nombre del informe, que Chrome usa como nombre de archivo).
- Impresión: `@page` A4 con márgenes, numeración «n / total», cada hallazgo en página nueva, títulos pegados a su
  contenido, bloques que no se parten (figuras, avisos, cabeceras de tabla) y `print-color-adjust: exact` para que
  las insignias se vean aunque no se marque «Gráficos de fondo».

## Sintaxis de plantilla

`{{variable}}` (escapa HTML), `{{{html}}}` (sin escapar), `{{#each lista}}…{{/each}}`, `{{#if cond}}…{{else}}…{{/if}}`,
`{{#unless cond}}…{{/unless}}`, `{{@index}}`, `{{@index1}}`, `{{@first}}`, `{{@last}}`, `{{! comentario }}`.
Dentro de `#each`, `this` es el elemento actual.

## Variables

| Variable | Descripción |
| :--- | :--- |
| `document_title`, `client_company`, `target_asset`, `auditor_company`, `auditor_name`, `auditor_email`, `version`, `date` | Datos del informe |
| `date_formatted` | Fecha legible según el idioma («4 de noviembre de 2026») |
| `classification_label`, `audit_type_label` | Clasificación y tipo de auditoría |
| `client_logo` | Lista de logotipos (data URL) |
| `audit_summary_html`, `tests_performed_html`, `recommended_solutions_html`, `incidents_html` | Textos en HTML (usa `{{{…}}}`); las versiones sin `_html` son texto plano |
| `has_incidents`, `show_severity_bars` | Banderas |
| `severity_breakdown` | `[{key, label, count, percent}]` por severidad |
| `risk_matrix_has_data`, `risk_matrix_rows` | Matriz de riesgo: filas con `likelihood_label` y `cells[{count, level, level_label}]` |
| `scope.*` | `show`, `engagement_start/end`, `scope_in/out`, `standards[{label}]`, `methodology_notes_html`, `tools_used` y sus `show_*` |
| `revision_history` | `[{version, date, author, changes_html}]` |
| `findings` | Lista de hallazgos (ver abajo) |
| `labels.*` | Textos del informe en el idioma activo (`labels.toc`, `labels.summary`, `labels.findings`, …): úsalos para que tu tema siga el idioma |

### Cada hallazgo (`findings`)

`index`, `index1`, `code` (`F-01`), `title`, `severity` (`crit|high|med|low|info`), `severity_label`, `cvss`, `cvss_vector`,
`cve`, `cwe`, `status_label`, `affected_assets`, `description_html`, `impact_html`, `poc_html`, `exploit`, `remediation_html`,
`references[]`, `compliance[]`, `owasp`, `likelihood_label`, `impact_rating_label`, `retest_notes_html`, los `*_visible`
(`owasp_visible`, `risk_visible`, `compliance_visible`, `retest_visible`) y **`evidence`**:
`[{src, alt, label, caption, n}]` (imágenes con texto alternativo y pie ya calculados).

## CSS

Es CSS normal. Cosas útiles para PDF:

```css
@page { size: A4; margin: 18mm 16mm 20mm; @bottom-center { content: counter(page) " / " counter(pages); } }
@page :first { @bottom-center { content: none; } }          /* sin numerar la portada */
@media print {
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }   /* conserva los fondos */
  .finding + .finding { break-before: page; }                          /* un hallazgo por página */
  h2, h3, h4 { break-after: avoid; }
}
```

El CSS admite hasta 200 000 caracteres. Se eliminan `@import`, `expression()`, `javascript:`, `url()` externas y
etiquetas HTML; el resto (incluido el combinador `>` y los escapes válidos) se conserva.
