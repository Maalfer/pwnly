// Versión de la aplicación. Se muestra de forma persistente en la interfaz
// (login y navbar) y debe coincidir con la del backend (FastAPI) y el badge del README.
const APP_VERSION = '1.0.0';

const state = {
    lang: 'es',
    showSplash: false,
    activeTab: 'editor',
    isLoading: false,
    currentReportId: null,
    reportTheme: 'default',
    savedReports: [],
    showReportSelector: false,
    showThemesPage: false,
    auditData: {
        documentTitle: 'Reporte Técnico de Vulnerabilidades',
        clientCompany: 'Empresa Cliente S.A.',
        clientLogo: ['', ''],
        targetAsset: 'Aplicación Principal',
        auditorCompany: 'Empresa Auditora LLC',
        auditorName: 'Juan Pérez',
        classification: '2',
        tlpLevel: 'amber',
        classificationMode: 'internal',
        version: '1.0',
        date: new Date().toISOString().split('T')[0],
        lang: 'es',
        auditType: 'pentesting_web',
        hasIncidents: false,
        incidentsText: '',
        auditSummary: '',
        testsPerformed: '',
        recommendedSolutions: '',
        // Alcance y metodología (informe profesional)
        scopeIn: '',
        scopeOut: '',
        methodologyNotes: '',
        methodologyStandards: [],
        toolsUsed: '',
        engagementStart: '',
        engagementEnd: '',
        revisionHistory: [],
        scopeFieldsVisibility: {}
    },
    findings: [],
    editingFindingIndex: null,
    currentFinding: {
        templateKey: 'custom',
        title: '',
        severity: 'med',
        description: '',
        cvss: '',
        cvssVector: '',
        poc: '',
        exploit: '',
        impact: '',
        remediation: '',
        reference: '',
        references: [],
        cve: '',
        cwe: '',
        status: 'open',
        affectedAssets: '',
        likelihood: '',
        impactRating: '',
        owasp: '',
        compliance: [],
        retestNotes: '',
        images: [],
        imageCaptions: []
    },
    // Temas personalizados y gestor de temas
    customThemes: [],
    userFindingTemplates: [],
    showThemeManager: false,
    themeEditor: null,
    isThemeStudio: false,
    themeManagerError: '',
    themeManagerSuccess: '',
    // Calculadora CVSS
    showCvssCalc: false,
    cvssMetrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' },
    isDirty: false,
    showSettings: false,
    generatingPdf: false,
    exportingHtml: false,
    exportMenuOpen: false,
    previewSourceView: false,
    showDemoModal: false,
    showPdfModal: false,
    showRevisionModal: false,
    pdfPrintTheme: 'default',
    pdfShowSeverityBars: true,
    pdfContentWidth: 820,
    // Autenticación
    authChecked: false,
    isAuthenticated: false,
    authUsername: '',
    loginUsername: '',
    loginPassword: '',
    loginError: '',
    loginLoading: false,
    // Configuración inicial (primer arranque, sin usuarios registrados)
    needsSetup: false,
    setupUsername: '',
    setupPassword: '',
    setupError: '',
    setupLoading: false,
    showProfile: false,
    profileError: '',
    profileSuccess: '',
    // Credenciales por defecto (admin/admin): pista en el login y aviso al entrar
    showDefaultCredsHint: false,   // true mientras admin conserve la contraseña 'admin'
    usingDefaultPassword: false,   // true si el usuario logueado usa la pass por defecto
    passwordWarningDismissed: false, // el usuario cerró el modal de aviso en esta sesión
    // Página de cuenta / gestión de usuarios
    isAccountView: false,
    users: [],
    userMgmtError: '',
    userMgmtSuccess: '',
    // API / Integraciones
    apiKeys: [],
    apiNewKey: null,
    apiKeyLabel: '',
    apiError: ''
};

const UI = {
    es: {
        appTitle: 'Pwnly',
        appSubtitle: 'Security Report Generator',
        welcome: 'Bienvenido a',
        tagline: 'Generador de Reportes de Pentesting',
        description: 'Crea reportes profesionales de vulnerabilidades con plantillas predefinidas y exportación PDF.',
        enterApp: 'Entrar a la Aplicación',
        newFinding: 'Registrar Nuevo Hallazgo',
        newFindingDesc: 'Completa los detalles de la vulnerabilidad descubierta.',
        quickTemplate: 'Plantilla Rápida (Auto-completar)',
        customOther: 'Personalizado / Otro',
        findingStatuses: { open: 'Abierto', remediated: 'Remediado', accepted_risk: 'Riesgo aceptado', false_positive: 'Falso positivo' },
        riskLevels: { '': '— Sin especificar —', high: 'Alta', med: 'Media', low: 'Baja' },
        vulnTitle: 'Título de la Vulnerabilidad',
        severity: 'Nivel de Severidad',
        description: 'Descripción de la Vulnerabilidad',
        cvss: 'Puntuación CVSS (0-10)',
        poc: 'Pasos para Reproducir (PoC)',
        exploit: 'Exploit (opcional)',
        impact: 'Impacto en el Negocio',
        remediation: 'Solución y Remediación',
        reference: 'Referencias (URLs)',
        cve: 'Identificador CVE',
        cwe: 'Identificador CWE (MITRE)',
        images: 'Evidencias (Imágenes)',
        addImages: 'Agregar Imágenes',
        addFinding: 'Agregar Hallazgo',
        updateFinding: 'Actualizar Hallazgo',
        cancel: 'Cancelar',
        preview: 'Vista Previa',
        generatePdf: 'Generar PDF',
        export: 'Exportar',
        exportHtml: 'Exportar HTML',
        exportingHtml: 'Exportando…',
        generatingPdf: 'Generando...',
        saveReport: 'Guardar Reporte',
        myReports: 'Mis Reportes',
        backToEditor: 'Volver al Editor',
        createNewReport: 'Crear Nuevo Reporte',
        generateDemoDb: 'Reporte de ejemplo',
        demoModalTitle: 'Generar reporte de ejemplo',
        demoModalDesc: 'Esto creará un reporte de pentesting completo de demostración con hallazgos reales, imágenes de evidencias y datos de ejemplo para que puedas explorar todas las funcionalidades de Pwnly.',
        demoModalWarning: 'El reporte de demo se añadirá a tus reportes existentes. No se eliminarán datos actuales.',
        demoModalWhat: 'Qué incluye el reporte demo:',
        demoModalItems: ['Empresa objetivo: AcmeShop Platform', '6 hallazgos: 2 Críticos, 3 Altos, 1 Bajo', 'Imágenes de evidencias reales (SQLMap, GTFOBins, BurpSuite, etc.)', 'CVSS scores, CWE IDs y referencias OWASP', 'Resumen ejecutivo y conclusiones completas'],
        demoModalGenerate: 'Generar Demo',
        demoModalGenerating: 'Creando demo...',
        demoModalCancel: 'Cancelar',
        pdfModalTitle: 'Configurar PDF',
        pdfModalTheme: 'Tema del documento',
        pdfModalThemeLight: 'Claro',
        pdfModalThemeDark: 'Oscuro',
        pdfModalThemeHtb: 'HTB',
        pdfModalThemeRedteam: 'Red Team',
        pdfModalSeverityBars: 'Barras de color de severidad',
        pdfModalSeverityBarsDesc: 'Incluir indicadores de color de severidad en cada hallazgo y en el resumen',
        pdfModalContentWidth: 'Ancho del contenido',
        pdfModalContentWidthDesc: 'Controla qué tan ancho o estrecho aparece el contenido de los hallazgos en el PDF',
        pdfModalContentWidthNarrow: 'Estrecho',
        pdfModalContentWidthWide: 'Ancho',
        pdfModalCancel: 'Cancelar',
        pdfModalGenerate: 'Generar PDF',
        noReports: 'No hay reportes guardados',
        noReportsDesc: 'Crea tu primer reporte usando el botón de arriba',
        editor: 'Edición',
        severityLevels: {
            crit: 'Crítico',
            high: 'Alto',
            med: 'Medio',
            low: 'Bajo',
            info: 'Informativo'
        },
        targetAsset: 'Activo a Auditar',
        clientCompany: 'Empresa Cliente',
        clientLogo1: 'Logotipo 1 (opcional)',
        clientLogo2: 'Logotipo 2 (opcional)',
        auditorCompany: 'Empresa Auditora',
        auditorName: 'Nombre del Auditor',
        documentTitle: 'Título del Documento',
        date: 'Fecha del Reporte',
        classification: 'Clasificación Interna',
        version: 'Versión',
        classifications: {
            '1': 'Público',
            '2': 'Interno',
            '3': 'Confidencial',
            '4': 'Restringido'
        },
        auditType: 'Tipo de Auditoría',
        auditTypes: {
            'pentesting_web': 'Pentesting Web',
            'caja_negra': 'Caja Negra (Black Box)',
            'caja_gris': 'Caja Gris (Grey Box)',
            'caja_blanca': 'Caja Blanca (White Box)',
            'intrusion_interna': 'Intrusión Interna',
            'phishing': 'Campaña de Phishing',
            'analisis_automatico': 'Análisis Automático de Vulnerabilidades'
        },
        incidents: 'Incidencias durante la Auditoría',
        incidentsYes: 'Sí, hubo incidencias',
        incidentsNo: 'No hubo incidencias',
        incidentsDesc: 'Descripción de las incidencias',
        incidentsNoneText: 'No se registraron incidencias durante el proceso de auditoría.',
        incidentsSectionTitle: 'Incidencias',
        auditSummary: 'Resumen de la Auditoría',
        auditSummaryDesc: 'Resumen ejecutivo de los hallazgos, alcance y conclusiones de la auditoría.',
        testsPerformed: 'Pruebas Realizadas',
        testsPerformedDesc: 'Descripción detallada de las pruebas y técnicas utilizadas durante la auditoría.',
        recommendedSolutions: 'Soluciones Recomendadas',
        recommendedSolutionsDesc: 'Plan de remediación con prioridades y recomendaciones generales.',
        // Preview/PDF translations
        index: 'Índice',
        executiveSummary: 'Resumen Ejecutivo',
        executiveSummaryWithCVSS: 'Resumen Ejecutivo (CVSS)',
        technicalFindings: 'Hallazgos Técnicos',
        incidentsRecorded: 'Se registraron incidencias durante la auditoría',
        cvssScore: 'CVSS Score',
        cveId: 'CVE',
        cweId: 'CWE',
        referenceUrl: 'URL de Referencia',
        pocSteps: 'Pasos para Reproducir (PoC)',
        exploitCode: 'Exploit',
        evidence: 'Evidencias',
        businessImpact: 'Impacto en el Negocio',
        solutionRemediation: 'Solución y Remediación',
        na: 'N/A',
        auditConclusions: 'Conclusiones y Resumen de la Auditoría',
        logoClient: 'Logo Cliente',
        logoClientAlt: 'Logo Cliente',
        cvssSummaryTitle: 'Resumen de Vulnerabilidades (CVSS)',
        noFindings: 'No hay hallazgos registrados',
        loginTitle: 'Iniciar sesión',
        loginSubtitle: 'Accede a tu generador de reportes',
        loginUser: 'Usuario',
        loginPass: 'Contraseña',
        loginBtn: 'Entrar',
        loginLoading: 'Entrando...',
        setupTitle: 'Configuración inicial',
        setupSubtitle: 'Crea la primera cuenta de administrador para empezar',
        setupBtn: 'Crear cuenta',
        setupLoading: 'Creando...',
        setupError: 'No se pudo crear la cuenta',
        sharedDataNote: 'Todos los usuarios comparten los mismos reportes, hallazgos y ajustes.',
        profile: 'Perfil',
        logout: 'Cerrar sesión',
        changePassword: 'Cambiar contraseña',
        currentPassword: 'Contraseña actual',
        newPassword: 'Nueva contraseña',
        confirmPassword: 'Confirmar nueva contraseña',
        savePassword: 'Guardar contraseña',
        passwordMismatch: 'Las contraseñas no coinciden',
        passwordChanged: 'Contraseña actualizada correctamente',
        defaultCredsHint: 'Acceso por defecto:',
        defaultCredsUserLabel: 'usuario',
        defaultCredsPassLabel: 'contraseña',
        pwWarnTitle: 'Cambia tu contraseña',
        pwWarnBody: 'Estás usando las credenciales por defecto (admin / admin). Por seguridad, te recomendamos cambiar la contraseña ahora mismo.',
        pwWarnCta: 'Cambiar contraseña',
        pwWarnDismiss: 'Ahora no',
        accountTitle: 'Cuenta y usuarios',
        accountSubtitle: 'Gestiona tu cuenta y los usuarios del sistema',
        backToApp: 'Volver a la aplicación',
        signedInAs: 'Sesión iniciada como',
        manageUsers: 'Gestión de usuarios',
        existingUsers: 'Usuarios existentes',
        createUser: 'Crear nuevo usuario',
        createUserBtn: 'Crear usuario',
        userCreated: 'Usuario creado correctamente',
        userDeleted: 'Usuario eliminado correctamente',
        deleteLabel: 'Eliminar',
        youLabel: 'tú',
        noUsers: 'No hay usuarios registrados',
        confirmDeleteUser: '¿Eliminar al usuario',
        apiTitle: 'API / Integraciones',
        apiSubtitle: 'Gestiona reportes y hallazgos desde scripts, CI o cualquier cliente HTTP',
        apiKeysTitle: 'API Keys',
        apiKeysDesc: 'Claves de larga duración para autenticar peticiones a la API REST de Pwnly',
        apiNoKeys: 'No hay API keys generadas',
        apiGenerateKey: 'Generar nueva API Key',
        apiKeyLabelField: 'Etiqueta',
        apiKeyLabelPlaceholder: 'p.ej. "Script de importación"',
        apiGenerate: 'Generar',
        apiGenerating: 'Generando...',
        apiRevoke: 'Revocar',
        apiRevokeConfirm: '¿Revocar esta API key? Los scripts e integraciones que la usen dejarán de funcionar.',
        apiNewKeyWarning: 'Copia esta clave ahora. No se volverá a mostrar.',
        apiCopy: 'Copiar',
        apiCopied: '¡Copiado!',
        apiCreatedAt: 'Creada',
        apiLastUsed: 'Último uso',
        apiNeverUsed: 'Sin usar',
        apiError: 'Error al gestionar las API keys',
        apiUsageTitle: 'Cómo usar la API',
        apiUsageDesc: 'La API REST usa JSON y está disponible en este mismo dominio. Los hallazgos siempre pertenecen a un reporte.',
        apiAuthTitle: 'Autenticación',
        apiAuthDesc: 'Envía tu API key en la cabecera Authorization de cada petición:',
        apiBaseUrlLabel: 'URL base',
        apiAuthHeaderLabel: 'Cabecera',
        apiEndpointsTitle: 'Endpoints de hallazgos',
        apiEndpointsDesc: 'Referencia rápida para automatizar la gestión de hallazgos.',
        apiMethod: 'Método',
        apiEndpoint: 'Endpoint',
        apiDescription: 'Descripción',
        apiListReports: 'Listar reportes',
        apiCreateReport: 'Crear reporte',
        apiListFindings: 'Listar hallazgos de un reporte',
        apiGetFinding: 'Obtener un hallazgo',
        apiCreateFinding: 'Crear hallazgo',
        apiBulkFindings: 'Crear hallazgos en lote',
        apiPatchFinding: 'Actualizar hallazgo (parcial)',
        apiDeleteFinding: 'Eliminar hallazgo',
        apiExampleTitle: 'Ejemplo rápido',
        apiExampleDesc: 'Crea un reporte y añade un hallazgo con cURL:',
        apiDocsHint: 'Documentación completa en docs/API.md del repositorio.'
    },
    en: {
        appTitle: 'Pwnly',
        appSubtitle: 'Security Report Generator',
        welcome: 'Welcome to',
        tagline: 'Pentesting Report Generator',
        description: 'Create professional vulnerability reports with predefined templates and PDF export.',
        enterApp: 'Enter Application',
        newFinding: 'Register New Finding',
        newFindingDesc: 'Complete the details of the discovered vulnerability.',
        quickTemplate: 'Quick Template (Auto-fill)',
        customOther: 'Custom / Other',
        findingStatuses: { open: 'Open', remediated: 'Remediated', accepted_risk: 'Accepted risk', false_positive: 'False positive' },
        riskLevels: { '': '— Not specified —', high: 'High', med: 'Medium', low: 'Low' },
        vulnTitle: 'Vulnerability Title',
        severity: 'Severity Level',
        description: 'Vulnerability Description',
        cvss: 'CVSS Score (0-10)',
        poc: 'Steps to Reproduce (PoC)',
        exploit: 'Exploit (optional)',
        impact: 'Business Impact',
        remediation: 'Solution and Remediation',
        reference: 'References (URLs)',
        cve: 'CVE Identifier',
        cwe: 'CWE Identifier (MITRE)',
        images: 'Evidence (Images)',
        addImages: 'Add Images',
        addFinding: 'Add Finding',
        updateFinding: 'Update Finding',
        cancel: 'Cancel',
        preview: 'Preview',
        generatePdf: 'Generate PDF',
        export: 'Export',
        exportHtml: 'Export HTML',
        exportingHtml: 'Exporting…',
        generatingPdf: 'Generating...',
        saveReport: 'Save Report',
        myReports: 'My Reports',
        backToEditor: 'Back to Editor',
        createNewReport: 'Create New Report',
        generateDemoDb: 'Sample report',
        demoModalTitle: 'Generate sample report',
        demoModalDesc: 'This will create a complete demo pentesting report with real findings, evidence images and sample data so you can explore all Pwnly features.',
        demoModalWarning: 'The demo report will be added to your existing reports. No current data will be deleted.',
        demoModalWhat: 'What the demo report includes:',
        demoModalItems: ['Target company: AcmeShop Platform', '6 findings: 2 Critical, 3 High, 1 Low', 'Real evidence images (SQLMap, GTFOBins, BurpSuite, etc.)', 'CVSS scores, CWE IDs and OWASP references', 'Executive summary and full conclusions'],
        demoModalGenerate: 'Generate Demo',
        demoModalGenerating: 'Creating demo...',
        demoModalCancel: 'Cancel',
        pdfModalTitle: 'PDF Settings',
        pdfModalTheme: 'Document theme',
        pdfModalThemeLight: 'Light',
        pdfModalThemeDark: 'Dark',
        pdfModalThemeHtb: 'HTB',
        pdfModalThemeRedteam: 'Red Team',
        pdfModalSeverityBars: 'Severity color bars',
        pdfModalSeverityBarsDesc: 'Include severity color indicators on each finding and in the summary',
        pdfModalContentWidth: 'Content width',
        pdfModalContentWidthDesc: 'Controls how wide or narrow the findings content appears in the PDF',
        pdfModalContentWidthNarrow: 'Narrow',
        pdfModalContentWidthWide: 'Wide',
        pdfModalCancel: 'Cancel',
        pdfModalGenerate: 'Generate PDF',
        noReports: 'No saved reports',
        noReportsDesc: 'Create your first report using the button above',
        editor: 'Editor',
        severityLevels: {
            crit: 'Critical',
            high: 'High',
            med: 'Medium',
            low: 'Low',
            info: 'Informational'
        },
        targetAsset: 'Target Asset',
        clientCompany: 'Client Company',
        clientLogo1: 'Client Logo 1 (optional)',
        clientLogo2: 'Client Logo 2 (optional)',
        auditorCompany: 'Auditor Company',
        auditorName: 'Auditor Name',
        documentTitle: 'Document Title',
        date: 'Report Date',
        classification: 'Internal Classification',
        version: 'Version',
        classifications: {
            '1': 'Public',
            '2': 'Internal',
            '3': 'Confidential',
            '4': 'Restricted'
        },
        auditType: 'Audit Type',
        auditTypes: {
            'pentesting_web': 'Web Pentesting',
            'caja_negra': 'Black Box',
            'caja_gris': 'Grey Box',
            'caja_blanca': 'White Box',
            'intrusion_interna': 'Internal Intrusion',
            'phishing': 'Phishing Campaign',
            'analisis_automatico': 'Automatic Vulnerability Analysis'
        },
        incidents: 'Incidents during the Audit',
        incidentsYes: 'Yes, there were incidents',
        incidentsNo: 'No incidents',
        incidentsDesc: 'Incident description',
        incidentsNoneText: 'No incidents were recorded during the audit process.',
        incidentsSectionTitle: 'Incidents',
        auditSummary: 'Audit Summary',
        auditSummaryDesc: 'Executive summary of findings, scope and conclusions of the audit.',
        testsPerformed: 'Tests Performed',
        testsPerformedDesc: 'Detailed description of tests and techniques used during the audit.',
        recommendedSolutions: 'Recommended Solutions',
        recommendedSolutionsDesc: 'Remediation plan with priorities and general recommendations.',
        // Preview/PDF translations
        index: 'Index',
        executiveSummary: 'Executive Summary',
        executiveSummaryWithCVSS: 'Executive Summary (CVSS)',
        technicalFindings: 'Technical Findings',
        incidentsRecorded: 'Incidents were recorded during the audit',
        cvssScore: 'CVSS Score',
        cveId: 'CVE',
        cweId: 'CWE',
        referenceUrl: 'Reference URL',
        pocSteps: 'Steps to Reproduce (PoC)',
        exploitCode: 'Exploit',
        evidence: 'Evidence',
        businessImpact: 'Business Impact',
        solutionRemediation: 'Solution and Remediation',
        na: 'N/A',
        auditConclusions: 'Audit Conclusions and Summary',
        logoClient: 'Client Logo',
        logoClientAlt: 'Client Logo',
        cvssSummaryTitle: 'Vulnerabilities Summary (CVSS)',
        noFindings: 'No findings registered',
        loginTitle: 'Sign in',
        loginSubtitle: 'Access your report generator',
        loginUser: 'Username',
        loginPass: 'Password',
        loginBtn: 'Sign in',
        loginLoading: 'Signing in...',
        setupTitle: 'Initial setup',
        setupSubtitle: 'Create the first administrator account to get started',
        setupBtn: 'Create account',
        setupLoading: 'Creating...',
        setupError: 'Could not create the account',
        sharedDataNote: 'All users share the same reports, findings and settings.',
        profile: 'Profile',
        logout: 'Log out',
        changePassword: 'Change password',
        currentPassword: 'Current password',
        newPassword: 'New password',
        confirmPassword: 'Confirm new password',
        savePassword: 'Save password',
        passwordMismatch: 'Passwords do not match',
        passwordChanged: 'Password updated successfully',
        defaultCredsHint: 'Default access:',
        defaultCredsUserLabel: 'username',
        defaultCredsPassLabel: 'password',
        pwWarnTitle: 'Change your password',
        pwWarnBody: 'You are using the default credentials (admin / admin). For your security, we recommend changing the password right now.',
        pwWarnCta: 'Change password',
        pwWarnDismiss: 'Not now',
        accountTitle: 'Account & users',
        accountSubtitle: 'Manage your account and system users',
        backToApp: 'Back to the app',
        signedInAs: 'Signed in as',
        manageUsers: 'User management',
        existingUsers: 'Existing users',
        createUser: 'Create new user',
        createUserBtn: 'Create user',
        userCreated: 'User created successfully',
        userDeleted: 'User deleted successfully',
        deleteLabel: 'Delete',
        youLabel: 'you',
        noUsers: 'No users registered',
        confirmDeleteUser: 'Delete user',
        apiTitle: 'API / Integrations',
        apiSubtitle: 'Manage reports and findings from scripts, CI or any HTTP client',
        apiKeysTitle: 'API Keys',
        apiKeysDesc: 'Long-lived keys to authenticate requests to the Pwnly REST API',
        apiNoKeys: 'No API keys generated yet',
        apiGenerateKey: 'Generate new API Key',
        apiKeyLabelField: 'Label',
        apiKeyLabelPlaceholder: 'e.g. "Import script"',
        apiGenerate: 'Generate',
        apiGenerating: 'Generating...',
        apiRevoke: 'Revoke',
        apiRevokeConfirm: 'Revoke this API key? Scripts and integrations using it will stop working.',
        apiNewKeyWarning: 'Copy this key now. It will not be shown again.',
        apiCopy: 'Copy',
        apiCopied: 'Copied!',
        apiCreatedAt: 'Created',
        apiLastUsed: 'Last used',
        apiNeverUsed: 'Never used',
        apiError: 'Error managing API keys',
        apiUsageTitle: 'How to use the API',
        apiUsageDesc: 'The REST API uses JSON and is available on this same domain. Findings always belong to a report.',
        apiAuthTitle: 'Authentication',
        apiAuthDesc: 'Send your API key in the Authorization header of every request:',
        apiBaseUrlLabel: 'Base URL',
        apiAuthHeaderLabel: 'Header',
        apiEndpointsTitle: 'Finding endpoints',
        apiEndpointsDesc: 'Quick reference for automating finding management.',
        apiMethod: 'Method',
        apiEndpoint: 'Endpoint',
        apiDescription: 'Description',
        apiListReports: 'List reports',
        apiCreateReport: 'Create report',
        apiListFindings: 'List findings of a report',
        apiGetFinding: 'Get a finding',
        apiCreateFinding: 'Create finding',
        apiBulkFindings: 'Create findings in bulk',
        apiPatchFinding: 'Update finding (partial)',
        apiDeleteFinding: 'Delete finding',
        apiExampleTitle: 'Quick example',
        apiExampleDesc: 'Create a report and add a finding with cURL:',
        apiDocsHint: 'Full documentation in docs/API.md in the repository.'
    }
};

let templates = {};

async function loadTemplates() {
    try {
        const response = await fetch('js/plantillas.json');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        templates = await response.json();
    } catch (error) {
        console.error('Error loading templates:', error);
        // Fallback: templates remain empty, app will still work but without auto-fill
    }
}

document.addEventListener('DOMContentLoaded', loadTemplates);

const $ = (selector) => document.querySelector(selector);

const escapeHTML = (str) => {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
};

const formatMultiline = (str) => escapeHTML(str).replace(/\n/g, '<br>');

// La severidad se interpola directamente en atributos `class` y `style`
// (severity-<x>, var(--severity-<x>)), donde escapeHTML no protege (las comillas
// escapadas no impiden romper el token del atributo). Se restringe a la lista
// blanca conocida; cualquier otro valor cae a 'info'. Neutraliza el XSS aunque
// un valor malicioso llegara a almacenarse.
const SEVERITY_KEYS = ['crit', 'high', 'med', 'low', 'info'];
const safeSeverity = (s) => (SEVERITY_KEYS.includes(s) ? s : 'info');

function markdownToHtml(str) {
    if (!str) return '';
    let s = String(str);

    // 1. Proteger bloques de código (``` ... ```) antes de cualquier escape
    const codeBlocks = [];
    s = s.replace(/```(\w*)\r?\n?([\s\S]*?)```/g, (_, _lang, code) => {
        const safe = code.replace(/\r?\n$/, '')
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        codeBlocks.push(safe);
        return `\x01CB${codeBlocks.length - 1}\x01`;
    });

    // 2. Proteger código inline (`...`)
    const inlineCodes = [];
    s = s.replace(/`([^`\n]+)`/g, (_, code) => {
        const safe = code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        inlineCodes.push(safe);
        return `\x01IC${inlineCodes.length - 1}\x01`;
    });

    // 3. Escapar HTML en el texto restante. Se escapan también las comillas
    // (dobles y simples): la URL de los links [texto](url) del paso 5 se
    // interpola dentro de un atributo href="…", así que un `"` sin escapar
    // permitiría cerrar el atributo e inyectar event handlers (XSS almacenado).
    s = s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
         .replace(/"/g,'&quot;').replace(/'/g,'&#39;');

    // 4. Negrita+cursiva, negrita, cursiva
    s = s.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/\*([^\s*][^*\n]*?[^\s*])\*/g, '<em>$1</em>');
    s = s.replace(/\*([^\s*\n])\*/g, '<em>$1</em>');

    // 5. Links [texto](url)
    s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
        '<a href="$2" target="_blank" style="color:inherit;text-decoration:underline;opacity:0.85;">$1</a>');

    // 6. Restaurar código inline
    s = s.replace(/\x01IC(\d+)\x01/g, (_, i) =>
        `<code style="font-family:ui-monospace,SFMono-Regular,monospace;background:rgba(128,128,128,0.15);padding:0.1em 0.4em;border-radius:3px;font-size:0.875em;word-break:break-word;">${inlineCodes[+i]}</code>`);

    // 7. Procesar línea a línea para estructura de bloque
    const lines = s.split('\n');
    const out = [];
    let inUl = false, inOl = false;
    let tableBuf = [];

    // Conserva la sangría inicial (espacios/tabs) convirtiéndola en espacios
    // duros, para que el código pegado en el PoC no se descuadre en el informe.
    const preserveIndent = (ln) => ln.replace(/^[ \t]+/, m =>
        m.replace(/\t/g, '\u00a0\u00a0\u00a0\u00a0').replace(/ /g, '\u00a0'));

    const closeUl = () => { if (inUl) { out.push('</ul>'); inUl = false; } };
    const closeOl = () => { if (inOl) { out.push('</ol>'); inOl = false; } };
    const closeAll = () => { closeUl(); closeOl(); };

    const flushTable = () => {
        if (!tableBuf.length) return;
        const rows = tableBuf;
        tableBuf = [];
        // Necesita al menos cabecera + separador + 1 fila de datos, y separador válido
        if (rows.length >= 2 && /^\|[\s|:=-]+\|$/.test(rows[1].trim())) {
            const parseRow = r => r.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim());
            const tdS = 'border:1px solid rgba(128,128,128,0.3);padding:0.38em 0.7em;text-align:left;vertical-align:top;line-height:1.5;';
            const thS = tdS + 'font-weight:700;background:rgba(128,128,128,0.1);';
            const head = `<thead><tr>${parseRow(rows[0]).map(c => `<th style="${thS}">${c}</th>`).join('')}</tr></thead>`;
            const body = rows.slice(2).map(r => `<tr>${parseRow(r).map(c => `<td style="${tdS}">${c}</td>`).join('')}</tr>`).join('');
            out.push(`<table style="border-collapse:collapse;width:100%;margin:0.5em 0;font-size:0.88em;">${head}${body ? `<tbody>${body}</tbody>` : ''}</table>`);
        } else {
            rows.forEach(r => { closeAll(); out.push(r + '<br>'); });
        }
    };

    for (const line of lines) {
        // Acumular líneas de tabla (empiezan con |)
        if (/^\s*\|/.test(line)) {
            tableBuf.push(line);
            continue;
        }
        flushTable();

        // Bloque de código
        const cbm = line.match(/^\x01CB(\d+)\x01$/);
        if (cbm) {
            closeAll();
            out.push(`<pre style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:rgba(128,128,128,0.12);border-radius:6px;padding:0.7em 1em;font-size:0.82em;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;margin:0.35em 0;line-height:1.55;"><code>${codeBlocks[+cbm[1]]}</code></pre>`);
            continue;
        }
        // Encabezados # ## ### ####
        const hm = line.match(/^(#{1,4}) (.+)$/);
        if (hm) {
            closeAll();
            const sizes = ['1.1em','1.0em','0.93em','0.88em'];
            out.push(`<div style="font-size:${sizes[hm[1].length-1]||'0.88em'};font-weight:${hm[1].length<=2?'800':'700'};margin:0.55em 0 0.15em;line-height:1.3;">${hm[2]}</div>`);
            continue;
        }
        // Lista no ordenada  -  *  +
        const ulm = line.match(/^[ \t]*[-*+] (.+)$/);
        if (ulm) {
            if (inOl) closeOl();
            if (!inUl) { out.push('<ul style="margin:0.15em 0;padding-left:1.4em;list-style:disc;">'); inUl = true; }
            out.push(`<li style="margin:0.1em 0;">${ulm[1]}</li>`);
            continue;
        }
        // Lista ordenada  1.  2)
        const olm = line.match(/^[ \t]*\d+[.)]\s+(.+)$/);
        if (olm) {
            if (inUl) closeUl();
            if (!inOl) { out.push('<ol style="margin:0.15em 0;padding-left:1.4em;">'); inOl = true; }
            out.push(`<li style="margin:0.1em 0;">${olm[1]}</li>`);
            continue;
        }
        // Línea vacía → separador
        if (line.trim() === '') {
            closeAll();
            out.push('<br>');
            continue;
        }
        // Texto normal
        closeAll();
        out.push(preserveIndent(line) + '<br>');
    }
    flushTable();
    closeAll();

    return out.join('').replace(/(<br>\s*)+$/, '');
}

const severityWeights = { crit: 5, high: 4, med: 3, low: 2, info: 1 };

// Normaliza un hallazgo recibido de la API (snake_case) a las claves camelCase
// que usa el estado local y el render. Conserva las claves originales.
function normalizeFinding(f) {
    if (!f) return f;
    const map = {
        cvss_vector: 'cvssVector',
        affected_assets: 'affectedAssets',
        impact_rating: 'impactRating',
        retest_notes: 'retestNotes',
        template_key: 'templateKey',
        fields_visibility: 'fieldsVisibility',
        image_captions: 'imageCaptions'
    };
    Object.entries(map).forEach(([snake, camel]) => {
        if (f[camel] === undefined && f[snake] !== undefined) f[camel] = f[snake];
    });
    if (!Array.isArray(f.references)) f.references = f.references ? [].concat(f.references) : [];
    if (!Array.isArray(f.compliance)) f.compliance = f.compliance ? [].concat(f.compliance) : [];
    if (typeof f.fieldsVisibility !== 'object' || !f.fieldsVisibility) f.fieldsVisibility = {};
    if (!Array.isArray(f.imageCaptions)) f.imageCaptions = Array.isArray(f.image_captions) ? [...f.image_captions] : [];
    if (!Array.isArray(f.images)) f.images = [];
    while (f.imageCaptions.length < f.images.length) f.imageCaptions.push('');
    if (!f.status) f.status = 'open';
    return f;
}

function normalizeFindings(list) {
    return (list || []).map(normalizeFinding);
}

function sortFindingsBySeverity(findings) {
    return findings.sort((a, b) => {
        const weightDiff = severityWeights[b.severity] - severityWeights[a.severity];
        if (weightDiff !== 0) return weightDiff;
        const cvssA = parseFloat(a.cvss) || 0;
        const cvssB = parseFloat(b.cvss) || 0;
        return cvssB - cvssA;
    });
}

const readFileAsDataURL = (file) => new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.readAsDataURL(file);
});

const calculateSeverityFromCvss = (cvss) => {
    const score = parseFloat(cvss);
    if (isNaN(score)) return null;
    if (score >= 9.0) return 'crit';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'med';
    if (score > 0.0) return 'low';
    return 'info';
};

const API = {
    baseUrl: '',

    async request(method, endpoint, data = null) {
        const url = `${this.baseUrl}${endpoint}`;
        const options = {
            method,
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin'  // envía la cookie de sesión (mismo origen)
        };
        if (data) options.body = JSON.stringify(data);

        const response = await fetch(url, options);
        if (response.status === 401) {
            handleUnauthorized();
            throw new Error('HTTP 401');
        }
        if (!response.ok) {
            // Intentamos extraer el mensaje de error del backend (FastAPI: { detail }).
            let detail = `HTTP ${response.status}`;
            try {
                const body = await response.json();
                if (body && typeof body.detail === 'string') detail = body.detail;
            } catch (e) { /* respuesta sin cuerpo JSON */ }
            const error = new Error(detail);
            error.status = response.status;
            throw error;
        }
        return response.json();
    },

    auth: {
        login: (data) => API.request('POST', '/api/auth/login', data),
        logout: () => API.request('POST', '/api/auth/logout'),
        me: () => API.request('GET', '/api/auth/me'),
        changePassword: (data) => API.request('POST', '/api/auth/change-password', data),
        needsSetup: () => API.request('GET', '/api/auth/needs-setup'),
        setup: (data) => API.request('POST', '/api/auth/setup', data),
        defaultCredentials: () => API.request('GET', '/api/auth/default-credentials')
    },

    users: {
        list: () => API.request('GET', '/api/users'),
        create: (data) => API.request('POST', '/api/users', data),
        delete: (id) => API.request('DELETE', `/api/users/${id}`)
    },

    apiKeys: {
        list: () => API.request('GET', '/api/api-keys'),
        create: (data) => API.request('POST', '/api/api-keys', data),
        delete: (id) => API.request('DELETE', `/api/api-keys/${id}`)
    },

    reports: {
        getAll: () => API.request('GET', '/api/reports'),
        getById: (id) => API.request('GET', `/api/reports/${id}`),
        create: (data) => API.request('POST', '/api/reports', data),
        update: (id, data) => API.request('PUT', `/api/reports/${id}`, data),
        delete: (id) => API.request('DELETE', `/api/reports/${id}`)
    },

    findings: {
        getAll: (reportId) => API.request('GET', `/api/reports/${reportId}/findings`),
        getById: (findingId) => API.request('GET', `/api/findings/${findingId}`),
        create: (reportId, data) => API.request('POST', `/api/reports/${reportId}/findings`, data),
        bulkCreate: (reportId, data) => API.request('POST', `/api/reports/${reportId}/findings/bulk`, data),
        update: (findingId, data) => API.request('PUT', `/api/findings/${findingId}`, data),
        patch: (findingId, data) => API.request('PATCH', `/api/findings/${findingId}`, data),
        delete: (findingId) => API.request('DELETE', `/api/findings/${findingId}`)
    },

    themes: {
        list: () => API.request('GET', '/api/themes'),
        create: (data) => API.request('POST', '/api/themes', data),
        delete: (id) => API.request('DELETE', `/api/themes/${id}`)
    },

    findingTemplates: {
        list: () => API.request('GET', '/api/finding-templates'),
        create: (data) => API.request('POST', '/api/finding-templates', data),
        delete: (id) => API.request('DELETE', `/api/finding-templates/${id}`)
    },

    settings: {
        get: () => API.request('GET', '/api/settings'),
        update: (data) => API.request('PUT', '/api/settings', data)
    }
};

// Preferencias globales (idioma, tema activo, opciones de PDF) persistidas en la
// BD para que la exportación capture el 100% del estado. El guardado va con
// debounce para no machacar la API en cada pulsación de un control.
let _settingsSaveTimer = null;
function persistSettings() {
    clearTimeout(_settingsSaveTimer);
    _settingsSaveTimer = setTimeout(() => {
        API.settings.update({
            lang: state.lang,
            report_theme: state.reportTheme,
            pdf_print_theme: state.pdfPrintTheme,
            pdf_show_severity_bars: !!state.pdfShowSeverityBars,
            pdf_content_width: state.pdfContentWidth
        }).catch(() => { /* sin sesión / offline: se reintentará al próximo cambio */ });
    }, 400);
}

async function loadSettings() {
    try {
        const s = await API.settings.get();
        if (!s) return;
        if (s.lang) { state.lang = s.lang; state.auditData.lang = s.lang; }
        if (s.pdf_print_theme) state.pdfPrintTheme = s.pdf_print_theme;
        if (typeof s.pdf_show_severity_bars !== 'undefined') state.pdfShowSeverityBars = !!s.pdf_show_severity_bars;
        if (s.pdf_content_width) state.pdfContentWidth = s.pdf_content_width;
        if (s.report_theme && listAllThemes().some(t => t.slug === s.report_theme)) {
            state.reportTheme = s.report_theme;
        }
    } catch (e) { /* fallback: se mantienen los valores por defecto / localStorage */ }
}

function renderSplashScreen() {
    if (!state.showSplash) return '';

    const t = UI[state.lang];

    return `
        <div class="splash-screen">
            <div class="splash-content">
                <div class="splash-logo">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <path d="M12 8v4"/><path d="M12 16h.01"/>
                    </svg>
                </div>
                <h1 class="splash-title">${t.appTitle}</h1>
                <p class="splash-tagline">${t.tagline}</p>
                <p class="splash-desc">${t.description}</p>
                
                <div class="splash-actions">
                    <button class="btn-enter" onclick="enterApp()">${t.enterApp}</button>
                    <div class="lang-toggle">
                        <button class="${state.lang === 'es' ? 'active' : ''}" onclick="setLang('es')">ES</button>
                        <button class="${state.lang === 'en' ? 'active' : ''}" onclick="setLang('en')">EN</button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function renderNavbar() {
    if (state.showSplash) return '';

    const t = UI[state.lang];

    return `
        <header class="navbar">
            <div class="navbar-brand">
                <span onclick="showReports()" title="${t.myReports}" style="display:inline-flex;align-items:center;gap:0.65rem;cursor:pointer;">
                    <img src="/assets/logo-transparent.png" alt="Pwnly" style="height: 38px; width: 38px; object-fit: contain; flex-shrink: 0;">
                    <span class="app-name">Pwnly</span>
                </span>
                <span class="app-version-badge">v${APP_VERSION}</span>
                ${state.isDirty ? '<span class="dirty-indicator">•</span>' : ''}
            </div>
            
            <div class="navbar-actions">
                <button class="${state.showReportSelector ? 'active' : ''}" onclick="showReports()">${t.myReports}</button>
                <button class="${state.activeTab === 'editor' && !state.showReportSelector ? 'active' : ''}" onclick="hideReports(); setTab('editor')">${t.editor}</button>
                <button class="${state.activeTab === 'preview' && !state.showReportSelector ? 'active' : ''}" onclick="hideReports(); setTab('preview')">${t.preview}</button>
                <button class="${state.showThemesPage ? 'active' : ''}" onclick="showThemesPage()">${state.lang === 'es' ? 'Temas' : 'Themes'}</button>
                <div class="export-dropdown" style="position:relative;display:inline-block;">
                    <button class="btn-primary pdf-btn${(state.generatingPdf || state.exportingHtml) ? ' pdf-btn--loading' : ''}" onclick="toggleExportMenu(event)" ${(state.generatingPdf || state.exportingHtml) ? 'disabled' : ''}>
                        ${(state.generatingPdf || state.exportingHtml)
                            ? `<svg class="spin" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> ${state.generatingPdf ? t.generatingPdf : t.exportingHtml}`
                            : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> ${t.export}
                               <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="margin-left:1px;"><polyline points="6 9 12 15 18 9"/></svg>`
                        }
                    </button>
                    ${state.exportMenuOpen ? `
                        <div class="export-menu">
                            <button onclick="chooseExport('pdf')">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                                <span>${t.generatePdf}</span>
                            </button>
                            <button onclick="chooseExport('html')">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                                <span>${t.exportHtml}</span>
                            </button>
                        </div>
                    ` : ''}
                </div>
                <button class="settings-btn" onclick="openSettings()" title="${state.lang === 'es' ? 'Ajustes' : 'Settings'}">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                </button>
                <button class="settings-btn" onclick="openProfile()" title="${UI[state.lang].profile}">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </button>
            </div>
        </header>
    `;
}


// =========================================================================== //
// EDITOR: navegación, accesibilidad y eficiencia
// =========================================================================== //
const _isMobileEditor = () => window.matchMedia && window.matchMedia('(max-width: 760px)').matches;
state.editorOpen = state.editorOpen || {};

// Estado abierto/cerrado de las secciones colapsables. En móvil las tarjetas de
// metadatos arrancan cerradas (menos scroll); el usuario las abre y se recuerda.
function editorSectionOpen(key, def) {
    if (key in state.editorOpen) return state.editorOpen[key];
    if (def !== undefined) return def;
    return !_isMobileEditor();
}
function editorToggled(key, open) { state.editorOpen[key] = !!open; }

function findingGroup(key, inner) {
    const isEs = state.lang === 'es';
    const labels = {
        evidence: isEs ? 'Reproducción y evidencia' : 'Reproduction & evidence',
        impact:   isEs ? 'Impacto y remediación'    : 'Impact & remediation',
        refs:     isEs ? 'Referencias e identificadores' : 'References & identifiers'
    };
    const def = key !== 'refs';
    return `<details class="fgroup" id="ed-fg-${key}" ${editorSectionOpen('fg-' + key, def) ? 'open' : ''} ontoggle="editorToggled('fg-${key}', this.open)">
        <summary>${labels[key]}</summary>
        <div class="details-body">${inner}</div>
    </details>`;
}

function renderEditorBar() {
    const isEs = state.lang === 'es';
    const n = state.findings.length;
    const chips = [
        ['ed-general',   isEs ? 'Información' : 'General'],
        ['ed-summary',   isEs ? 'Resumen' : 'Summary'],
        ['ed-scope',     isEs ? 'Alcance' : 'Scope'],
        ['ed-revisions', isEs ? 'Revisiones' : 'Revisions'],
        ['ed-findings',  (isEs ? 'Hallazgos' : 'Findings') + ` (${n})`],
    ];
    const saveLabel = (UI[state.lang] || {}).saveReport || (isEs ? 'Guardar' : 'Save');
    const saveIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>';
    const plus = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>';
    return `
        <div class="editor-bar" role="toolbar" aria-label="${isEs ? 'Herramientas del editor' : 'Editor tools'}">
            <nav class="editor-bar-nav" aria-label="${isEs ? 'Secciones del editor' : 'Editor sections'}">
                ${chips.map(([id, label]) => `<a class="editor-chip" href="#${id}" data-target="${id}" onclick="editorGoto(event,'${id}')">${label}</a>`).join('')}
                <a class="editor-chip editor-chip--accent" href="#ed-form" data-target="ed-form" onclick="editorNewFinding(event)">${plus}<span>${isEs ? 'Nuevo hallazgo' : 'New finding'}</span></a>
            </nav>
            <div class="editor-bar-actions">
                <span class="editor-status ${state.isDirty ? 'is-dirty' : ''}" role="status" aria-live="polite">${state.isDirty ? (isEs ? 'Cambios sin guardar' : 'Unsaved changes') : (isEs ? 'Guardado' : 'Saved')}</span>
                <button type="button" class="btn-primary editor-save" onclick="saveCurrentReport()" aria-keyshortcuts="Control+S Meta+S" title="${isEs ? 'Guardar reporte (Ctrl+S)' : 'Save report (Ctrl+S)'}">${saveIcon}<span>${saveLabel}</span></button>
            </div>
        </div>
        <div class="editor-fab-bar" role="toolbar" aria-label="${isEs ? 'Acciones rápidas' : 'Quick actions'}">
            <button type="button" class="btn-secondary" onclick="editorNewFinding(event)">${plus}<span>${isEs ? 'Hallazgo' : 'Finding'}</span></button>
            <button type="button" class="btn-primary editor-save" onclick="saveCurrentReport()">${saveIcon}<span>${saveLabel}</span></button>
        </div>`;
}

function editorGoto(e, id) {
    if (e) e.preventDefault();
    const el = document.getElementById(id);
    if (!el) return;
    if (el.tagName === 'DETAILS' && !el.open) { el.open = true; }
    const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    const target = el.querySelector('summary, h2, h3, input, textarea, select, button');
    if (target) setTimeout(() => { try { target.focus({ preventScroll: true }); } catch (_) {} }, reduce ? 0 : 350);
}

function focusFindingForm() {
    const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const form = document.getElementById('ed-form');
    if (form) form.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    const title = document.getElementById('findingTitle');
    if (title) setTimeout(() => { try { title.focus({ preventScroll: true }); } catch (_) {} }, reduce ? 0 : 300);
}

function editorNewFinding(e) {
    if (e) e.preventDefault();
    if (state.editingFindingIndex !== null) { resetFindingForm(); }
    focusFindingForm();
}

function switchKey(e) {
    if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); e.currentTarget.click(); }
}

// Plantillas: combobox con teclado (↓ abre y entra en la lista, Enter aplica, Esc cierra).
function templateSearchKey(e) {
    const select = document.getElementById('templateSelect');
    if (!select) return;
    if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (select.style.display === 'none') showTemplateDropdownKeep();
        const opt = Array.from(select.options).find(o => o.style.display !== 'none' && !o.hidden);
        if (opt) { select._kb = true; select.value = opt.value; }
        select.focus();
    } else if (e.key === 'Escape') {
        hideTemplateDropdown();
        e.currentTarget.setAttribute('aria-expanded', 'false');
    }
}
function showTemplateDropdownKeep() {
    const select = document.getElementById('templateSelect');
    const input = document.getElementById('templateSearch');
    if (select) select.style.display = 'block';
    if (input) input.setAttribute('aria-expanded', 'true');
}
function templateListKey(e) {
    const select = e.currentTarget;
    if (['ArrowDown', 'ArrowUp', 'PageUp', 'PageDown', 'Home', 'End'].includes(e.key)) {
        select._kb = true;
    } else if (e.key === 'Enter') {
        e.preventDefault();
        select._kb = false;
        if (select.value) { applyTemplate(select.value); hideTemplateDropdown(); }
    } else if (e.key === 'Escape') {
        hideTemplateDropdown();
        const input = document.getElementById('templateSearch');
        if (input) input.focus();
    }
}

// Indicador "Sin guardar / Guardado" siempre sincronizado con state.isDirty.
function refreshEditorStatus() {
    const isEs = state.lang === 'es';
    document.querySelectorAll('.editor-status').forEach(el => {
        el.classList.toggle('is-dirty', !!state.isDirty);
        el.textContent = state.isDirty ? (isEs ? 'Cambios sin guardar' : 'Unsaved changes') : (isEs ? 'Guardado' : 'Saved');
    });
}
(function () {
    let v = !!state.isDirty;
    Object.defineProperty(state, 'isDirty', {
        get() { return v; },
        set(x) { const nv = !!x; if (nv !== v) { v = nv; refreshEditorStatus(); } },
        enumerable: true, configurable: true
    });
})();

let _edUid = 0;
let _edSpyRaf = 0;
function postRenderEditor() {
    const nav = document.querySelector('.navbar');
    if (nav) document.documentElement.style.setProperty('--nav-h', nav.offsetHeight + 'px');
    const page = document.querySelector('.editor-page');
    if (!page) return;
    // 1) Etiquetas asociadas a su control (lectores de pantalla + clic en la etiqueta).
    page.querySelectorAll('.form-group').forEach(g => {
        const ctl = g.querySelector('input:not([type=hidden]):not([type=file]):not([type=radio]):not([type=checkbox]), select, textarea');
        if (!ctl) return;
        if (!ctl.id) ctl.id = 'ed-f-' + (++_edUid);
        const lab = g.querySelector('label');
        if (lab && !lab.hasAttribute('for') && !lab.querySelector('input,select,textarea')) lab.setAttribute('for', ctl.id);
        const small = g.querySelector('small.text-muted, small');
        if (small && !small.id) small.id = ctl.id + '-hint';
        if (small && !ctl.hasAttribute('aria-describedby') && small.textContent.trim() && !ctl.closest('.template-search-container')) ctl.setAttribute('aria-describedby', small.id);
    });
    // 2) Controles sin etiqueta visible: usar placeholder / título.
    page.querySelectorAll('input, textarea, select').forEach(c => {
        if (c.type === 'hidden') return;
        const labelled = c.getAttribute('aria-label') || c.getAttribute('aria-labelledby') || (c.id && page.querySelector('label[for="' + c.id + '"]')) || c.closest('label');
        if (!labelled) {
            const txt = c.getAttribute('placeholder') || c.getAttribute('title');
            if (txt) c.setAttribute('aria-label', txt);
        }
    });
    page.querySelectorAll('input[type=file]').forEach(c => {
        if (!c.getAttribute('aria-label')) c.setAttribute('aria-label', (c.closest('.form-group')?.querySelector('label')?.textContent || 'Archivo').trim());
    });
    // 3) Tarjetas como regiones con nombre.
    page.querySelectorAll('.editor-meta-card').forEach(card => {
        const h = card.querySelector('h3');
        if (!h) return;
        if (!h.id) h.id = card.id + '-title';
        card.setAttribute('role', 'region');
        card.setAttribute('aria-labelledby', h.id);
    });
    const fc = page.querySelector('.findings-card');
    const fh = fc && fc.querySelector('.findings-section-title');
    if (fc && fh) { fh.id = fh.id || 'ed-findings-title'; fc.setAttribute('role', 'region'); fc.setAttribute('aria-labelledby', fh.id); }
    const form = document.getElementById('findingForm');
    if (form && !form.getAttribute('aria-label')) form.setAttribute('aria-label', state.lang === 'es' ? 'Formulario de hallazgo' : 'Finding form');
    refreshEditorStatus();
    editorScrollSpy();
}

// Resalta en la barra la sección visible (aria-current).
function editorScrollSpy() {
    if (_edSpyRaf) return;
    _edSpyRaf = requestAnimationFrame(() => {
        _edSpyRaf = 0;
        const chips = document.querySelectorAll('.editor-chip[data-target]:not(.editor-chip--accent)');
        if (!chips.length) return;
        const bar = document.querySelector('.editor-bar');
        const offset = (bar ? bar.getBoundingClientRect().bottom : 120) + 24;
        let current = null;
        chips.forEach(ch => {
            const el = document.getElementById(ch.dataset.target);
            if (el && el.getBoundingClientRect().top <= offset) current = ch;
        });
        if (!current) current = chips[0];
        chips.forEach(ch => {
            const on = ch === current;
            if (on) { ch.setAttribute('aria-current', 'true'); } else { ch.removeAttribute('aria-current'); }
        });
        // En móvil la barra se desliza: mantener visible el chip activo.
        if (current && current.scrollIntoView && _isMobileEditor()) {
            const nav = current.parentElement;
            if (nav) nav.scrollTo({ left: current.offsetLeft - 12, behavior: 'auto' });
        }
    });
}
window.addEventListener('scroll', editorScrollSpy, { passive: true });
window.addEventListener('resize', () => { postRenderEditor(); });

// Atajos: Ctrl/Cmd+S guarda; Ctrl/Cmd+Enter registra el hallazgo desde el formulario.
document.addEventListener('keydown', (e) => {
    if (state.activeTab !== 'editor' || !state.isAuthenticated || !document.querySelector('.editor-page')) return;
    const mod = e.ctrlKey || e.metaKey;
    if (mod && (e.key === 's' || e.key === 'S')) { e.preventDefault(); saveCurrentReport(); return; }
    if (mod && e.key === 'Enter') {
        const form = document.getElementById('findingForm');
        if (form && form.contains(document.activeElement)) { e.preventDefault(); form.requestSubmit(); }
    }
});

function renderEditor() {
    if (state.activeTab !== 'editor' || state.showSplash || state.showReportSelector || state.showThemesPage) return '';
    if (state.showReportSelector) return '';

    const t = UI[state.lang];

    return `
        <div class="editor-page">
        ${renderEditorBar()}
        <div class="editor-meta-grid">
            ${renderGeneralInfoCard()}
            ${renderExecutiveSummaryCard()}
            ${renderScopeMethodologySection()}
            ${renderRevisionHistorySection()}
        </div>
        <div class="editor-work-grid">
            <div class="editor-work-form" id="ed-form">
                <div class="card">
                    <h2>${state.editingFindingIndex !== null ? (state.lang === 'es' ? 'Editando hallazgo #' : 'Editing finding #') + (state.editingFindingIndex + 1) : t.newFinding}</h2>
                    <p class="text-muted">${t.newFindingDesc}</p>
                    
                    <form id="findingForm" onsubmit="handleFindingSubmit(event)">
                        <div class="form-group template-search-container">
                            <label>${t.quickTemplate}</label>
                            <input type="text"
                                   id="templateSearch"
                                   class="template-search-input"
                                   role="combobox" aria-expanded="false" aria-controls="templateSelect" aria-autocomplete="list"
                                   onkeydown="templateSearchKey(event)"
                                   placeholder="${state.lang === 'es' ? 'Buscar plantilla...' : 'Search template...'}"
                                   oninput="filterTemplates(this.value)"
                                   onfocus="showTemplateDropdown()"
                                   autocomplete="off">
                            <select id="templateSelect" aria-label="${t.quickTemplate}" onpointerdown="this._kb=false" onkeydown="templateListKey(event)" onchange="if(this._kb){return;} applyTemplate(this.value); hideTemplateDropdown();" size="8" class="template-filtered-select" style="display:none;">
                                <option value="custom" ${state.currentFinding.templateKey === 'custom' ? 'selected' : ''}>${t.customOther}</option>
                                <option value="sqli" ${state.currentFinding.templateKey === 'sqli' ? 'selected' : ''}>SQL Injection</option>
                                <option value="xss" ${state.currentFinding.templateKey === 'xss' ? 'selected' : ''}>XSS</option>
                                <option value="idor" ${state.currentFinding.templateKey === 'idor' ? 'selected' : ''}>IDOR</option>
                                <option value="ssrf" ${state.currentFinding.templateKey === 'ssrf' ? 'selected' : ''}>SSRF</option>
                                <option value="csrf" ${state.currentFinding.templateKey === 'csrf' ? 'selected' : ''}>CSRF</option>
                                <option value="xxe" ${state.currentFinding.templateKey === 'xxe' ? 'selected' : ''}>XXE</option>
                                <option value="rce" ${state.currentFinding.templateKey === 'rce' ? 'selected' : ''}>RCE</option>
                                <option value="lfi" ${state.currentFinding.templateKey === 'lfi' ? 'selected' : ''}>LFI</option>
                                <option value="cors" ${state.currentFinding.templateKey === 'cors' ? 'selected' : ''}>CORS Misconfig</option>
                                <option value="path_traversal" ${state.currentFinding.templateKey === 'path_traversal' ? 'selected' : ''}>Path Traversal</option>
                                <option value="command_injection" ${state.currentFinding.templateKey === 'command_injection' ? 'selected' : ''}>Command Injection</option>
                                <option value="insecure_deserialization" ${state.currentFinding.templateKey === 'insecure_deserialization' ? 'selected' : ''}>Insecure Deserialization</option>
                                <option value="jwt_bypass" ${state.currentFinding.templateKey === 'jwt_bypass' ? 'selected' : ''}>JWT Bypass</option>
                                <option value="file_upload" ${state.currentFinding.templateKey === 'file_upload' ? 'selected' : ''}>File Upload</option>
                                <option value="security_misconfig" ${state.currentFinding.templateKey === 'security_misconfig' ? 'selected' : ''}>Security Misconfig</option>
                                <option value="missing_csp" ${state.currentFinding.templateKey === 'missing_csp' ? 'selected' : ''}>Missing CSP Header</option>
                                <option value="missing_x_frame" ${state.currentFinding.templateKey === 'missing_x_frame' ? 'selected' : ''}>Missing X-Frame-Options</option>
                                <option value="missing_x_content_type" ${state.currentFinding.templateKey === 'missing_x_content_type' ? 'selected' : ''}>Missing X-Content-Type-Options</option>
                                <option value="missing_referrer" ${state.currentFinding.templateKey === 'missing_referrer' ? 'selected' : ''}>Missing Referrer-Policy</option>
                                <option value="missing_permissions" ${state.currentFinding.templateKey === 'missing_permissions' ? 'selected' : ''}>Missing Permissions-Policy</option>
                                <optgroup label="WordPress">
                                    <option value="wordpress_xmlrpc" ${state.currentFinding.templateKey === 'wordpress_xmlrpc' ? 'selected' : ''}>WP XML-RPC Enabled</option>
                                    <option value="wordpress_rest_enum" ${state.currentFinding.templateKey === 'wordpress_rest_enum' ? 'selected' : ''}>WP User Enum via REST API</option>
                                    <option value="wordpress_error_enum" ${state.currentFinding.templateKey === 'wordpress_error_enum' ? 'selected' : ''}>WP User Enum via Errors</option>
                                    <option value="wordpress_login_brute" ${state.currentFinding.templateKey === 'wordpress_login_brute' ? 'selected' : ''}>WP Brute Force Login</option>
                                    <option value="wordpress_plugin_enum" ${state.currentFinding.templateKey === 'wordpress_plugin_enum' ? 'selected' : ''}>WP Plugin Enumeration</option>
                                    <option value="wordpress_theme_enum" ${state.currentFinding.templateKey === 'wordpress_theme_enum' ? 'selected' : ''}>WP Theme Enumeration</option>
                                    <option value="wordpress_config_exposure" ${state.currentFinding.templateKey === 'wordpress_config_exposure' ? 'selected' : ''}>WP wp-config.php Exposed</option>
                                    <option value="wordpress_uploads_directory" ${state.currentFinding.templateKey === 'wordpress_uploads_directory' ? 'selected' : ''}>WP Uploads Dir Listing</option>
                                    <option value="wordpress_version_leak" ${state.currentFinding.templateKey === 'wordpress_version_leak' ? 'selected' : ''}>WP Version Leak</option>
                                    <option value="wordpress_db_backup" ${state.currentFinding.templateKey === 'wordpress_db_backup' ? 'selected' : ''}>WP Database Backup Exposed</option>
                                </optgroup>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label>${t.vulnTitle}</label>
                            <input type="text" id="findingTitle" value="${escapeHTML(state.currentFinding.title)}" required oninput="updateCurrentFinding('title', this.value)">
                        </div>
                        
                        <div class="form-row form-row--sev-cvss">
<div class="form-group">
                            <label>${t.severity}</label>
                            <select id="findingSeverity" onchange="updateCurrentFinding('severity', this.value)">
                                ${Object.entries(t.severityLevels).map(([key, label]) =>
        `<option value="${key}" ${state.currentFinding.severity === key ? 'selected' : ''}>${label}</option>`
    ).join('')}
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label>${t.cvss}</label>
                            <div style="display:flex;gap:0.5rem;align-items:center;">
                                <input type="text" id="findingCvss" style="flex:1;" value="${escapeHTML(state.currentFinding.cvss)}" oninput="updateCurrentFinding('cvss', this.value)">
                                <button type="button" class="btn-secondary btn-sm" onclick="openCvssCalc()" title="${state.lang === 'es' ? 'Calculadora CVSS 3.1' : 'CVSS 3.1 calculator'}" style="white-space:nowrap;">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;"><rect x="4" y="2" width="16" height="20" rx="2"/><line x1="8" y1="6" x2="16" y2="6"/><line x1="8" y1="10" x2="8" y2="10"/><line x1="12" y1="10" x2="12" y2="10"/><line x1="16" y1="10" x2="16" y2="10"/><line x1="8" y1="14" x2="8" y2="14"/><line x1="12" y1="14" x2="12" y2="14"/><line x1="8" y1="18" x2="16" y2="18"/></svg>
                                    ${state.lang === 'es' ? 'Calcular' : 'Calculate'}
                                </button>
                            </div>
                            ${state.currentFinding.cvssVector ? `<small class="text-muted" style="font-family:ui-monospace,monospace;display:block;margin-top:0.35rem;word-break:break-all;">${escapeHTML(state.currentFinding.cvssVector)}</small>` : ''}
                        </div>

                        </div>
<div class="form-group">
                            <label>${t.description}</label>
                            <textarea id="findingDescription" rows="4" oninput="updateCurrentFinding('description', this.value)">${escapeHTML(state.currentFinding.description)}</textarea>
                        </div>
                        
                        ${findingGroup('evidence', `<div class="form-group">
                            <label>${t.poc}</label>
                            <textarea id="findingPoc" rows="4" oninput="updateCurrentFinding('poc', this.value)">${escapeHTML(state.currentFinding.poc)}</textarea>
                        </div>

                        <div class="form-group">
                            <label>${t.exploit}</label>
                            <textarea id="findingExploit" class="code-input" rows="6" spellcheck="false" placeholder="${state.lang === 'es' ? 'Pega aquí el código del exploit (se imprimirá como bloque de código en el informe)' : 'Paste the exploit code here (it will be printed as a code block in the report)'}" oninput="updateCurrentFinding('exploit', this.value)">${escapeHTML(state.currentFinding.exploit || '')}</textarea>
                        </div>

                        <div class="form-group image-upload-section" onpaste="handleImagePaste(event)">
                            <label>${t.images} <small style="font-weight:normal;color:#666;">(también puedes pegar imagen con Ctrl+V aquí)</small></label>
                            <input type="file" id="findingImages" accept="image/*" multiple onchange="handleImageUpload(event)">
                            <small class="text-muted">${state.currentFinding.images.length} imagen(es) seleccionada(s)</small>
                        </div>

                        ${state.currentFinding.images.length > 0 ? `
                        ${state.currentFinding.images.length > 1 ? `<small class="text-muted image-reorder-hint">${state.lang === 'es' ? 'Arrastra las imágenes para cambiar su orden en el informe' : 'Drag the images to change their order in the report'}</small>` : ''}
                        <div class="image-preview-container">
                            ${state.currentFinding.images.map((img, idx) => `
                                <div class="image-preview-item" draggable="true" data-img-idx="${idx}"
                                    ondragstart="imageDragStart(event, ${idx})"
                                    ondragover="imageDragOver(event, ${idx})"
                                    ondragleave="imageDragLeave(event)"
                                    ondrop="imageDrop(event, ${idx})"
                                    ondragend="imageDragEnd(event)"
                                    title="${state.lang === 'es' ? 'Arrastra para reordenar' : 'Drag to reorder'}">
                                    <span class="image-order-badge">${idx + 1}</span>
                                    <img src="${escapeHTML(img)}" alt="Evidencia ${idx + 1}" draggable="false">
                                    <button type="button" class="image-remove-btn" onclick="removeImage(${idx})">×</button>
                                    <div class="image-caption-wrap">
                                        <input type="text" class="image-caption-input"
                                            placeholder="${state.lang === 'es' ? 'Pie de imagen (opcional)' : 'Image caption (optional)'}"
                                            value="${escapeHTML(state.currentFinding.imageCaptions[idx] || '')}"
                                            oninput="state.currentFinding.imageCaptions[${idx}] = this.value">
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                        ` : ''}

                        `)}
${findingGroup('impact', `<div class="form-group">
                            <label>${t.impact}</label>
                            <textarea id="findingImpact" rows="3" oninput="updateCurrentFinding('impact', this.value)">${escapeHTML(state.currentFinding.impact)}</textarea>
                        </div>

                        <div class="form-group">
                            <label>${t.remediation}</label>
                            <textarea id="findingRemediation" rows="3" oninput="updateCurrentFinding('remediation', this.value)">${escapeHTML(state.currentFinding.remediation)}</textarea>
                        </div>

                        `)}
${findingGroup('refs', `<div class="form-group">
                            <label>${t.reference} ${state.lang === 'es' ? '(principal)' : '(primary)'}</label>
                            <input type="text" id="findingReference" value="${escapeHTML(state.currentFinding.reference)}" oninput="updateCurrentFinding('reference', this.value)">
                        </div>

                        <div class="form-group">
                            <label>${state.lang === 'es' ? 'Referencias adicionales (una por línea)' : 'Additional references (one per line)'}</label>
                            <textarea id="findingReferences" rows="2" placeholder="https://owasp.org/...\nhttps://cwe.mitre.org/..." oninput="updateCurrentFindingList('references', this.value)">${escapeHTML((state.currentFinding.references || []).join('\n'))}</textarea>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>${t.cve}</label>
                                <input type="text" id="findingCve" placeholder="CVE-2024-XXXXX" value="${escapeHTML(state.currentFinding.cve)}" oninput="updateCurrentFinding('cve', this.value)">
                            </div>
                            <div class="form-group">
                                <label>${t.cwe}</label>
                                <input type="text" id="findingCwe" placeholder="CWE-89" value="${escapeHTML(state.currentFinding.cwe || '')}" oninput="updateCurrentFinding('cwe', this.value)">
                            </div>
                        </div>

                        `)}
${renderFindingProFieldsEditor()}

                        <div class="form-actions">
                            <button type="submit" class="btn-primary">${state.editingFindingIndex !== null ? t.updateFinding : t.addFinding}</button>
                            <button type="button" onclick="resetFindingForm()">${t.cancel}</button>
                        </div>
                    </form>
                </div>
            </div>

            <div class="editor-work-list" id="ed-findings">
                ${renderFindingsList()}
            </div>
        </div>
        </div>
    `;
}

// Tarjeta 1: identidad del informe (título, cliente, portada, clasificación).
// Es la única sección siempre visible sin colapsar: son los datos esenciales.
function renderGeneralInfoCard() {
    const t = UI[state.lang];
    const isEs = state.lang === 'es';
    const d = state.auditData;

    return `
        <div class="card editor-meta-card editor-meta-card--wide" id="ed-general">
            <div class="card-header-row">
                <h3>${isEs ? 'Información general' : 'General information'}</h3>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label for="genDocTitle">${t.documentTitle}</label>
                    <input id="genDocTitle" type="text" value="${escapeHTML(d.documentTitle)}" onchange="updateAuditData('documentTitle', this.value)">
                </div>
                <div class="form-group">
                    <label for="genClientCompany">${t.clientCompany}</label>
                    <input id="genClientCompany" type="text" value="${escapeHTML(d.clientCompany)}" onchange="updateAuditData('clientCompany', this.value)">
                </div>
            </div>

            <div class="form-row-3">
                <div class="form-group">
                    <label for="genTargetAsset">${t.targetAsset}</label>
                    <input id="genTargetAsset" type="text" value="${escapeHTML(d.targetAsset)}" onchange="updateAuditData('targetAsset', this.value)">
                </div>
                <div class="form-group">
                    <label for="genAuditorCompany">${t.auditorCompany}</label>
                    <input id="genAuditorCompany" type="text" value="${escapeHTML(d.auditorCompany)}" onchange="updateAuditData('auditorCompany', this.value)">
                </div>
                <div class="form-group">
                    <label for="genAuditorName">${t.auditorName}</label>
                    <input id="genAuditorName" type="text" value="${escapeHTML(d.auditorName)}" onchange="updateAuditData('auditorName', this.value)">
                </div>
            </div>

            <div class="form-row-4">
                <div class="form-group">
                    <label for="genClassification">${t.classification}</label>
                    <select id="genClassification" onchange="updateAuditData('classification', this.value)">
                        ${Object.entries(t.classifications).map(([key, label]) =>
        `<option value="${key}" ${d.classification === key ? 'selected' : ''}>${label}</option>`
    ).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label for="genAuditType">${t.auditType}</label>
                    <select id="genAuditType" onchange="updateAuditData('auditType', this.value)">
                        ${Object.entries(t.auditTypes).map(([key, label]) =>
        `<option value="${key}" ${d.auditType === key ? 'selected' : ''}>${label}</option>`
    ).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label for="genVersion">${t.version}</label>
                    <input id="genVersion" type="text" value="${escapeHTML(d.version)}" onchange="updateAuditData('version', this.value)">
                </div>
                <div class="form-group">
                    <label for="genDate">${t.date}</label>
                    <input id="genDate" type="date" value="${escapeHTML(d.date)}" onchange="updateAuditData('date', this.value)">
                </div>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label for="genLogo1">${t.clientLogo1 || 'Logotipo 1'}</label>
                    <input id="genLogo1" type="file" accept="image/*" onchange="handleClientLogoUpload(event, 0)">
                    ${d.clientLogo[0] ? `
                        <div style="margin-top: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
                            <img src="${escapeHTML(d.clientLogo[0])}" alt="${isEs ? 'Vista previa del logotipo 1' : 'Logo 1 preview'}" style="height: 40px; border-radius: 4px; border: 1px solid #e5e7eb;">
                            <button type="button" class="btn-sm btn-secondary" onclick="removeClientLogo(0)" aria-label="${isEs ? 'Quitar logotipo 1' : 'Remove logo 1'}">×</button>
                        </div>
                    ` : ''}
                </div>
                <div class="form-group">
                    <label for="genLogo2">${t.clientLogo2 || 'Logotipo 2'}</label>
                    <input id="genLogo2" type="file" accept="image/*" onchange="handleClientLogoUpload(event, 1)">
                    ${d.clientLogo[1] ? `
                        <div style="margin-top: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
                            <img src="${escapeHTML(d.clientLogo[1])}" alt="${isEs ? 'Vista previa del logotipo 2' : 'Logo 2 preview'}" style="height: 40px; border-radius: 4px; border: 1px solid #e5e7eb;">
                            <button type="button" class="btn-sm btn-secondary" onclick="removeClientLogo(1)" aria-label="${isEs ? 'Quitar logotipo 2' : 'Remove logo 2'}">×</button>
                        </div>
                    ` : ''}
                </div>
            </div>

            <fieldset class="form-group" style="border:none;padding:0;margin-bottom:0;">
                <legend style="font-size:0.6875rem;font-weight:700;color:#64748b;margin-bottom:0.375rem;letter-spacing:0.06em;text-transform:uppercase;padding:0;">${t.incidents}</legend>
                <div class="incidents-toggle" style="display:flex; gap:0.75rem; margin-bottom:0.5rem;">
                    <label style="display:flex; align-items:center; gap:0.4rem; font-weight:500; text-transform:none; letter-spacing:normal; cursor:pointer;">
                        <input type="radio" name="hasIncidents" value="no" ${!d.hasIncidents ? 'checked' : ''} onchange="updateAuditData('hasIncidents', false); document.getElementById('incidentsTextContainer').style.display='none';" style="width:auto; padding:0; margin:0;">
                        ${t.incidentsNo}
                    </label>
                    <label style="display:flex; align-items:center; gap:0.4rem; font-weight:500; text-transform:none; letter-spacing:normal; cursor:pointer;">
                        <input type="radio" name="hasIncidents" value="yes" ${d.hasIncidents ? 'checked' : ''} onchange="updateAuditData('hasIncidents', true); document.getElementById('incidentsTextContainer').style.display='block';" style="width:auto; padding:0; margin:0;">
                        ${t.incidentsYes}
                    </label>
                </div>
                <div id="incidentsTextContainer" style="display: ${d.hasIncidents ? 'block' : 'none'};">
                    <label for="genIncidentsText" class="sr-only">${t.incidentsDesc}</label>
                    <textarea id="genIncidentsText" rows="3" placeholder="${t.incidentsDesc}..." oninput="updateAuditData('incidentsText', this.value)">${escapeHTML(d.incidentsText)}</textarea>
                </div>
            </fieldset>
        </div>`;
}

// Tarjeta 2: resumen ejecutivo (textos largos del cierre del informe).
function renderExecutiveSummaryCard() {
    const t = UI[state.lang];
    const d = state.auditData;
    return `
        <details class="card editor-meta-card" id="ed-summary" ${editorSectionOpen('summary') ? 'open' : ''} ontoggle="editorToggled('summary', this.open)">
            <summary><h3>${state.lang === 'es' ? 'Resumen ejecutivo' : 'Executive summary'}</h3></summary>
            <div class="details-body">
            <div class="form-group">
                <label for="genAuditSummary">${t.auditSummary}</label>
                <small style="display:block; color:#666; margin-bottom:0.5rem; font-weight:normal;">${t.auditSummaryDesc}</small>
                <textarea id="genAuditSummary" rows="4" placeholder="${t.auditSummary}..." oninput="updateAuditData('auditSummary', this.value)">${escapeHTML(d.auditSummary)}</textarea>
            </div>

            <div class="form-group">
                <label for="genTestsPerformed">${t.testsPerformed}</label>
                <small style="display:block; color:#666; margin-bottom:0.5rem; font-weight:normal;">${t.testsPerformedDesc}</small>
                <textarea id="genTestsPerformed" rows="4" placeholder="${t.testsPerformed}..." oninput="updateAuditData('testsPerformed', this.value)">${escapeHTML(d.testsPerformed)}</textarea>
            </div>

            <div class="form-group" style="margin-bottom:0;">
                <label for="genRecommendedSolutions">${t.recommendedSolutions}</label>
                <small style="display:block; color:#666; margin-bottom:0.5rem; font-weight:normal;">${t.recommendedSolutionsDesc}</small>
                <textarea id="genRecommendedSolutions" rows="4" placeholder="${t.recommendedSolutions}..." oninput="updateAuditData('recommendedSolutions', this.value)">${escapeHTML(d.recommendedSolutions)}</textarea>
            </div>
            </div>
        </details>`;
}

const METHODOLOGY_STANDARDS = [
    { key: 'owasp_wstg', label: 'OWASP WSTG' },
    { key: 'owasp_top10', label: 'OWASP Top 10' },
    { key: 'ptes', label: 'PTES' },
    { key: 'nist_800_115', label: 'NIST SP 800-115' },
    { key: 'osstmm', label: 'OSSTMM' },
    { key: 'mitre_attack', label: 'MITRE ATT&CK' },
    { key: 'owasp_masvs', label: 'OWASP MASVS' },
    { key: 'iso_27001', label: 'ISO 27001' }
];

function toggleMethodologyStandard(key) {
    const arr = state.auditData.methodologyStandards || [];
    const i = arr.indexOf(key);
    if (i >= 0) arr.splice(i, 1); else arr.push(key);
    state.auditData.methodologyStandards = arr;
    state.isDirty = true;
    renderApp();
}

function getScopeFieldVis(key) {
    const vis = state.auditData.scopeFieldsVisibility || {};
    return !!vis[key];
}

function _scopeFieldToggle(key, isEs) {
    const on = getScopeFieldVis(key);
    return `<span role="switch" tabindex="0" aria-checked="${on}" aria-label="${isEs ? 'Incluir en el informe' : 'Include in report'}" onkeydown="switchKey(event)" class="rep-switch" onclick="toggleScopeField('${key}')" title="${isEs ? 'Incluir en informe' : 'Include in report'}"
        style="display:inline-flex;align-items:center;gap:0.3rem;cursor:pointer;font-size:0.75rem;font-weight:500;color:${on ? '#2563eb' : '#9ca3af'};user-select:none;flex-shrink:0;">
        <span style="position:relative;display:inline-block;width:28px;height:16px;">
            <span style="display:block;width:28px;height:16px;border-radius:999px;background:${on ? '#2563eb' : '#d1d5db'};transition:background 0.15s;"></span>
            <span style="position:absolute;top:2px;left:${on ? '14px' : '2px'};width:12px;height:12px;border-radius:50%;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,0.2);transition:left 0.15s;"></span>
        </span>
        ${isEs ? 'en informe' : 'in report'}
    </span>`;
}

function toggleScopeField(key) {
    const vis = Object.assign({}, state.auditData.scopeFieldsVisibility || {});
    vis[key] = !getScopeFieldVis(key);
    state.auditData.scopeFieldsVisibility = vis;
    state.isDirty = true;
    renderApp();
}

// --- Visibilidad opt-in de campos OPCIONALES del hallazgo (por defecto ocultos) ---
// A diferencia del alcance (que por defecto se muestra), estos metadatos accesorios
// SOLO aparecen en el informe si su toggle está activado explícitamente.
function getFindingFieldVis(f, key) {
    return !!(f && f.fieldsVisibility && f.fieldsVisibility[key]);
}

function toggleCurrentFindingField(key) {
    const f = state.currentFinding;
    const vis = Object.assign({}, f.fieldsVisibility || {});
    vis[key] = !vis[key];
    f.fieldsVisibility = vis;
    state.isDirty = true;
    renderApp();
}

function _findingFieldToggle(key, isEs) {
    const on = getFindingFieldVis(state.currentFinding, key);
    return `<span role="switch" tabindex="0" aria-checked="${on}" aria-label="${isEs ? 'Incluir este campo en el informe' : 'Include this field in the report'}" onkeydown="switchKey(event)" class="rep-switch" onclick="toggleCurrentFindingField('${key}')" title="${isEs ? 'Incluir este campo en el informe' : 'Include this field in the report'}"
        style="display:inline-flex;align-items:center;gap:0.3rem;cursor:pointer;font-size:0.72rem;font-weight:500;color:${on ? '#2563eb' : '#9ca3af'};user-select:none;flex-shrink:0;">
        <span style="position:relative;display:inline-block;width:28px;height:16px;">
            <span style="display:block;width:28px;height:16px;border-radius:999px;background:${on ? '#2563eb' : '#d1d5db'};transition:background 0.15s;"></span>
            <span style="position:absolute;top:2px;left:${on ? '14px' : '2px'};width:12px;height:12px;border-radius:50%;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,0.2);transition:left 0.15s;"></span>
        </span>
        ${isEs ? 'en informe' : 'in report'}
    </span>`;
}

// Metadatos profesionales opcionales del hallazgo (estado, riesgo, OWASP,
// activos afectados, cumplimiento, notas de re-test). El modelo de datos y
// la plantilla del informe ya los soportaban; esto es lo que faltaba para
// poder rellenarlos desde la interfaz.
function renderFindingProFieldsEditor() {
    const t = UI[state.lang];
    const isEs = state.lang === 'es';
    const cf = state.currentFinding;

    return `
        <details class="pro-fields-details" id="ed-pro" ${editorSectionOpen('pro', false) ? 'open' : ''} ontoggle="editorToggled('pro', this.open)">
            <summary>${isEs ? 'Metadatos profesionales (opcional)' : 'Professional metadata (optional)'}</summary>
            <div class="details-body">
                <div class="form-row">
                    <div class="form-group">
                        <label for="findingStatus">${isEs ? 'Estado' : 'Status'}</label>
                        <select id="findingStatus" onchange="updateCurrentFinding('status', this.value)">
                            ${Object.entries(t.findingStatuses).map(([key, label]) =>
        `<option value="${key}" ${cf.status === key ? 'selected' : ''}>${label}</option>`
    ).join('')}
                        </select>
                    </div>
                    <div class="form-group">
                        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.375rem;">
                            <label style="margin:0;" for="findingOwasp">OWASP Top 10</label>
                            ${_findingFieldToggle('owasp', isEs)}
                        </div>
                        <input id="findingOwasp" type="text" placeholder="A03:2021 – Injection" value="${escapeHTML(cf.owasp || '')}" oninput="updateCurrentFinding('owasp', this.value)">
                    </div>
                </div>

                <div class="form-group">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.375rem;">
                        <label style="margin:0;">${isEs ? 'Probabilidad × Impacto (matriz de riesgo)' : 'Likelihood × Impact (risk matrix)'}</label>
                        ${_findingFieldToggle('risk', isEs)}
                    </div>
                    <div class="form-row">
                        <select id="findingLikelihood" aria-label="${isEs ? 'Probabilidad' : 'Likelihood'}" onchange="updateCurrentFinding('likelihood', this.value)">
                            ${Object.entries(t.riskLevels).map(([key, label]) =>
        `<option value="${key}" ${cf.likelihood === key ? 'selected' : ''}>${label}</option>`
    ).join('')}
                        </select>
                        <select id="findingImpactRating" aria-label="${isEs ? 'Impacto' : 'Impact'}" onchange="updateCurrentFinding('impactRating', this.value)">
                            ${Object.entries(t.riskLevels).map(([key, label]) =>
        `<option value="${key}" ${cf.impactRating === key ? 'selected' : ''}>${label}</option>`
    ).join('')}
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label for="findingAffectedAssets">${isEs ? 'Activos afectados' : 'Affected assets'}</label>
                    <textarea id="findingAffectedAssets" rows="2" placeholder="${isEs ? 'Endpoints, parámetros, hosts afectados...' : 'Affected endpoints, parameters, hosts...'}" oninput="updateCurrentFinding('affectedAssets', this.value)">${escapeHTML(cf.affectedAssets || '')}</textarea>
                </div>

                <div class="form-group">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.375rem;">
                        <label style="margin:0;" for="findingCompliance">${isEs ? 'Cumplimiento / mapeo (separado por comas)' : 'Compliance / mapping (comma-separated)'}</label>
                        ${_findingFieldToggle('compliance', isEs)}
                    </div>
                    <input id="findingCompliance" type="text" placeholder="PCI-DSS 6.5.1, ISO 27001 A.14.2" value="${escapeHTML((cf.compliance || []).join(', '))}" oninput="updateCurrentFindingCsv('compliance', this.value)">
                </div>

                <div class="form-group" style="margin-bottom:0;">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.375rem;">
                        <label style="margin:0;" for="findingRetestNotes">${isEs ? 'Notas de re-test' : 'Re-test notes'}</label>
                        ${_findingFieldToggle('retest', isEs)}
                    </div>
                    <textarea id="findingRetestNotes" rows="2" placeholder="${isEs ? 'Resultado de la verificación tras la remediación...' : 'Verification result after remediation...'}" oninput="updateCurrentFinding('retestNotes', this.value)">${escapeHTML(cf.retestNotes || '')}</textarea>
                </div>
            </div>
        </details>
    `;
}

function renderScopeMethodologySection() {
    const isEs = state.lang === 'es';
    const d = state.auditData;
    const selected = d.methodologyStandards || [];
    return `
        <details class="card editor-meta-card" id="ed-scope" ${editorSectionOpen('scope') ? 'open' : ''} ontoggle="editorToggled('scope', this.open)">
        <summary><h3>${isEs ? 'Alcance y Metodología' : 'Scope & Methodology'}</h3></summary>
        <div class="details-body">
        <div class="form-row">
            <div class="form-group">
                <label>${isEs ? 'Inicio del engagement' : 'Engagement start'}</label>
                <input type="date" value="${escapeHTML(d.engagementStart || '')}" onchange="updateAuditData('engagementStart', this.value)">
            </div>
            <div class="form-group">
                <label>${isEs ? 'Fin del engagement' : 'Engagement end'}</label>
                <input type="date" value="${escapeHTML(d.engagementEnd || '')}" onchange="updateAuditData('engagementEnd', this.value)">
            </div>
        </div>

        <div class="form-group">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.35rem;">
                <label style="margin:0;">${isEs ? 'Dentro del alcance (in-scope)' : 'In-scope assets'}</label>
                ${_scopeFieldToggle('scopeIn', isEs)}
            </div>
            <textarea rows="2" placeholder="${isEs ? 'IPs, dominios, URLs incluidos...' : 'Included IPs, domains, URLs...'}" oninput="updateAuditData('scopeIn', this.value)" style="${!getScopeFieldVis('scopeIn') ? 'opacity:0.4;' : ''}">${escapeHTML(d.scopeIn || '')}</textarea>
        </div>
        <div class="form-group">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.35rem;">
                <label style="margin:0;">${isEs ? 'Fuera del alcance / exclusiones' : 'Out-of-scope / exclusions'}</label>
                ${_scopeFieldToggle('scopeOut', isEs)}
            </div>
            <textarea rows="2" placeholder="${isEs ? 'Sistemas excluidos, rangos no probados...' : 'Excluded systems, untested ranges...'}" oninput="updateAuditData('scopeOut', this.value)" style="${!getScopeFieldVis('scopeOut') ? 'opacity:0.4;' : ''}">${escapeHTML(d.scopeOut || '')}</textarea>
        </div>

        <div class="form-group">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.35rem;">
                <label style="margin:0;">${isEs ? 'Metodologías / estándares aplicados' : 'Methodologies / standards applied'}</label>
                ${_scopeFieldToggle('standards', isEs)}
            </div>
            <div class="pro-tags" style="margin-top:0.25rem;${!getScopeFieldVis('standards') ? 'opacity:0.4;' : ''}">
                ${METHODOLOGY_STANDARDS.map(s => `
                    <label style="display:inline-flex;align-items:center;gap:0.35rem;font-weight:500;text-transform:none;letter-spacing:normal;cursor:pointer;padding:0.2rem 0.55rem;border:1px solid ${selected.includes(s.key) ? '#3b82f6' : '#e2e8f0'};border-radius:999px;font-size:0.78rem;${selected.includes(s.key) ? 'background:rgba(59,130,246,0.1);color:#2563eb;' : ''}">
                        <input type="checkbox" ${selected.includes(s.key) ? 'checked' : ''} onchange="toggleMethodologyStandard('${s.key}')" style="width:auto;margin:0;padding:0;">
                        ${s.label}
                    </label>
                `).join('')}
            </div>
        </div>

        <div class="form-group">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.35rem;">
                <label style="margin:0;">${isEs ? 'Notas de metodología (opcional)' : 'Methodology notes (optional)'}</label>
                ${_scopeFieldToggle('methodologyNotes', isEs)}
            </div>
            <textarea rows="2" placeholder="${isEs ? 'Tipo de caja, reglas de enfrentamiento...' : 'Box type, rules of engagement...'}" oninput="updateAuditData('methodologyNotes', this.value)" style="${!getScopeFieldVis('methodologyNotes') ? 'opacity:0.4;' : ''}">${escapeHTML(d.methodologyNotes || '')}</textarea>
        </div>
        <div class="form-group">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.35rem;">
                <label style="margin:0;">${isEs ? 'Herramientas utilizadas' : 'Tools used'}</label>
                ${_scopeFieldToggle('toolsUsed', isEs)}
            </div>
            <textarea rows="4" placeholder="Burp Suite, nmap, sqlmap, ffuf..." oninput="updateAuditData('toolsUsed', this.value)" style="${!getScopeFieldVis('toolsUsed') ? 'opacity:0.4;' : ''}">${escapeHTML(d.toolsUsed || '')}</textarea>
        </div>
        </div>
        </details>
    `;
}

function addRevisionRow() {
    if (!Array.isArray(state.auditData.revisionHistory)) state.auditData.revisionHistory = [];
    state.auditData.revisionHistory.push({
        version: state.auditData.version || '1.0',
        date: state.auditData.date || new Date().toISOString().split('T')[0],
        author: state.auditData.auditorName || '',
        changes: ''
    });
    state.isDirty = true;
    renderApp();
}

function updateRevisionRow(idx, field, value) {
    if (state.auditData.revisionHistory[idx]) {
        state.auditData.revisionHistory[idx][field] = value;
        state.isDirty = true;
    }
}

function removeRevisionRow(idx) {
    state.auditData.revisionHistory.splice(idx, 1);
    state.isDirty = true;
    renderApp();
}

function openRevisionModal() {
    state.showRevisionModal = true;
    renderApp();
}

function closeRevisionModal() {
    state.showRevisionModal = false;
    renderApp();
}

// Sección contraída: sólo un resumen y un botón que abre el modal de gestión.
function renderRevisionHistorySection() {
    const isEs = state.lang === 'es';
    const rows = state.auditData.revisionHistory || [];
    const count = rows.length;
    const summary = count
        ? rows.map(r => escapeHTML(r.version || '?')).join(' · ')
        : (isEs ? 'Sin revisiones registradas.' : 'No revisions recorded.');
    return `
        <div class="card editor-meta-card editor-meta-card--compact" id="ed-revisions">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:0.75rem;">
            <div style="display:flex;align-items:center;gap:0.5rem;">
                <h3 style="margin:0;">${isEs ? 'Historial de revisiones' : 'Revision history'}</h3>
                ${count ? `<span class="findings-count">${count}</span>` : ''}
            </div>
            <button type="button" class="btn-sm btn-secondary" onclick="openRevisionModal()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.3rem;">
                    <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                </svg>${count ? (isEs ? 'Gestionar' : 'Manage') : (isEs ? 'Añadir' : 'Add')}
            </button>
        </div>
        <p class="text-muted" style="font-size:0.82rem;margin:0.55rem 0 0;">${summary}</p>
        </div>
    `;
}

function renderRevisionRowsEditor() {
    const isEs = state.lang === 'es';
    const rows = state.auditData.revisionHistory || [];
    if (rows.length === 0) {
        return `<p class="text-muted" style="font-size:0.9rem;text-align:center;padding:1.5rem 0;">${isEs ? 'Sin revisiones registradas. Añade la primera con el botón de abajo.' : 'No revisions recorded. Add the first one with the button below.'}</p>`;
    }
    return `<div class="revision-list">${rows.map((r, idx) => `
        <div class="revision-card">
            <button type="button" class="revision-remove" onclick="removeRevisionRow(${idx})" title="${isEs ? 'Eliminar' : 'Delete'}">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
            <div class="revision-grid">
                <div class="form-group">
                    <label>${isEs ? 'Versión' : 'Version'}</label>
                    <input type="text" value="${escapeHTML(r.version || '')}" oninput="updateRevisionRow(${idx},'version',this.value)">
                </div>
                <div class="form-group">
                    <label>${isEs ? 'Fecha' : 'Date'}</label>
                    <input type="date" value="${escapeHTML(r.date || '')}" oninput="updateRevisionRow(${idx},'date',this.value)">
                </div>
                <div class="form-group">
                    <label>${isEs ? 'Autor' : 'Author'}</label>
                    <input type="text" value="${escapeHTML(r.author || '')}" oninput="updateRevisionRow(${idx},'author',this.value)">
                </div>
                <div class="form-group revision-changes">
                    <label>${isEs ? 'Cambios' : 'Changes'}</label>
                    <input type="text" value="${escapeHTML(r.changes || '')}" oninput="updateRevisionRow(${idx},'changes',this.value)">
                </div>
            </div>
        </div>
    `).join('')}</div>`;
}

function renderRevisionModal() {
    if (!state.showRevisionModal) return '';
    const isEs = state.lang === 'es';
    return `
        <div class="settings-overlay" style="align-items:center;justify-content:center;padding:1rem;" onclick="closeRevisionModal()">
            <div class="settings-modal" style="width:100%;max-width:760px;display:flex;flex-direction:column;max-height:90vh;" onclick="event.stopPropagation()">
                <div class="settings-modal-header">
                    <span>${isEs ? 'Historial de revisiones' : 'Revision history'}</span>
                    <button class="settings-close-btn" onclick="closeRevisionModal()">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </div>
                <div style="padding:1.25rem;overflow-y:auto;">
                    ${renderRevisionRowsEditor()}
                    <button type="button" class="btn-sm btn-secondary" onclick="addRevisionRow()" style="margin-top:0.5rem;">+ ${isEs ? 'Añadir revisión' : 'Add revision'}</button>
                </div>
                <div style="display:flex;gap:0.5rem;justify-content:flex-end;padding:1rem 1.25rem;border-top:1px solid #3a3a40;">
                    <button class="btn-primary" onclick="closeRevisionModal()">${isEs ? 'Hecho' : 'Done'}</button>
                </div>
            </div>
        </div>`;
}

function renderFindingsList() {
    const t = UI[state.lang];
    const isEs = state.lang === 'es';
    const title = isEs ? 'Findings / Vulnerabilidades' : 'Findings / Vulnerabilities';

    const header = `
        <div class="findings-section-header">
            <h3 class="findings-section-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9.5 12l1.8 1.8 3.5-3.6"/>
                </svg>
                ${title}
            </h3>
            <span class="findings-count">${state.findings.length}</span>
        </div>`;

    if (state.findings.length === 0) {
        return `
            <div class="card findings-card">
                ${header}
                <p class="text-muted findings-empty">${t.noFindings}</p>
            </div>`;
    }

    return `
        <div class="card findings-card">
            ${header}
            <div class="findings-grid">
                ${state.findings.map((f, idx) => `
                    <div class="finding-item severity-${safeSeverity(f.severity)}${state.editingFindingIndex === idx ? ' is-editing' : ''}"${state.editingFindingIndex === idx ? ' aria-current="true"' : ''}>
                        <div class="finding-header">
                            <span class="finding-number">#${idx + 1}</span>
                            <span class="finding-severity">${t.severityLevels[safeSeverity(f.severity)]}</span>
                            <div class="finding-actions">
                                <button type="button" class="btn-edit" onclick="editFinding(${idx})" title="${isEs ? 'Editar' : 'Edit'}" aria-label="${isEs ? 'Editar hallazgo' : 'Edit finding'} #${idx + 1}">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                    </svg>
                                </button>
                                <button type="button" class="btn-delete" onclick="deleteFinding(${idx})" title="${isEs ? 'Eliminar' : 'Delete'}" aria-label="${isEs ? 'Eliminar hallazgo' : 'Delete finding'} #${idx + 1}"><span aria-hidden="true">×</span></button>
                            </div>
                        </div>
                        <button type="button" class="finding-title finding-title-btn" onclick="editFinding(${idx})">${escapeHTML(f.title)}</button>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

// --------------------------------------------------------------------------- //
// Plantilla de partida que se precarga al crear un tema nuevo desde cero.
// No es un "tema de fábrica" seleccionable: es sólo contenido de ejemplo,
// completamente editable/sustituible, pensado para enseñar toda la sintaxis
// del motor de plantillas (ThemeEngine) y las variables disponibles.
// --------------------------------------------------------------------------- //
const DEFAULT_THEME_TEMPLATE_HTML = `<div class="cover">
  {{#if client_logo}}
  <div class="cover-logos">
    {{#each client_logo}}<img src="{{this}}" alt="logo" class="cover-logo">{{/each}}
  </div>
  {{/if}}
  <h1 class="cover-title">{{document_title}}</h1>
  <p class="cover-target">{{target_asset}}</p>
  <span class="badge badge-classif">{{classification_label}}</span>

  <div class="cover-meta">
    <div><span class="cover-meta-label">Cliente</span><strong>{{client_company}}</strong></div>
    <div><span class="cover-meta-label">Auditor</span><strong>{{auditor_company}}</strong><br>{{auditor_name}}</div>
    <div><span class="cover-meta-label">Fecha</span><strong>{{date}}</strong></div>
    <div><span class="cover-meta-label">Versión</span><strong>{{version}}</strong></div>
  </div>
</div>

<div class="toc">
  <h2>Índice</h2>
  <a class="toc-item" href="#resumen"><span>Resumen ejecutivo</span></a>
  {{#if scope.show}}<a class="toc-item" href="#alcance"><span>Alcance y metodología</span></a>{{/if}}
  <a class="toc-item" href="#hallazgos"><span>Hallazgos técnicos</span></a>
  {{#each findings}}
  <a class="toc-item toc-finding" href="#finding-{{this.index}}">
    <span>{{this.index1}}. {{this.title}}</span>
    <span class="badge sev-{{this.severity}}">{{this.severity_label}}</span>
  </a>
  {{/each}}
</div>

<div id="resumen" class="section">
  <h2 class="section-title">Resumen ejecutivo</h2>

  {{#if show_severity_bars}}
  <div class="summary-bar">
    {{#each severity_breakdown}}
    {{#if this.count}}<div class="summary-bar-seg sev-bg-{{this.key}}" style="width:{{this.percent}}%" title="{{this.label}}: {{this.count}}"></div>{{/if}}
    {{/each}}
  </div>
  {{/if}}

  <div class="summary-legend">
    {{#each severity_breakdown}}
    <div class="legend-item"><span class="legend-dot sev-bg-{{this.key}}"></span>{{this.label}} <strong>{{this.count}}</strong></div>
    {{/each}}
  </div>

  {{#if audit_summary}}<div class="rich-text">{{{audit_summary_html}}}</div>{{/if}}

  {{#if risk_matrix_has_data}}
  <h3>Matriz de riesgo (Probabilidad × Impacto)</h3>
  <table class="risk-matrix">
    <tr><th></th><th>Imp. Alta</th><th>Imp. Media</th><th>Imp. Baja</th></tr>
    {{#each risk_matrix_rows}}
    <tr>
      <th>Prob. {{this.likelihood_label}}</th>
      {{#each this.cells}}<td class="risk-cell risk-{{this.level}}">{{this.count}}</td>{{/each}}
    </tr>
    {{/each}}
  </table>
  {{/if}}

  <h3>Incidencias detectadas durante las pruebas</h3>
  {{#if has_incidents}}
  <div class="callout callout-warning">{{{incidents_html}}}</div>
  {{else}}
  <div class="callout callout-ok">No se registraron incidencias durante la ejecución de las pruebas.</div>
  {{/if}}
</div>

{{#if scope.show}}
<div id="alcance" class="section">
  <h2 class="section-title">Alcance y metodología</h2>
  {{#if scope.show_dates}}<p><strong>Ventana del engagement:</strong> {{scope.engagement_start}} &rarr; {{scope.engagement_end}}</p>{{/if}}
  {{#if scope.show_scope_in}}<h3>Dentro del alcance</h3><pre class="mono-block">{{scope.scope_in}}</pre>{{/if}}
  {{#if scope.show_scope_out}}<h3>Fuera del alcance</h3><pre class="mono-block">{{scope.scope_out}}</pre>{{/if}}
  {{#if scope.show_standards}}
  <h3>Metodologías y estándares</h3>
  <div class="tags">{{#each scope.standards}}<span class="tag">{{this.label}}</span>{{/each}}</div>
  {{/if}}
  {{#if scope.show_notes}}<h3>Notas de metodología</h3><div class="rich-text">{{{scope.methodology_notes_html}}}</div>{{/if}}
  {{#if scope.show_tools}}<h3>Herramientas utilizadas</h3><pre class="mono-block">{{scope.tools_used}}</pre>{{/if}}
</div>
{{/if}}

<div id="hallazgos" class="section">
  <h2 class="section-title">Hallazgos técnicos</h2>

  {{#each findings}}
  <div id="finding-{{this.index}}" class="finding sev-border-{{this.severity}}">
    <div class="finding-head">
      <div>
        <span class="finding-code">{{this.code}}</span>
        <h3>{{this.index1}}. {{this.title}}</h3>
      </div>
      <span class="badge sev-bg-{{this.severity}}">{{this.severity_label}}</span>
    </div>

    <div class="finding-meta-grid">
      <div class="finding-meta-item"><span>CVSS</span><strong>{{this.cvss}}</strong></div>
      <div class="finding-meta-item"><span>CVE</span><strong>{{this.cve}}</strong></div>
      <div class="finding-meta-item"><span>CWE</span><strong>{{this.cwe}}</strong></div>
      <div class="finding-meta-item"><span>Estado</span><strong>{{this.status_label}}</strong></div>
    </div>

    {{#if this.owasp_visible}}{{#if this.owasp}}<p><strong>OWASP:</strong> {{this.owasp}}</p>{{/if}}{{/if}}
    {{#if this.risk_visible}}{{#if this.likelihood}}<p><strong>Probabilidad × Impacto:</strong> {{this.likelihood_label}} × {{this.impact_rating_label}}</p>{{/if}}{{/if}}
    {{#if this.cvss_vector}}<p class="mono-inline">{{this.cvss_vector}}</p>{{/if}}
    {{#if this.affected_assets}}<p><strong>Activos afectados:</strong></p><pre class="mono-block">{{this.affected_assets}}</pre>{{/if}}

    {{#if this.description}}<h4>Descripción</h4><div class="rich-text">{{{this.description_html}}}</div>{{/if}}
    {{#if this.poc}}<h4>Pasos de reproducción (PoC)</h4><div class="code-block">{{{this.poc_html}}}</div>{{/if}}
    {{#if this.exploit}}<h4>Código / exploit</h4><pre class="mono-block">{{this.exploit}}</pre>{{/if}}

    {{#if this.images}}
    <h4>Evidencias</h4>
    <div class="evidence-grid">
      {{#each this.images}}
      <figure class="evidence">
        <img src="{{this}}" alt="evidencia {{@index1}}">
      </figure>
      {{/each}}
    </div>
    {{/if}}

    {{#if this.impact}}<h4>Impacto</h4><div class="rich-text">{{{this.impact_html}}}</div>{{/if}}
    {{#if this.remediation}}<div class="callout callout-ok"><h4>Solución recomendada</h4><div class="rich-text">{{{this.remediation_html}}}</div></div>{{/if}}

    {{#if this.compliance_visible}}{{#if this.compliance}}
    <div class="tags">{{#each this.compliance}}<span class="tag">{{this}}</span>{{/each}}</div>
    {{/if}}{{/if}}

    {{#if this.references}}
    <h4>Referencias</h4>
    <ul>{{#each this.references}}<li><a href="{{this}}" target="_blank">{{this}}</a></li>{{/each}}</ul>
    {{/if}}

    {{#if this.retest_visible}}{{#if this.retest_notes}}
    <div class="callout"><h4>Notas de re-test</h4><div class="rich-text">{{{this.retest_notes_html}}}</div></div>
    {{/if}}{{/if}}
  </div>
  {{/each}}
</div>

{{#if revision_history}}
<div class="section">
  <h2 class="section-title">Control de versiones</h2>
  <table class="revisions">
    <tr><th>Versión</th><th>Fecha</th><th>Autor</th><th>Cambios</th></tr>
    {{#each revision_history}}
    <tr><td>{{this.version}}</td><td>{{this.date}}</td><td>{{this.author}}</td><td>{{{this.changes_html}}}</td></tr>
    {{/each}}
  </table>
</div>
{{/if}}
`;

const DEFAULT_THEME_TEMPLATE_CSS = `/* Tema de ejemplo de Pwnly — edítalo libremente, es tuyo. */
body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; color: #1f2937; background: #fff; line-height: 1.6; margin: 0; }
h1, h2, h3, h4 { font-weight: 800; color: #111827; }
a { color: #2563eb; }

.cover { min-height: 90vh; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; gap: 1rem; padding: 3rem 2rem; page-break-after: always; }
.cover-logos { display: flex; gap: 1rem; margin-bottom: 1rem; }
.cover-logo { max-height: 90px; }
.cover-title { font-size: 2.6rem; margin: 0; max-width: 760px; }
.cover-target { font-size: 1.2rem; color: #2563eb; font-weight: 600; margin: 0; }
.cover-meta { display: flex; gap: 2rem; flex-wrap: wrap; justify-content: center; margin-top: 2rem; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 1.25rem 2rem; }
.cover-meta-label { display: block; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em; color: #6b7280; margin-bottom: 0.2rem; }

.badge { display: inline-block; padding: 0.3rem 0.8rem; border-radius: 6px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; color: #fff; }
.badge-classif { background: #475569; }
.sev-bg-crit { background: #dc2626; } .sev-bg-high { background: #f97316; } .sev-bg-med { background: #eab308; }
.sev-bg-low  { background: #22c55e; } .sev-bg-info { background: #6b7280; }
.sev-border-crit { border-left: 6px solid #dc2626; } .sev-border-high { border-left: 6px solid #f97316; }
.sev-border-med  { border-left: 6px solid #eab308; } .sev-border-low  { border-left: 6px solid #22c55e; }
.sev-border-info { border-left: 6px solid #6b7280; }

.toc { max-width: 820px; margin: 0 auto 3rem; padding: 0 1.5rem; page-break-after: always; }
.toc-item { display: flex; justify-content: space-between; align-items: center; gap: 1rem; padding: 0.65rem 0; border-bottom: 1px dotted #d1d5db; text-decoration: none; color: #1f2937; }

.section { max-width: 900px; margin: 0 auto 3rem; padding: 0 1.5rem; }
.section-title { border-bottom: 2px solid #e5e7eb; padding-bottom: 0.6rem; }

.summary-bar { display: flex; height: 26px; border-radius: 6px; overflow: hidden; margin: 1rem 0; background: #f1f5f9; }
.summary-bar-seg { height: 100%; }
.summary-legend { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 1.5rem; }
.legend-item { display: flex; align-items: center; gap: 0.4rem; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 0.4rem 0.8rem; font-size: 0.875rem; }
.legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }

.rich-text { line-height: 1.75; }
.callout { border-radius: 8px; padding: 1rem 1.25rem; border: 1px solid #e2e8f0; background: #f8fafc; margin: 1rem 0; }
.callout-ok { background: #f0fdf4; border-color: #bbf7d0; }
.callout-warning { background: #fff7ed; border-color: #fed7aa; }

.tags { display: flex; flex-wrap: wrap; gap: 0.4rem; }
.tag { background: rgba(37,99,235,0.1); color: #1d4ed8; border-radius: 999px; padding: 0.2rem 0.7rem; font-size: 0.78rem; font-weight: 600; }

.mono-block { font-family: ui-monospace, monospace; font-size: 0.85rem; white-space: pre-wrap; background: #0f172a; color: #e2e8f0; border-radius: 8px; padding: 1rem; }
.mono-inline { font-family: ui-monospace, monospace; font-size: 0.85rem; color: #475569; }
.code-block { font-family: ui-monospace, monospace; font-size: 0.85rem; background: #0f172a; color: #e2e8f0; border-radius: 8px; padding: 1rem; overflow-x: auto; }

.risk-matrix { border-collapse: collapse; margin: 1rem 0; }
.risk-matrix th, .risk-matrix td { border: 1px solid #e5e7eb; padding: 0.5rem 0.75rem; text-align: center; font-size: 0.85rem; }

.finding { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 1.75rem; margin-bottom: 2rem; page-break-inside: avoid; }
.finding-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; border-bottom: 1px solid #e5e7eb; padding-bottom: 1rem; margin-bottom: 1.25rem; }
.finding-head h3 { margin: 0.2rem 0 0; }
.finding-code { font-family: ui-monospace, monospace; font-size: 0.7rem; font-weight: 700; color: #6b7280; border: 1px solid #e5e7eb; border-radius: 5px; padding: 0.1rem 0.45rem; }
.finding-meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 1.25rem; }
.finding-meta-item { background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 8px; padding: 0.75rem 1rem; }
.finding-meta-item span { display: block; font-size: 0.7rem; text-transform: uppercase; color: #6b7280; margin-bottom: 0.2rem; }

.evidence-grid { display: grid; gap: 1rem; }
.evidence img { width: 100%; border-radius: 8px; border: 1px solid #e5e7eb; }

.revisions { width: 100%; border-collapse: collapse; }
.revisions th, .revisions td { border: 1px solid #e5e7eb; padding: 0.6rem 0.8rem; text-align: left; font-size: 0.875rem; }

@media print {
  .finding { page-break-inside: avoid; }
}
`;

// --------------------------------------------------------------------------- //
// Sistema de Temas: cada tema es una plantilla HTML + una hoja de CSS creadas
// íntegramente por el usuario (ver js/theme-engine.js para la sintaxis
// {{variable}} / {{#each}} / {{#if}}). No hay temas de fábrica: el informe no
// se puede generar hasta que exista al menos un tema. Los datos del reporte se
// exponen al motor de plantillas vía buildReportContext().
// --------------------------------------------------------------------------- //

function uniqueThemeSlug(name) {
    let base = (name || 'tema').toLowerCase()
        .normalize('NFD').replace(/[̀-ͯ]/g, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
    if (!base) base = 'tema';
    base = base.slice(0, 40);
    const existing = new Set((state.customThemes || []).map(t => t.slug).concat([BUILTIN_THEME_SLUG]));
    if (!existing.has(base)) return base;
    let i = 2;
    while (existing.has(`${base}-${i}`)) i++;
    return `${base}-${i}`;
}

async function loadCustomThemes() {
    try {
        state.customThemes = await API.themes.list();
    } catch (e) {
        state.customThemes = state.customThemes || [];
    }
}

// Tema por defecto (integrado): vive en el código, NO en la base de datos. Por
// eso siempre existe, no se puede borrar ni editar y no depende de nada que el
// usuario pueda romper. Es la referencia para crear temas nuevos (Duplicar) y
// el tema al que volver si uno propio sale mal.
const BUILTIN_THEME_SLUG = 'default';
function getBuiltinTheme() {
    return {
        id: null,
        slug: BUILTIN_THEME_SLUG,
        name: state.lang === 'es' ? 'Pwnly (por defecto)' : 'Pwnly (default)',
        html_template: DEFAULT_THEME_TEMPLATE_HTML,
        custom_css: DEFAULT_THEME_TEMPLATE_CSS,
        builtin: true
    };
}

// Siempre devuelve el tema por defecto primero y después los del usuario.
function listAllThemes() {
    const custom = (state.customThemes || []).slice().sort((a, b) => a.name.localeCompare(b.name));
    return [getBuiltinTheme(), ...custom];
}

function getActiveTheme() {
    return listAllThemes().find(t => t.slug === state.reportTheme) || getBuiltinTheme();
}

// Inyecta SOLO el CSS del tema activo (no todos a la vez: cada tema es CSS
// libre sin espacio de nombres, así que inyectar varios a la vez colisionaría).
function injectThemeStyles() {
    let style = document.getElementById('rt-theme-styles');
    if (!style) {
        style = document.createElement('style');
        style.id = 'rt-theme-styles';
        document.head.appendChild(style);
    }
    const theme = getActiveTheme();
    // El CSS del tema es del usuario y afecta SOLO al informe: se confina a
    // .preview-container para que nunca pueda tocar la interfaz de la app.
    style.textContent = theme ? scopeReportCss(theme.custom_css || '') : '';
}

// Confina el CSS de un tema de informe al contenedor del informe. Reglas
// :root/html/body pasan a ser el propio contenedor; @media/@supports se procesan
// recursivamente; @page/@font-face/@keyframes se dejan tal cual (son globales
// por naturaleza y no afectan a la interfaz).
const REPORT_SCOPE = '.preview-container';
function scopeReportCss(css) {
    if (!css || !css.trim()) return '';
    // En la vista de impresión/export la página ES el informe: CSS sin confinar
    // (así body/@page del tema controlan todo el PDF).
    if (new URLSearchParams(window.location.search).get('print_mode') === 'true') return css;
    const splitSelectors = (text) => {
        const out = []; let depth = 0, quote = '', cur = '';
        for (const ch of text) {
            if (quote) { cur += ch; if (ch === quote) quote = ''; continue; }
            if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
            if (ch === '(' || ch === '[') depth++;
            if (ch === ')' || ch === ']') depth--;
            if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
            cur += ch;
        }
        if (cur.trim()) out.push(cur);
        return out.map(s => s.trim()).filter(Boolean);
    };
    const scopeSelector = (sel) => {
        if (/^(\.preview-container|#_pdf_inner|\[data-rt-theme)/.test(sel)) return sel;
        const m = sel.match(/^(:root|html|body)(?![\w-])/i);
        if (m) return REPORT_SCOPE + sel.slice(m[0].length);
        return REPORT_SCOPE + ' ' + sel;
    };
    const walk = (rules) => {
        let out = '';
        for (const r of rules) {
            if (r.type === CSSRule.STYLE_RULE) {
                out += splitSelectors(r.selectorText).map(scopeSelector).join(', ') + ' { ' + r.style.cssText + ' }\n';
            } else if (r.cssRules && (r.type === CSSRule.MEDIA_RULE || r.type === CSSRule.SUPPORTS_RULE)) {
                const head = r.cssText.slice(0, r.cssText.indexOf('{')).trim();
                out += head + ' {\n' + walk(r.cssRules) + '}\n';
            } else if (r.type === CSSRule.IMPORT_RULE) {
                continue; // sin @import externos dentro de un tema
            } else {
                out += r.cssText + '\n';
            }
        }
        return out;
    };
    try {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync(css);
        return walk(sheet.cssRules);
    } catch (e) {
        return REPORT_SCOPE + ' {\n' + css + '\n}';
    }
}

function applyThemeAttributes(slug) {
    // El slug del tema solo se aplica al contenedor del informe (data-rt-theme en
    // .preview-container), nunca a <html>: tema de la app y tema del informe son independientes.
    document.documentElement.removeAttribute('data-rt-theme');
    injectThemeStyles();
}

function setReportTheme(slug) {
    if (!listAllThemes().some(t => t.slug === slug)) return;
    state.reportTheme = slug;
    applyThemeAttributes(slug);
    try { localStorage.setItem('pwnly_theme', slug); } catch (e) { /* almacenamiento no disponible */ }
    persistSettings();
    renderApp();
}

// --------------------------------------------------------------------------- //
// Página "Temas": listado + gestión. Vive como pestaña propia de la navbar,
// independiente del editor/preview del reporte.
// --------------------------------------------------------------------------- //
function showThemesPage() {
    state.showThemesPage = true;
    state.showReportSelector = false;
    renderApp();
    loadCustomThemes().then(renderApp);
}

function renderThemesPage() {
    if (!state.showThemesPage || state.showSplash) return '';
    const isEs = state.lang === 'es';
    const themes = listAllThemes();
    const lock = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
    const activeTheme = getActiveTheme();

    return `
        <div class="themes-page">
            <div class="themes-page-header">
                <div>
                    <h1>${isEs ? 'Temas del informe' : 'Report themes'}</h1>
                    <p class="themes-page-sub">${isEs
                        ? 'Los temas controlan solo el aspecto del informe (PDF/HTML). El tema por defecto siempre existe y es de solo lectura: úsalo como referencia, duplícalo para crear uno nuevo o vuelve a él si un tema tuyo sale mal.'
                        : 'Themes control only the look of the report (PDF/HTML). The default theme always exists and is read-only: use it as a reference, duplicate it to start a new one, or go back to it if one of yours turns out wrong.'}</p>
                </div>
                <button class="btn-primary" onclick="openThemeEditor(null)">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    ${isEs ? 'Nuevo tema' : 'New theme'}
                </button>
            </div>

            ${!activeTheme.builtin ? `
                <div class="themes-restore" role="status">
                    <span>${isEs ? 'Tema activo:' : 'Active theme:'} <strong>${escapeHTML(activeTheme.name)}</strong></span>
                    <button type="button" class="btn-sm btn-secondary" onclick="setReportTheme('${BUILTIN_THEME_SLUG}')">${isEs ? 'Volver al tema por defecto' : 'Back to the default theme'}</button>
                </div>` : ''}

            <div class="themes-grid">
                ${themes.map(th => {
                    const active = state.reportTheme === th.slug || (th.builtin && !listAllThemes().some(t => t.slug === state.reportTheme));
                    const nm = escapeHTML(th.name);
                    const slugAttr = escapeHTML(th.slug);
                    return `
                    <article class="theme-card2 ${active ? 'active' : ''} ${th.builtin ? 'builtin' : ''}" aria-label="${nm}">
                        <div class="theme-card2-thumb" aria-hidden="true">
                            <iframe tabindex="-1" sandbox title="" data-theme-thumb="${slugAttr}"></iframe>
                        </div>
                        <div class="theme-card2-head">
                            <span class="theme-card2-name">${nm}</span>
                            <span class="theme-card2-badges">
                                ${th.builtin ? `<span class="theme-card2-badge theme-card2-badge--ref">${lock}${isEs ? 'Por defecto' : 'Default'}</span>` : ''}
                                ${active ? `<span class="theme-card2-badge">${isEs ? 'Activo' : 'Active'}</span>` : ''}
                            </span>
                        </div>
                        ${th.builtin ? `<p class="theme-card2-note">${isEs ? 'Solo lectura. Referencia para crear nuevos temas.' : 'Read-only. Reference for creating new themes.'}</p>` : ''}
                        <div class="theme-card2-actions">
                            ${!active ? `<button class="btn-sm btn-primary" onclick="setReportTheme('${slugAttr}')" aria-label="${isEs ? 'Usar el tema' : 'Use theme'} ${nm}">${isEs ? 'Usar' : 'Use'}</button>` : ''}
                            ${!th.builtin ? `<button class="btn-sm btn-secondary" onclick="openThemeEditor('${slugAttr}')" aria-label="${isEs ? 'Editar el tema' : 'Edit theme'} ${nm}">${isEs ? 'Editar' : 'Edit'}</button>` : ''}
                            <button class="btn-sm btn-secondary" onclick="duplicateTheme('${slugAttr}')" aria-label="${isEs ? 'Duplicar el tema' : 'Duplicate theme'} ${nm}">${isEs ? 'Duplicar' : 'Duplicate'}</button>
                            <button class="btn-sm btn-secondary" onclick="exportTheme('${slugAttr}')" aria-label="${isEs ? 'Exportar el tema' : 'Export theme'} ${nm}">${isEs ? 'Exportar' : 'Export'}</button>
                            ${!th.builtin ? `<button class="btn-sm btn-danger" onclick="deleteCustomTheme(${th.id}, '${slugAttr}')" aria-label="${isEs ? 'Eliminar el tema' : 'Delete theme'} ${nm}">${isEs ? 'Eliminar' : 'Delete'}</button>` : ''}
                        </div>
                    </article>`;
                }).join('')}
            </div>

            <div class="themes-page-import">
                <label class="btn-secondary theme-import-label">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    ${isEs ? 'Importar tema (.html)' : 'Import theme (.html)'}
                    <input type="file" accept=".html,.htm,text/html" style="display:none" onchange="importThemeFile(this)">
                </label>
            </div>
        </div>
    `;
}

// Duplicar (también el tema por defecto): abre el editor con una copia nueva.
function duplicateTheme(slug) {
    const src = listAllThemes().find(t => t.slug === slug);
    if (!src) return;
    const isEs = state.lang === 'es';
    state.themeEditor = {
        slug: null,
        name: (src.builtin ? (isEs ? 'Mi tema' : 'My theme') : src.name + (isEs ? ' (copia)' : ' (copy)')),
        html: src.html_template || '',
        css: src.custom_css || '',
        isNew: true
    };
    state.themeEditorTab = 'html';
    state.isThemeStudio = true;
    renderApp();
    refreshThemeEditorPreview();
}

// Miniaturas reales de cada tema (iframe aislado y sin scripts, datos de ejemplo).
function renderThemeThumbs() {
    const frames = document.querySelectorAll('iframe[data-theme-thumb]');
    if (!frames.length) return;
    const ctx = buildSampleReportContext();
    const all = listAllThemes();
    frames.forEach(fr => {
        const th = all.find(t => t.slug === fr.dataset.themeThumb);
        if (!th) return;
        let body;
        try { body = ThemeEngine.render(th.html_template || '', ctx); } catch (e) { body = '<p style="padding:2rem;font-family:sans-serif;color:#b91c1c">Error en la plantilla</p>'; }
        fr.srcdoc = `<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0}body{overflow:hidden}</style><style>${th.custom_css || ''}</style></head><body>${body}</body></html>`;
        const box = fr.parentElement;
        const w = 820;
        fr.style.width = w + 'px';
        fr.style.height = '1160px';
        const s = (box.clientWidth || 260) / w;
        fr.style.transform = 'scale(' + s + ')';
    });
}

// --------------------------------------------------------------------------- //
// Editor de tema a página completa: dos áreas de código (HTML / CSS) + vista
// previa en vivo (iframe aislado) contra el reporte actual o datos de ejemplo.
// --------------------------------------------------------------------------- //
function openThemeEditor(slug) {
    const existing = slug ? (state.customThemes || []).find(t => t.slug === slug) : null;
    state.themeEditor = existing ? {
        slug: existing.slug,
        name: existing.name,
        html: existing.html_template || '',
        css: existing.custom_css || '',
        isNew: false
    } : {
        slug: null,
        name: '',
        html: DEFAULT_THEME_TEMPLATE_HTML,
        css: DEFAULT_THEME_TEMPLATE_CSS,
        isNew: true
    };
    state.themeEditorTab = 'html';
    state.isThemeStudio = true;
    renderApp();
    refreshThemeEditorPreview();
}

function closeThemeEditor() {
    state.isThemeStudio = false;
    state.themeEditor = null;
    renderApp();
}

function renderThemeStudio() {
    const ed = state.themeEditor;
    if (!ed) return '';
    const isEs = state.lang === 'es';
    const tab = state.themeEditorTab || 'html';

    return `
        <div class="theme-studio">
            <div class="theme-studio-header">
                <div class="ts-head-left">
                    <button class="account-back-btn" onclick="closeThemeEditor()">&larr; ${isEs ? 'Temas' : 'Themes'}</button>
                    <h1>${ed.isNew ? (isEs ? 'Nuevo tema' : 'New theme') : (isEs ? 'Editar tema' : 'Edit theme')}</h1>
                    <input type="text" class="ts-text" style="width:220px;" placeholder="${isEs ? 'Nombre del tema' : 'Theme name'}"
                        value="${escapeHTML(ed.name)}" oninput="themeEditorSetName(this.value)">
                </div>
                <div class="ts-head-actions">
                    <button class="btn-sm btn-secondary" onclick="themeEditorResetToDefault()" title="${isEs ? 'Reemplaza el HTML y el CSS por los del tema por defecto' : 'Replace HTML and CSS with the default theme'}">${isEs ? 'Restablecer al tema por defecto' : 'Reset to default theme'}</button>
                    <button class="btn-sm btn-secondary" onclick="closeThemeEditor()">${isEs ? 'Cancelar' : 'Cancel'}</button>
                    <button class="btn-sm btn-primary" onclick="saveThemeFromEditor()">${isEs ? 'Guardar' : 'Save'}</button>
                </div>
            </div>
            <div class="theme-studio-body">
                <div class="ts-controls ts-controls--code">
                    <div class="ts-tabs">
                        <button class="ts-tab ${tab === 'html' ? 'active' : ''}" onclick="themeEditorSetTab('html')">HTML</button>
                        <button class="ts-tab ${tab === 'css' ? 'active' : ''}" onclick="themeEditorSetTab('css')">CSS</button>
                    </div>
                    ${tab === 'html' ? `
                        <textarea class="ts-code ts-code--full" spellcheck="false"
                            oninput="themeEditorSetHtml(this.value)">${escapeHTML(ed.html)}</textarea>
                        <p class="ts-hint">${isEs
                            ? 'Plantilla del documento. Sintaxis: <code>{{variable}}</code>, <code>{{{html_sin_escapar}}}</code>, <code>{{#each lista}}...{{/each}}</code>, <code>{{#if cond}}...{{else}}...{{/if}}</code>.'
                            : 'Document template. Syntax: <code>{{variable}}</code>, <code>{{{unescaped_html}}}</code>, <code>{{#each list}}...{{/each}}</code>, <code>{{#if cond}}...{{else}}...{{/if}}</code>.'}</p>
                    ` : `
                        <textarea class="ts-code ts-code--full" spellcheck="false"
                            oninput="themeEditorSetCss(this.value)">${escapeHTML(ed.css)}</textarea>
                        <p class="ts-hint">${isEs ? 'CSS libre: sin espacio de nombres ni variables obligatorias, es tu CSS.' : 'Free CSS: no required namespace or variables, it is just your CSS.'}</p>
                    `}
                </div>
                <div class="ts-preview ts-preview--frame">
                    <p class="ts-preview-title">${isEs ? 'Vista previa en vivo' : 'Live preview'}</p>
                    <iframe id="theme-editor-preview-frame" class="ts-preview-iframe"></iframe>
                </div>
            </div>
        </div>
    `;
}

function themeEditorResetToDefault() {
    const isEs = state.lang === 'es';
    if (!state.themeEditor) return;
    if (!confirm(isEs ? 'Se reemplazará el HTML y el CSS de este tema por los del tema por defecto (aún no se guarda). ¿Continuar?' : 'This replaces this theme\'s HTML and CSS with the default theme (not saved yet). Continue?')) return;
    state.themeEditor.html = DEFAULT_THEME_TEMPLATE_HTML;
    state.themeEditor.css = DEFAULT_THEME_TEMPLATE_CSS;
    renderApp();
    refreshThemeEditorPreview();
}

function themeEditorSetName(v) {
    if (state.themeEditor) state.themeEditor.name = v;
}

function themeEditorSetHtml(v) {
    if (!state.themeEditor) return;
    state.themeEditor.html = v;
    _debounceThemePreview();
}

function themeEditorSetCss(v) {
    if (!state.themeEditor) return;
    state.themeEditor.css = v;
    _debounceThemePreview();
}

function themeEditorSetTab(tab) {
    state.themeEditorTab = tab;
    renderApp();
    refreshThemeEditorPreview();
}

let _themeEditorPreviewTimer = null;
function _debounceThemePreview() {
    clearTimeout(_themeEditorPreviewTimer);
    _themeEditorPreviewTimer = setTimeout(refreshThemeEditorPreview, 250);
}

function refreshThemeEditorPreview() {
    const frame = document.getElementById('theme-editor-preview-frame');
    if (!frame || !state.themeEditor) return;
    const isEs = state.lang === 'es';
    const ctx = (state.findings && state.findings.length > 0) ? buildReportContext() : buildSampleReportContext();
    let bodyHtml;
    try {
        bodyHtml = ThemeEngine.render(state.themeEditor.html, ctx);
    } catch (e) {
        bodyHtml = `<pre style="color:#dc2626;white-space:pre-wrap;padding:1.5rem;font-family:ui-monospace,monospace;">${escapeHTML((isEs ? 'Error en la plantilla: ' : 'Template error: ') + e.message)}</pre>`;
    }
    const doc = `<!doctype html><html><head><meta charset="utf-8"><style>${state.themeEditor.css || ''}</style></head><body>${bodyHtml}</body></html>`;
    frame.srcdoc = doc;
}

async function saveThemeFromEditor() {
    const ed = state.themeEditor;
    if (!ed) return;
    const isEs = state.lang === 'es';
    const name = (ed.name || '').trim();
    if (!name) {
        alert(isEs ? 'El nombre del tema no puede estar vacío' : 'Theme name cannot be empty');
        return;
    }
    const slug = ed.slug || uniqueThemeSlug(name);
    try {
        await API.themes.create({ slug, name, html_template: ed.html || '', custom_css: ed.css || '' });
        await loadCustomThemes();
        closeThemeEditor();
        state.showThemesPage = true;
        setReportTheme(slug);
    } catch (e) {
        alert((isEs ? 'Error al guardar el tema: ' : 'Error saving theme: ') + e.message);
    }
}

async function deleteCustomTheme(id, slug) {
    const isEs = state.lang === 'es';
    if (!confirm(isEs ? '¿Eliminar este tema? Esta acción no se puede deshacer.' : 'Delete this theme? This cannot be undone.')) return;
    try {
        await API.themes.delete(id);
        await loadCustomThemes();
        if (state.pdfPrintTheme === slug) state.pdfPrintTheme = BUILTIN_THEME_SLUG;
        if (state.reportTheme === slug) {
            state.reportTheme = BUILTIN_THEME_SLUG;
            applyThemeAttributes(state.reportTheme);
            persistSettings();
        }
        renderApp();
    } catch (e) {
        alert((isEs ? 'Error al eliminar: ' : 'Error deleting: ') + e.message);
    }
}

function _downloadText(text, filename, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
}

// Exporta el tema como un único .html autocontenido: el CSS en un <style> y el
// HTML de la plantilla dentro de un <template> (inerte: se puede abrir en el
// navegador sin que el motor de temas se ejecute). Pensado para reimportarse
// con "Importar tema" o editarse a mano y volver a subirlo.
function exportTheme(slug) {
    const th = listAllThemes().find(t => t.slug === slug);
    if (!th) return;
    const bundle = `<!doctype html>
<!--
  Tema de Pwnly -- "${th.name}"
  Para importarlo de nuevo: Temas -> Importar tema (.html) y selecciona este archivo.
  Puedes editar el CSS y el HTML de abajo directamente antes de volver a importarlo.
-->
<html data-pwnly-theme-name="${escapeHTML(th.name)}">
<head>
<meta charset="utf-8">
<title>${escapeHTML(th.name)} — Tema Pwnly</title>
<style id="pwnly-theme-css">
${th.custom_css || ''}
</style>
</head>
<body>
<template id="pwnly-theme-html">
${th.html_template || ''}
</template>
</body>
</html>
`;
    _downloadText(bundle, `pwnly-tema-${slug}.html`, 'text/html');
}

function parseThemeBundle(text) {
    const doc = new DOMParser().parseFromString(text, 'text/html');
    const titleText = doc.querySelector('title') ? doc.querySelector('title').textContent : '';
    const name = (doc.documentElement.getAttribute('data-pwnly-theme-name') || titleText.replace(/ — Tema Pwnly$/, '')).trim();
    const cssEl = doc.getElementById('pwnly-theme-css');
    const htmlEl = doc.getElementById('pwnly-theme-html');
    return {
        name,
        css: cssEl ? cssEl.textContent : '',
        html: htmlEl ? htmlEl.innerHTML : ''
    };
}

async function importThemeFile(input) {
    const file = input.files && input.files[0];
    if (!file) return;
    const isEs = state.lang === 'es';
    const text = await file.text();
    let parsed;
    try {
        parsed = parseThemeBundle(text);
        if (!parsed.html && !parsed.css) throw new Error('empty');
    } catch (e) {
        alert(isEs ? 'No se pudo leer el archivo de tema.' : 'Could not read the theme file.');
        input.value = '';
        return;
    }
    const name = parsed.name || file.name.replace(/\.html?$/i, '');
    const slug = uniqueThemeSlug(name);
    try {
        await API.themes.create({ slug, name, html_template: parsed.html, custom_css: parsed.css });
        await loadCustomThemes();
        renderApp();
    } catch (e) {
        alert((isEs ? 'Error al importar: ' : 'Error importing: ') + e.message);
    }
    input.value = '';
}

// --------------------------------------------------------------------------- //
// Calculadora CVSS 3.1 (independiente del sistema de temas)
// --------------------------------------------------------------------------- //
const CVSS_METRIC_DEFS = [
    { id: 'AV', es: 'Vector de ataque', en: 'Attack Vector', opts: [['N', 'Red'], ['A', 'Adyacente'], ['L', 'Local'], ['P', 'Físico']], optsEn: [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']] },
    { id: 'AC', es: 'Complejidad', en: 'Attack Complexity', opts: [['L', 'Baja'], ['H', 'Alta']], optsEn: [['L', 'Low'], ['H', 'High']] },
    { id: 'PR', es: 'Privilegios req.', en: 'Privileges Required', opts: [['N', 'Ninguno'], ['L', 'Bajos'], ['H', 'Altos']], optsEn: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
    { id: 'UI', es: 'Interacción usuario', en: 'User Interaction', opts: [['N', 'Ninguna'], ['R', 'Requerida']], optsEn: [['N', 'None'], ['R', 'Required']] },
    { id: 'S', es: 'Alcance (Scope)', en: 'Scope', opts: [['U', 'Sin cambio'], ['C', 'Cambiado']], optsEn: [['U', 'Unchanged'], ['C', 'Changed']] },
    { id: 'C', es: 'Confidencialidad', en: 'Confidentiality', opts: [['N', 'Ninguno'], ['L', 'Bajo'], ['H', 'Alto']], optsEn: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
    { id: 'I', es: 'Integridad', en: 'Integrity', opts: [['N', 'Ninguno'], ['L', 'Bajo'], ['H', 'Alto']], optsEn: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
    { id: 'A', es: 'Disponibilidad', en: 'Availability', opts: [['N', 'Ninguno'], ['L', 'Bajo'], ['H', 'Alto']], optsEn: [['N', 'None'], ['L', 'Low'], ['H', 'High']] }
];

function cvssRoundUp(x) {
    // Roundup oficial CVSS 3.1: menor decimal (1 cifra) >= x, evitando errores float.
    const i = Math.round(x * 100000);
    if (i % 10000 === 0) return i / 100000;
    return (Math.floor(i / 10000) + 1) / 10;
}

function computeCvss(m) {
    const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
    const AC = { L: 0.77, H: 0.44 }[m.AC];
    const PR = (m.S === 'C')
        ? { N: 0.85, L: 0.68, H: 0.50 }[m.PR]
        : { N: 0.85, L: 0.62, H: 0.27 }[m.PR];
    const UI = { N: 0.85, R: 0.62 }[m.UI];
    const cia = { N: 0, L: 0.22, H: 0.56 };
    const C = cia[m.C], I = cia[m.I], A = cia[m.A];

    const iscBase = 1 - ((1 - C) * (1 - I) * (1 - A));
    let impact;
    if (m.S === 'C') {
        impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
    } else {
        impact = 6.42 * iscBase;
    }
    const exploitability = 8.22 * AV * AC * PR * UI;

    let score;
    if (impact <= 0) {
        score = 0;
    } else if (m.S === 'C') {
        score = cvssRoundUp(Math.min(1.08 * (impact + exploitability), 10));
    } else {
        score = cvssRoundUp(Math.min(impact + exploitability, 10));
    }
    const vector = `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
    return { score: score.toFixed(1), vector };
}

function cvssSeverityKey(score) {
    const s = parseFloat(score);
    if (s >= 9.0) return 'crit';
    if (s >= 7.0) return 'high';
    if (s >= 4.0) return 'med';
    if (s > 0.0) return 'low';
    return 'info';
}

function parseCvssVector(vec) {
    const m = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' };
    if (!vec) return m;
    vec.split('/').forEach(part => {
        const [k, v] = part.split(':');
        if (k in m && v) m[k] = v;
    });
    return m;
}

function openCvssCalc() {
    state.cvssMetrics = parseCvssVector(state.currentFinding.cvssVector);
    state.showCvssCalc = true;
    renderApp();
}

function closeCvssCalc() {
    state.showCvssCalc = false;
    renderApp();
}

function cvssSetMetric(id, val) {
    state.cvssMetrics[id] = val;
    const r = computeCvss(state.cvssMetrics);
    // Actualiza marca de score y botones activos sin re-render completo.
    const badge = document.getElementById('cvss-live-score');
    const vecEl = document.getElementById('cvss-live-vector');
    const sevKey = cvssSeverityKey(r.score);
    const colorMap = { crit: '#dc2626', high: '#f97316', med: '#eab308', low: '#22c55e', info: '#6b7280' };
    if (badge) {
        badge.textContent = r.score;
        const box = document.getElementById('cvss-score-box');
        if (box) box.style.background = colorMap[sevKey];
    }
    if (vecEl) vecEl.textContent = r.vector;
    // Refresca botones del grupo modificado.
    CVSS_METRIC_DEFS.forEach(def => {
        if (def.id !== id) return;
        def.opts.forEach(([code]) => {
            const b = document.getElementById(`cvss-opt-${def.id}-${code}`);
            if (b) b.classList.toggle('active', code === val);
        });
    });
    // Si cambia S, recalcular PR no es necesario en UI (PR sigue igual), pero el score sí cambia.
}

function applyCvssCalc() {
    const r = computeCvss(state.cvssMetrics);
    state.currentFinding.cvss = r.score;
    state.currentFinding.cvssVector = r.vector;
    state.currentFinding.severity = cvssSeverityKey(r.score);
    state.showCvssCalc = false;
    renderApp();
}

function renderCvssCalcModal() {
    if (!state.showCvssCalc) return '';
    const isEs = state.lang === 'es';
    const m = state.cvssMetrics;
    const r = computeCvss(m);
    const sevKey = cvssSeverityKey(r.score);
    const colorMap = { crit: '#dc2626', high: '#f97316', med: '#eab308', low: '#22c55e', info: '#6b7280' };
    const sevLabel = UI[state.lang].severityLevels[sevKey];

    const groups = CVSS_METRIC_DEFS.map(def => {
        const opts = isEs ? def.opts : def.optsEn;
        return `
            <div class="cvss-metric">
                <span>${isEs ? def.es : def.en}</span>
                <div class="cvss-metric-opts">
                    ${opts.map(([code, label]) => `
                        <button type="button" id="cvss-opt-${def.id}-${code}" class="cvss-opt ${m[def.id] === code ? 'active' : ''}" onclick="cvssSetMetric('${def.id}','${code}')">${label}</button>
                    `).join('')}
                </div>
            </div>`;
    }).join('');

    return `
        <div class="settings-overlay" style="align-items:center;justify-content:center;padding:1rem;" onclick="closeCvssCalc()">
            <div class="settings-modal" style="width:100%;max-width:640px;display:flex;flex-direction:column;max-height:92vh;" onclick="event.stopPropagation()">
                <div class="settings-modal-header">
                    <span>${isEs ? 'Calculadora CVSS 3.1' : 'CVSS 3.1 Calculator'}</span>
                    <button class="settings-close-btn" onclick="closeCvssCalc()">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </div>
                <div style="padding:1.25rem;overflow-y:auto;">
                    <div class="cvss-score-badge" id="cvss-score-box" style="background:${colorMap[sevKey]};color:#fff;">
                        <span class="cvss-score-num" id="cvss-live-score">${r.score}</span>
                        <div>
                            <div style="font-weight:800;text-transform:uppercase;font-size:0.8rem;letter-spacing:0.05em;">${sevLabel}</div>
                            <div id="cvss-live-vector" style="font-family:ui-monospace,Menlo,monospace;font-size:0.72rem;opacity:0.9;word-break:break-all;">${r.vector}</div>
                        </div>
                    </div>
                    <div class="cvss-calc-grid">
                        ${groups}
                    </div>
                    <div style="display:flex;gap:0.5rem;justify-content:flex-end;margin-top:1.25rem;">
                        <button class="btn-secondary" onclick="closeCvssCalc()">${isEs ? 'Cancelar' : 'Cancel'}</button>
                        <button class="btn-primary" onclick="applyCvssCalc()">${isEs ? 'Aplicar al hallazgo' : 'Apply to finding'}</button>
                    </div>
                </div>
            </div>
        </div>`;
}

// Campos del alcance que se imprimen en el informe. El engagement no tiene
// interruptor (siempre se muestra si hay fechas); el resto son opt-in por campo.
// No hay interruptor de sección: la sección aparece si hay algún campo visible
// con contenido. Usado por buildReportContext() para la sección de alcance.
function scopeSectionVisibleFields(d) {
    const std = d.methodologyStandards || [];
    const stdLabels = METHODOLOGY_STANDARDS.filter(s => std.includes(s.key)).map(s => s.label);
    const fv = d.scopeFieldsVisibility || {};
    const fvis = (key) => !!fv[key];
    return {
        stdLabels,
        showDates:    !!(d.engagementStart || d.engagementEnd),
        showScopeIn:  fvis('scopeIn') && !!d.scopeIn,
        showScopeOut: fvis('scopeOut') && !!d.scopeOut,
        showStd:      fvis('standards') && stdLabels.length > 0,
        showNotes:    fvis('methodologyNotes') && !!d.methodologyNotes,
        showTools:    fvis('toolsUsed') && !!d.toolsUsed,
    };
}

function scopeSectionHasContent(d) {
    const s = scopeSectionVisibleFields(d);
    return !!(s.showDates || s.showScopeIn || s.showScopeOut || s.showStd || s.showNotes || s.showTools);
}

// --------------------------------------------------------------------------- //
// Datos del reporte expuestos al motor de plantillas (ThemeEngine). Acepta
// overrides opcionales (auditData/findings/showBars) para poder construir un
// contexto de EJEMPLO sin depender del estado global (ver buildSampleReportContext).
// --------------------------------------------------------------------------- //
function buildReportContext(auditDataParam, findingsParam, showBarsParam) {
    const d = auditDataParam || state.auditData;
    const findingsSrc = findingsParam || state.findings;
    const showBars = (typeof showBarsParam === 'boolean') ? showBarsParam : !!state.pdfShowSeverityBars;
    const t = UI[state.lang];
    const isEs = state.lang === 'es';
    const riskLbl = (k) => (t.riskLevels || {})[k] || k || '';

    const classLabels = {
        '1': isEs ? 'Público' : 'Public',
        '2': isEs ? 'Interno' : 'Internal',
        '3': isEs ? 'Confidencial' : 'Confidential',
        '4': isEs ? 'Restringido' : 'Restricted'
    };

    const severityOrderKeys = ['crit', 'high', 'med', 'low', 'info'];
    const severityCounts = { crit: 0, high: 0, med: 0, low: 0, info: 0 };
    findingsSrc.forEach(f => { severityCounts[safeSeverity(f.severity)]++; });
    const totalFindings = findingsSrc.length;
    const severityBreakdown = severityOrderKeys.map(k => ({
        key: k,
        label: t.severityLevels[k],
        count: severityCounts[k],
        percent: totalFindings ? Math.round((severityCounts[k] / totalFindings) * 1000) / 10 : 0
    }));

    // Matriz de riesgo Probabilidad x Impacto (sólo cuenta hallazgos con el
    // metadato de riesgo activado; si falta probabilidad/impacto, se infiere
    // de la severidad).
    const sevToRisk = { crit: ['high', 'high'], high: ['high', 'med'], med: ['med', 'med'], low: ['low', 'med'], info: ['low', 'low'] };
    const riskOrder = ['high', 'med', 'low'];
    const cellCounts = {};
    riskOrder.forEach(lk => riskOrder.forEach(im => { cellCounts[lk + '_' + im] = 0; }));
    let riskMatrixHasData = false;
    findingsSrc.forEach(f => {
        if (!getFindingFieldVis(f, 'risk')) return;
        let lk = f.likelihood, im = f.impactRating || f.impact_rating;
        if (!lk || !im) {
            const dd = sevToRisk[safeSeverity(f.severity)] || ['med', 'med'];
            lk = lk || dd[0]; im = im || dd[1];
        }
        const key = lk + '_' + im;
        if (cellCounts[key] !== undefined) { cellCounts[key]++; riskMatrixHasData = true; }
    });
    const weight = { high: 3, med: 2, low: 1 };
    const riskMatrixRows = riskOrder.map(lk => ({
        likelihood: lk,
        likelihood_label: riskLbl(lk),
        cells: riskOrder.map(im => {
            const score = weight[lk] * weight[im];
            return {
                impact: im,
                impact_label: riskLbl(im),
                count: cellCounts[lk + '_' + im],
                level: score >= 9 ? 'critical' : score >= 6 ? 'high' : score >= 3 ? 'medium' : 'low'
            };
        })
    }));

    // Alcance y metodología
    const scopeVis = scopeSectionVisibleFields(d);
    const standards = METHODOLOGY_STANDARDS.filter(s => (d.methodologyStandards || []).includes(s.key));

    const findings = findingsSrc.map((f, idx) => {
        const sev = safeSeverity(f.severity);
        const likelihood = f.likelihood || '';
        const impactRating = f.impactRating || f.impact_rating || '';
        const retestNotes = f.retestNotes || f.retest_notes || '';
        return {
            index: idx,
            index1: idx + 1,
            code: 'F-' + String(idx + 1).padStart(2, '0'),
            title: f.title || '',
            severity: sev,
            severity_label: t.severityLevels[sev],
            cvss: f.cvss || '',
            cvss_vector: f.cvssVector || f.cvss_vector || '',
            cve: f.cve || '',
            cwe: f.cwe || '',
            reference: f.reference || '',
            references: Array.isArray(f.references) ? f.references : [],
            description: f.description || '',
            description_html: markdownToHtml(f.description || ''),
            poc: f.poc || '',
            poc_html: markdownToHtml(f.poc || ''),
            exploit: f.exploit || '',
            impact: f.impact || '',
            impact_html: markdownToHtml(f.impact || ''),
            remediation: f.remediation || '',
            remediation_html: markdownToHtml(f.remediation || ''),
            images: Array.isArray(f.images) ? f.images : [],
            image_captions: Array.isArray(f.imageCaptions || f.image_captions) ? (f.imageCaptions || f.image_captions) : [],
            status: f.status || 'open',
            status_label: (t.findingStatuses || {})[f.status || 'open'] || f.status || '',
            affected_assets: f.affectedAssets || f.affected_assets || '',
            likelihood,
            likelihood_label: likelihood ? riskLbl(likelihood) : '',
            impact_rating: impactRating,
            impact_rating_label: impactRating ? riskLbl(impactRating) : '',
            risk_visible: getFindingFieldVis(f, 'risk'),
            owasp: f.owasp || '',
            owasp_visible: getFindingFieldVis(f, 'owasp'),
            compliance: Array.isArray(f.compliance) ? f.compliance : [],
            compliance_visible: getFindingFieldVis(f, 'compliance'),
            retest_notes: retestNotes,
            retest_notes_html: markdownToHtml(retestNotes),
            retest_visible: getFindingFieldVis(f, 'retest')
        };
    });

    return {
        lang: state.lang,
        document_title: d.documentTitle || '',
        client_company: d.clientCompany || '',
        client_logo: Array.isArray(d.clientLogo) ? d.clientLogo.filter(Boolean) : [],
        target_asset: d.targetAsset || '',
        auditor_company: d.auditorCompany || '',
        auditor_name: d.auditorName || '',
        auditor_phone: d.auditorPhone || d.auditor_phone || '',
        auditor_email: d.auditorEmail || d.auditor_email || '',
        classification: d.classification || '2',
        classification_label: classLabels[d.classification] || classLabels['2'],
        version: d.version || '',
        date: d.date || '',
        audit_type: d.auditType || '',
        audit_type_label: (t.auditTypes || {})[d.auditType] || d.auditType || '',

        has_incidents: !!d.hasIncidents,
        incidents_text: d.incidentsText || '',
        incidents_html: markdownToHtml(d.incidentsText || ''),

        audit_summary: d.auditSummary || '',
        audit_summary_html: markdownToHtml(d.auditSummary || ''),
        tests_performed: d.testsPerformed || '',
        tests_performed_html: markdownToHtml(d.testsPerformed || ''),
        recommended_solutions: d.recommendedSolutions || '',
        recommended_solutions_html: markdownToHtml(d.recommendedSolutions || ''),

        scope: {
            show: scopeSectionHasContent(d),
            show_dates: scopeVis.showDates,
            engagement_start: d.engagementStart || '',
            engagement_end: d.engagementEnd || '',
            show_scope_in: scopeVis.showScopeIn,
            scope_in: d.scopeIn || '',
            show_scope_out: scopeVis.showScopeOut,
            scope_out: d.scopeOut || '',
            show_standards: scopeVis.showStd,
            standards,
            show_notes: scopeVis.showNotes,
            methodology_notes: d.methodologyNotes || '',
            methodology_notes_html: markdownToHtml(d.methodologyNotes || ''),
            show_tools: scopeVis.showTools,
            tools_used: d.toolsUsed || ''
        },

        revision_history: (d.revisionHistory || [])
            .filter(r => r.version || r.date || r.author || r.changes)
            .map(r => ({
                version: r.version || '', date: r.date || '', author: r.author || '',
                changes: r.changes || '', changes_html: markdownToHtml(r.changes || '')
            })),

        findings_count: totalFindings,
        severity_counts: severityCounts,
        severity_breakdown: severityBreakdown,
        show_severity_bars: showBars,

        risk_matrix_rows: riskMatrixRows,
        risk_matrix_has_data: riskMatrixHasData,

        findings
    };
}

// Contexto de EJEMPLO para que el editor de temas tenga algo que previsualizar
// sin depender de un reporte real abierto.
function buildSampleReportContext() {
    const isEs = state.lang === 'es';
    const today = new Date().toISOString().split('T')[0];
    const sampleFindings = [
        {
            title: isEs ? 'Inyección SQL en el formulario de login' : 'SQL Injection in the login form',
            severity: 'crit', cvss: '9.8', cwe: 'CWE-89',
            description: isEs
                ? 'El parámetro `usuario` no sanea la entrada antes de construir la consulta SQL, permitiendo un bypass de autenticación.'
                : 'The `user` parameter is not sanitized before building the SQL query, allowing an authentication bypass.',
            poc: '```\n\' OR \'1\'=\'1\n```',
            impact: isEs ? 'Un atacante no autenticado puede acceder a cualquier cuenta de la plataforma.' : 'An unauthenticated attacker can access any account on the platform.',
            remediation: isEs ? 'Usar siempre consultas parametrizadas (prepared statements).' : 'Always use parameterized queries (prepared statements).',
            images: [], likelihood: 'high', impactRating: 'high', owasp: 'A03:2021',
            fieldsVisibility: { risk: true, owasp: true }
        },
        {
            title: isEs ? 'Cabeceras de seguridad ausentes' : 'Missing security headers',
            severity: 'med', cvss: '5.3', cwe: 'CWE-693',
            description: isEs
                ? 'La aplicación no envía `Content-Security-Policy` ni `X-Frame-Options`.'
                : 'The application does not send `Content-Security-Policy` or `X-Frame-Options`.',
            impact: isEs ? 'Aumenta la superficie de ataque frente a XSS y clickjacking.' : 'Increases the attack surface for XSS and clickjacking.',
            remediation: isEs ? 'Añadir las cabeceras recomendadas por OWASP Secure Headers.' : 'Add the headers recommended by OWASP Secure Headers.',
            images: [], likelihood: 'med', impactRating: 'med',
            fieldsVisibility: { risk: true }
        },
        {
            title: isEs ? 'Versión de servidor desactualizada' : 'Outdated server version',
            severity: 'low', cvss: '3.1',
            description: isEs
                ? 'El servidor expone una versión de nginx con vulnerabilidades públicas de baja severidad.'
                : 'The server exposes an nginx version with publicly known low-severity vulnerabilities.',
            remediation: isEs ? 'Actualizar a la última versión estable.' : 'Update to the latest stable version.',
            images: [], likelihood: 'low', impactRating: 'low',
            fieldsVisibility: { risk: true }
        }
    ];
    const sampleAuditData = {
        documentTitle: isEs ? 'Informe de Pentesting — Demo' : 'Pentesting Report — Demo',
        clientCompany: isEs ? 'Empresa Cliente Demo S.A.' : 'Demo Client Company Inc.',
        clientLogo: ['', ''],
        targetAsset: 'https://demo.example.com',
        auditorCompany: 'Pwnly Security Lab',
        auditorName: isEs ? 'Equipo de Auditoría' : 'Audit Team',
        classification: '2',
        version: '1.0',
        date: today,
        auditType: 'pentesting_web',
        hasIncidents: false,
        incidentsText: '',
        auditSummary: isEs
            ? 'Durante la auditoría se identificaron 3 hallazgos (1 crítico, 1 medio, 1 bajo). El hallazgo crítico permite un bypass de autenticación completo y debe remediarse con prioridad máxima.'
            : 'During the audit, 3 findings were identified (1 critical, 1 medium, 1 low). The critical finding allows a full authentication bypass and must be remediated with top priority.',
        testsPerformed: '',
        recommendedSolutions: '',
        scopeIn: 'https://demo.example.com\n192.168.1.0/24',
        scopeOut: isEs ? 'Infraestructura de terceros' : 'Third-party infrastructure',
        methodologyNotes: '',
        methodologyStandards: ['owasp_wstg', 'ptes'],
        toolsUsed: 'Burp Suite, nmap, sqlmap',
        engagementStart: today,
        engagementEnd: today,
        revisionHistory: [{ version: '1.0', date: today, author: isEs ? 'Equipo de Auditoría' : 'Audit Team', changes: isEs ? 'Versión inicial' : 'Initial version' }],
        scopeFieldsVisibility: { scopeIn: true, scopeOut: true, standards: true, toolsUsed: true }
    };
    return buildReportContext(sampleAuditData, sampleFindings, true);
}

// --------------------------------------------------------------------------- //
// Renderizado del informe: compila la plantilla HTML del tema activo contra
// buildReportContext() con el motor de ThemeEngine. Sin tema activo, se
// muestra un estado vacío invitando a crear uno en "Temas".
// --------------------------------------------------------------------------- //
function renderPreview() {
    if (state.activeTab !== 'preview' || state.showSplash || state.showReportSelector) return '';
    const isEs = state.lang === 'es';
    const _cw = state.pdfContentWidth || 820;
    const theme = getActiveTheme();

    const ctx = buildReportContext();
    let bodyHtml;
    try {
        bodyHtml = ThemeEngine.render(theme.html_template || '', ctx);
    } catch (e) {
        bodyHtml = `<pre style="color:#dc2626;white-space:pre-wrap;padding:1.5rem;font-family:ui-monospace,monospace;">${escapeHTML((isEs ? 'Error en la plantilla del tema: ' : 'Theme template error: ') + e.message)}</pre>`;
    }

    return `<div class="preview-container" data-rt-theme="${escapeHTML(theme.slug)}" style="max-width:${_cw}px;">${bodyHtml}</div>`;
}


function renderReportsPage() {
    if (!state.showReportSelector || state.showSplash) return '';

    const t = UI[state.lang];
    const bk = _bk();

    return `
        <div class="reports-page">
            <div class="reports-header">
                <h1>${t.myReports}</h1>
                <div class="reports-actions">
                    <button class="btn-secondary" onclick="showDemoModal()">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                            <line x1="8" y1="21" x2="16" y2="21"/>
                            <line x1="12" y1="17" x2="12" y2="21"/>
                        </svg>
                        ${t.generateDemoDb}
                    </button>
                    <button class="btn-secondary" onclick="openBackupExport()">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="7 10 12 15 17 10"/>
                            <line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                        ${bk.exportBtn}
                    </button>
                    <button class="btn-secondary" onclick="document.getElementById('backup-import-input').click()">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="17 8 12 3 7 8"/>
                            <line x1="12" y1="3" x2="12" y2="15"/>
                        </svg>
                        ${bk.importBtn}
                    </button>
                    <input type="file" id="backup-import-input" accept=".zip,.enc,application/zip" style="display:none" onchange="pickBackupFile(this)" aria-label="${bk.importBtn}">
                </div>
            </div>

            <div class="reports-list">
                ${state.savedReports.length === 0 ? `
                    <div class="empty-state">
                        <p>${t.noReports}</p>
                        <p class="text-muted">${t.noReportsDesc}</p>
                    </div>
                ` : state.savedReports.map(r => `
                    <div class="report-card" onclick="loadReport(${r.id})">
                        <div class="report-card-actions" onclick="event.stopPropagation()">
                            <button class="report-card-icon-btn danger" title="${state.lang === 'es' ? 'Eliminar reporte' : 'Delete report'}" onclick="deleteReport(${r.id})">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                            </button>
                        </div>
                        <h3>${escapeHTML(r.document_title)}</h3>
                        <p>${escapeHTML(r.client_company)}</p>
                        <span>${r.findings_count || 0} ${state.lang === 'es' ? 'hallazgos' : 'findings'}</span>
                    </div>
                `).join('')}
            </div>

            <footer class="made-by-footer">
                <span>${state.lang === 'es' ? 'Un proyecto hecho con' : 'A project made with'}</span>
                <svg class="made-by-heart" width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-label="${state.lang === 'es' ? 'amor' : 'love'}">
                    <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/>
                </svg>
                <span>${state.lang === 'es' ? 'por' : 'by'}</span>
                <a href="https://www.linkedin.com/in/maalfer1/" target="_blank" rel="noopener noreferrer">Mario Álvarez</a>
            </footer>
        </div>
    `;
}

function renderSettingsModal() {
    if (!state.showSettings) return '';
    const isEs = state.lang === 'es';

    return `
        <div class="settings-overlay" onclick="closeSettings()">
            <div class="settings-modal" onclick="event.stopPropagation()">
                <div class="settings-modal-header">
                    <span>${isEs ? 'Ajustes' : 'Settings'}</span>
                    <button class="settings-close-btn" onclick="closeSettings()">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </div>

                <div class="settings-section">
                    <p class="settings-section-title">${isEs ? 'Idioma de la interfaz' : 'Interface language'}</p>
                    <div class="settings-option-row">
                        <button class="settings-lang-btn ${isEs ? 'selected' : ''}" onclick="setLang('es')">
                            <span class="settings-lang-flag">🇪🇸</span>
                            <span>Español</span>
                            ${isEs ? `<svg class="settings-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>` : ''}
                        </button>
                        <button class="settings-lang-btn ${!isEs ? 'selected' : ''}" onclick="setLang('en')">
                            <span class="settings-lang-flag">🇬🇧</span>
                            <span>English</span>
                            ${!isEs ? `<svg class="settings-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>` : ''}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function renderDemoModal() {
    if (!state.showDemoModal) return '';
    const t = UI[state.lang];
    const isEs = state.lang === 'es';

    return `
        <div class="settings-overlay" style="align-items:center;justify-content:center;padding:1rem;" onclick="closeDemoModal()">
            <div class="settings-modal" style="width:100%;max-width:520px;transform-origin:center center;" onclick="event.stopPropagation()">
                <div class="settings-modal-header">
                    <span>${t.demoModalTitle}</span>
                    <button class="settings-close-btn" onclick="closeDemoModal()">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </div>
                <div class="settings-modal-body" style="padding:1.5rem;">
                    <p style="color:var(--text-muted,#64748b);line-height:1.6;margin-bottom:1.25rem;">${t.demoModalDesc}</p>

                    <div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.3);border-radius:8px;padding:0.875rem 1rem;margin-bottom:1.25rem;display:flex;gap:0.75rem;align-items:flex-start;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                        <p style="color:#f59e0b;font-size:0.875rem;margin:0;line-height:1.5;">${t.demoModalWarning}</p>
                    </div>

                    <p style="font-weight:700;font-size:0.875rem;margin-bottom:0.75rem;">${t.demoModalWhat}</p>
                    <ul style="list-style:none;padding:0;margin:0 0 1.75rem;display:flex;flex-direction:column;gap:0.5rem;">
                        ${t.demoModalItems.map(item => `
                            <li style="display:flex;align-items:flex-start;gap:0.6rem;font-size:0.875rem;color:var(--text-muted,#64748b);">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2.5" style="flex-shrink:0;margin-top:1px;"><polyline points="20 6 9 17 4 12"/></svg>
                                ${escapeHTML(item)}
                            </li>
                        `).join('')}
                    </ul>

                    <div style="display:flex;gap:0.75rem;justify-content:flex-end;">
                        <button class="btn-secondary" onclick="closeDemoModal()" style="min-width:90px;">${t.demoModalCancel}</button>
                        <button class="btn-primary" id="demo-generate-btn" onclick="loadDemoReport()" style="min-width:140px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                                <line x1="8" y1="21" x2="16" y2="21"/>
                                <line x1="12" y1="17" x2="12" y2="21"/>
                            </svg>
                            ${t.demoModalGenerate}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function showDemoModal() {
    state.showDemoModal = true;
    renderApp();
}

function closeDemoModal() {
    state.showDemoModal = false;
    renderApp();
}

async function loadDemoReport() {
    const btn = document.getElementById('demo-generate-btn');
    const t = UI[state.lang];
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<svg class="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> ${t.demoModalGenerating}`;
    }
    try {
        const result = await fetch('/api/demo/create', { method: 'POST' });
        if (!result.ok) {
            const err = await result.json().catch(() => ({}));
            throw new Error(err.detail || result.statusText);
        }
        const data = await result.json();
        state.showDemoModal = false;
        await loadReport(data.report_id);
    } catch (e) {
        alert((state.lang === 'es' ? 'Error al crear demo: ' : 'Error creating demo: ') + e.message);
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg> ${t.demoModalGenerate}`;
        }
    }
}

function renderPdfModal() {
    if (!state.showPdfModal) return '';
    const t = UI[state.lang];
    const isEs = state.lang === 'es';
    // Estilos de la propia ventana del modal (chrome de la app): fijos, no
    // dependen del tema del informe (cada tema es CSS 100% libre del usuario).
    const c = { border: '#3a3a40', cardBg: '#1c1c1f', textMuted: '#a1a1aa', textFaint: '#8b8b95', textHeading: '#fafafa' };
    const themes = listAllThemes();

    function themeCard(th) {
        const active = state.pdfPrintTheme === th.slug;
        return `<button id="pdf-theme-btn-${escapeHTML(th.slug)}" onclick="pdfModalSetTheme('${th.slug}')"
            style="flex:1 1 auto;min-width:110px;padding:0.6rem 0.75rem;border-radius:10px;text-align:left;
                   border:2px solid ${active ? '#3b82f6' : c.border};
                   background:${active ? '#3b82f6' : c.cardBg};
                   color:${active ? '#ffffff' : c.textMuted};
                   cursor:pointer;font-weight:${active ? '700' : '500'};font-size:0.825rem;transition:all 0.15s;">
            ${escapeHTML(th.name)}
        </button>`;
    }

    const toggleOn  = state.pdfShowSeverityBars;
    const toggleBg  = toggleOn ? '#3b82f6' : c.border;
    const thumbLeft = toggleOn ? '22px' : '2px';
    const panelBg   = '#111113';
    const dotMuted  = '#71717a';

    return `
        <div class="settings-overlay" style="align-items:center;justify-content:center;padding:1rem;" onclick="closePdfModal()">
            <div class="settings-modal" style="width:100%;max-width:860px;display:flex;flex-direction:column;max-height:90vh;" onclick="event.stopPropagation()">

                <!-- Header -->
                <div class="settings-modal-header" style="flex-shrink:0;">
                    <div style="display:flex;align-items:center;gap:0.5rem;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                        <span>${t.pdfModalTitle}</span>
                    </div>
                    <button class="settings-close-btn" onclick="closePdfModal()">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </div>

                <!-- Two-column body -->
                <div style="display:flex;min-height:0;flex:1;overflow:hidden;">

                    <!-- LEFT: Controls -->
                    <div style="width:272px;flex-shrink:0;border-right:1px solid ${c.border};padding:1.375rem;display:flex;flex-direction:column;gap:1.25rem;overflow-y:auto;">

                        <!-- Theme -->
                        <div>
                            <p style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:${c.textMuted};margin-bottom:0.625rem;">${t.pdfModalTheme}</p>
                            ${themes.length === 0 ? `
                                <p style="font-size:0.8rem;color:${c.textFaint};margin:0;">${isEs ? 'Usando el tema por defecto. Crea el tuyo en "Temas" para personalizarlo.' : 'Using the default theme. Create your own in "Themes" to customize it.'}</p>
                            ` : `
                                <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
                                    ${themes.map(themeCard).join('')}
                                </div>
                            `}
                        </div>

                        <div style="border-top:1px solid ${c.border};"></div>

                        <!-- Severity bars -->
                        <div style="display:flex;justify-content:space-between;align-items:center;gap:0.75rem;">
                            <div style="min-width:0;">
                                <p style="font-weight:600;font-size:0.875rem;color:${c.textHeading};margin-bottom:0.2rem;">${t.pdfModalSeverityBars}</p>
                                <p style="font-size:0.775rem;color:${c.textFaint};margin:0;line-height:1.4;">${t.pdfModalSeverityBarsDesc}</p>
                            </div>
                            <label style="position:relative;display:inline-flex;align-items:center;cursor:pointer;flex-shrink:0;">
                                <input type="checkbox" style="opacity:0;position:absolute;width:0;height:0;" ${toggleOn ? 'checked' : ''} onchange="pdfModalSetBars(this.checked)">
                                <div id="pdf-toggle-bg" style="width:44px;height:24px;background:${toggleBg};border-radius:12px;position:relative;transition:background 0.2s;">
                                    <div id="pdf-toggle-thumb" style="position:absolute;top:2px;left:${thumbLeft};width:20px;height:20px;background:white;border-radius:50%;transition:left 0.2s;box-shadow:0 1px 3px rgba(0,0,0,0.25);"></div>
                                </div>
                            </label>
                        </div>

                        <div style="border-top:1px solid ${c.border};"></div>

                        <!-- Content width -->
                        <div>
                            <p style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:${c.textMuted};margin-bottom:0.25rem;">${t.pdfModalContentWidth}</p>
                            <p style="font-size:0.75rem;color:${c.textFaint};margin:0 0 0.875rem;line-height:1.4;">${t.pdfModalContentWidthDesc}</p>
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.375rem;">
                                <span style="font-size:0.8rem;color:${c.textFaint};">${t.pdfModalContentWidthNarrow}</span>
                                <span id="pdf-content-width-val" style="font-size:0.875rem;font-weight:700;color:#3b82f6;">${state.pdfContentWidth} px</span>
                                <span style="font-size:0.8rem;color:${c.textFaint};">${t.pdfModalContentWidthWide}</span>
                            </div>
                            <input type="range" min="580" max="1100" step="20" value="${state.pdfContentWidth}"
                                oninput="pdfModalSetContentWidth(this.value)"
                                style="width:100%;accent-color:#3b82f6;cursor:pointer;">
                        </div>

                        <!-- Spacer + Buttons -->
                        <div style="flex:1;min-height:0.5rem;"></div>
                        <div style="display:flex;flex-direction:column;gap:0.5rem;">
                            <button class="btn-primary" id="pdf-confirm-btn" onclick="executePdfGeneration()" style="width:100%;justify-content:center;gap:0.5rem;">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                                ${t.pdfModalGenerate}
                            </button>
                            <button class="btn-secondary" onclick="closePdfModal()" style="width:100%;justify-content:center;">${t.pdfModalCancel}</button>
                        </div>
                    </div>

                    <!-- RIGHT: Live preview -->
                    <div style="flex:1;background:${panelBg};overflow:hidden;position:relative;min-height:480px;">
                        <div style="position:absolute;top:0;left:0;right:0;height:28px;display:flex;align-items:center;padding:0 0.75rem;gap:0.35rem;z-index:5;">
                            <div style="width:8px;height:8px;border-radius:50%;background:#ef4444;opacity:0.7;"></div>
                            <div style="width:8px;height:8px;border-radius:50%;background:#f59e0b;opacity:0.7;"></div>
                            <div style="width:8px;height:8px;border-radius:50%;background:#22c55e;opacity:0.7;"></div>
                            <span style="margin-left:0.375rem;font-size:0.67rem;font-weight:600;color:${dotMuted};text-transform:uppercase;letter-spacing:0.06em;">Vista Previa</span>
                        </div>
                        <div id="pdf-preview-panel" style="position:absolute;inset:0;top:28px;overflow-y:auto;overflow-x:hidden;">
                            ${renderPdfPreviewHtml(state.pdfPrintTheme, state.pdfShowSeverityBars, state.pdfContentWidth)}
                        </div>
                    </div>

                </div>
            </div>
        </div>
    `;
}

function openPdfModal() {
    // Usamos las preferencias persistidas en la BD (no reseteamos en cada apertura),
    // salvo que el tema de PDF guardado ya no exista: caemos al tema activo del informe.
    if (!listAllThemes().some(t => t.slug === state.pdfPrintTheme)) {
        state.pdfPrintTheme = state.reportTheme;
    }
    state.showPdfModal = true;
    renderApp();
}

function closePdfModal() {
    state.showPdfModal = false;
    renderApp();
}

function pdfModalSetTheme(theme) {
    state.pdfPrintTheme = theme;
    const border = '#3a3a40', cardBg = '#1c1c1f', textMuted = '#a1a1aa';
    listAllThemes().forEach(th => {
        const btn = document.getElementById('pdf-theme-btn-' + th.slug);
        if (!btn) return;
        const isActive = th.slug === theme;
        btn.style.background  = isActive ? '#3b82f6' : cardBg;
        btn.style.borderColor = isActive ? '#3b82f6' : border;
        btn.style.color       = isActive ? '#ffffff' : textMuted;
        btn.style.fontWeight  = isActive ? '700'      : '500';
    });
    persistSettings();
    updatePdfModalPreview();
}

function pdfModalSetBars(checked) {
    state.pdfShowSeverityBars = checked;
    const border = '#3a3a40';
    const bg    = document.getElementById('pdf-toggle-bg');
    const thumb = document.getElementById('pdf-toggle-thumb');
    if (bg)    bg.style.background = checked ? '#3b82f6' : border;
    if (thumb) thumb.style.left    = checked ? '22px'   : '2px';
    persistSettings();
    updatePdfModalPreview();
}

let _pdfWidthTimer = null;

function pdfModalSetContentWidth(v) {
    state.pdfContentWidth = parseInt(v);
    const el = document.getElementById('pdf-content-width-val');
    if (el) el.textContent = v + ' px';
    persistSettings();
    clearTimeout(_pdfWidthTimer);
    _pdfWidthTimer = setTimeout(updatePdfModalPreview, 200);
}

function updatePdfModalPreview() {
    const panel = document.getElementById('pdf-preview-panel');
    if (!panel) return;
    panel.innerHTML = renderPdfPreviewHtml(state.pdfPrintTheme, state.pdfShowSeverityBars, state.pdfContentWidth);
}

function renderPdfPreviewHtml(previewTheme, showBars, contentWidth) {
    const saved = {
        reportTheme:          state.reportTheme,
        pdfShowSeverityBars:  state.pdfShowSeverityBars,
        pdfContentWidth:      state.pdfContentWidth,
        activeTab:            state.activeTab,
        showSplash:           state.showSplash,
        showReportSelector:   state.showReportSelector,
    };

    state.reportTheme        = previewTheme;
    state.pdfShowSeverityBars = showBars;
    state.pdfContentWidth    = contentWidth || 820;
    state.activeTab          = 'preview';
    state.showSplash         = false;
    state.showReportSelector = false;

    const html = renderPreview();

    state.reportTheme        = saved.reportTheme;
    state.pdfShowSeverityBars = saved.pdfShowSeverityBars;
    state.pdfContentWidth    = saved.pdfContentWidth;
    state.activeTab          = saved.activeTab;
    state.showSplash         = saved.showSplash;
    state.showReportSelector = saved.showReportSelector;

    const ZOOM = 0.42;

    // El fondo real lo pone el CSS propio del tema (ya inyectado globalmente
    // por injectThemeStyles); aquí sólo evitamos bordes/sombra duplicados en
    // la miniatura.
    return `
        <style>
            #_pdf_inner .preview-container {
                border-radius: 0 !important;
                box-shadow: none !important;
                margin: 0 auto !important;
            }
        </style>
        <div data-rt-theme="${escapeHTML(previewTheme)}">
            <div id="_pdf_inner" data-rt-theme="${escapeHTML(previewTheme)}" style="zoom:${ZOOM};">
                ${html}
            </div>
        </div>`;
}

function renderLogin() {
    const t = UI[state.lang];
    return `
        <div class="login-screen">
            <div class="login-card">
                <div class="login-brand">
                    <img src="/assets/logo-transparent.png" alt="Pwnly">
                    <div>
                        <h1>${t.appTitle}</h1>
                        <p>${t.loginSubtitle}</p>
                    </div>
                </div>

                <form onsubmit="doLogin(event)" autocomplete="on">
                    <label class="login-label">${t.loginUser}</label>
                    <input type="text" id="loginUsername" class="login-input" autocomplete="username"
                           value="${escapeHTML(state.loginUsername)}" oninput="state.loginUsername = this.value" autofocus>

                    <label class="login-label">${t.loginPass}</label>
                    <input type="password" id="loginPassword" class="login-input" autocomplete="current-password"
                           value="${escapeHTML(state.loginPassword)}" oninput="state.loginPassword = this.value">

                    ${state.loginError ? `<div class="login-error">${escapeHTML(state.loginError)}</div>` : ''}

                    <button type="submit" class="login-btn" ${state.loginLoading ? 'disabled' : ''}>
                        ${state.loginLoading ? t.loginLoading : t.loginBtn}
                    </button>
                </form>

                ${state.showDefaultCredsHint ? `
                <div class="login-default-creds">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                    <span>${t.defaultCredsHint}
                        <code>${t.defaultCredsUserLabel}: admin</code>
                        <code>${t.defaultCredsPassLabel}: admin</code>
                    </span>
                </div>` : ''}

                <div class="login-version">v${APP_VERSION}</div>
            </div>
        </div>
    `;
}

function renderSetup() {
    const t = UI[state.lang];
    return `
        <div class="login-screen">
            <div class="login-card">
                <div class="login-brand">
                    <img src="/assets/logo-transparent.png" alt="Pwnly">
                    <div>
                        <h1>${t.setupTitle}</h1>
                        <p>${t.setupSubtitle}</p>
                    </div>
                </div>

                <form onsubmit="doSetup(event)" autocomplete="off">
                    <label class="login-label">${t.loginUser}</label>
                    <input type="text" id="setupUsername" class="login-input" autocomplete="username"
                           value="${escapeHTML(state.setupUsername)}" oninput="state.setupUsername = this.value" autofocus>

                    <label class="login-label">${t.loginPass}</label>
                    <input type="password" id="setupPassword" class="login-input" autocomplete="new-password"
                           value="${escapeHTML(state.setupPassword)}" oninput="state.setupPassword = this.value">

                    ${state.setupError ? `<div class="login-error">${escapeHTML(state.setupError)}</div>` : ''}

                    <button type="submit" class="login-btn" ${state.setupLoading ? 'disabled' : ''}>
                        ${state.setupLoading ? t.setupLoading : t.setupBtn}
                    </button>
                </form>

                <div class="login-version">v${APP_VERSION}</div>
            </div>
        </div>
    `;
}

function renderAccountPage() {
    const t = UI[state.lang];

    // Cualquier usuario —incluido el propio— se puede eliminar mientras quede al
    // menos otro registrado. Si sólo hay uno, no se muestra el botón de borrar.
    const canDelete = state.users.length > 1;
    const userRows = state.users.length
        ? state.users.map(u => {
            const isSelf = u.username === state.authUsername;
            return `
                <div class="account-user-row">
                    <div class="account-user-info">
                        <span class="account-user-avatar">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                        </span>
                        <span class="account-user-name">${escapeHTML(u.username)}</span>
                        ${isSelf ? `<span class="account-user-badge">${t.youLabel}</span>` : ''}
                    </div>
                    ${canDelete
                        ? `<button class="account-user-delete" onclick="deleteUser(${u.id})" title="${t.deleteLabel}">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                           </button>`
                        : ''
                    }
                </div>`;
        }).join('')
        : `<p class="account-empty">${t.noUsers}</p>`;

    return `
        <div class="account-page">
            <header class="account-header">
                <div class="account-header-brand">
                    <img src="/assets/logo-transparent.png" alt="Pwnly">
                    <div>
                        <h1>${t.accountTitle}</h1>
                        <p>${t.accountSubtitle}</p>
                    </div>
                </div>
                <div class="account-header-actions">
                    <a class="account-back-btn" href="/">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                        ${t.backToApp}
                    </a>
                    <button class="profile-logout-btn" onclick="doLogout()">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                        ${t.logout}
                    </button>
                </div>
            </header>

            <div class="account-container">
                <div class="account-card">
                    <div class="account-signed-in">
                        <span class="account-user-avatar account-user-avatar--lg">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                        </span>
                        <div>
                            <span class="account-signed-in-label">${t.signedInAs}</span>
                            <strong>${escapeHTML(state.authUsername)}</strong>
                        </div>
                    </div>
                </div>

                <div class="account-grid">
                    <div class="account-card">
                        <h2 class="account-section-title">${t.changePassword}</h2>
                        <form onsubmit="doChangePassword(event)" class="profile-form">
                            <label class="login-label">${t.currentPassword}</label>
                            <input type="password" id="currentPassword" class="login-input" autocomplete="current-password">

                            <label class="login-label">${t.newPassword}</label>
                            <input type="password" id="newPassword" class="login-input" autocomplete="new-password">

                            <label class="login-label">${t.confirmPassword}</label>
                            <input type="password" id="confirmPassword" class="login-input" autocomplete="new-password">

                            ${state.profileError ? `<div class="login-error">${escapeHTML(state.profileError)}</div>` : ''}
                            ${state.profileSuccess ? `<div class="login-success">${escapeHTML(state.profileSuccess)}</div>` : ''}

                            <button type="submit" class="login-btn" style="margin-top:0.85rem;">${t.savePassword}</button>
                        </form>
                    </div>

                    <div class="account-card">
                        <h2 class="account-section-title">${t.manageUsers}</h2>

                        <p class="account-shared-note">${t.sharedDataNote}</p>

                        <p class="account-subsection-title">${t.existingUsers}${state.users.length ? `<span class="account-user-count">${state.users.length}</span>` : ''}</p>
                        <div class="account-user-list">
                            ${userRows}
                        </div>

                        <div class="account-divider"></div>

                        <p class="account-subsection-title">${t.createUser}</p>
                        <form onsubmit="createUser(event)">
                            <label class="login-label">${t.loginUser}</label>
                            <input type="text" id="newUserName" class="login-input" autocomplete="off">

                            <label class="login-label">${t.loginPass}</label>
                            <input type="password" id="newUserPassword" class="login-input" autocomplete="new-password">

                            ${state.userMgmtError ? `<div class="login-error">${escapeHTML(state.userMgmtError)}</div>` : ''}
                            ${state.userMgmtSuccess ? `<div class="login-success">${escapeHTML(state.userMgmtSuccess)}</div>` : ''}

                            <button type="submit" class="login-btn" style="margin-top:0.85rem;">${t.createUserBtn}</button>
                        </form>
                    </div>
                </div>

                ${renderApiSection()}

            </div>
        </div>
    `;
}

// Sustituye las imágenes data URL (base64) por un marcador para que el código
// fuente sea legible (si no, cada evidencia añadiría megas de base64).
function reportSourceForView(html) {
    return html.replace(
        /(data:image\/[a-zA-Z0-9.+-]+;base64,)[A-Za-z0-9+/=\s]+/g,
        '$1…(base64 de la imagen omitido en la vista de código)…'
    );
}

function setPreviewView(mode) {
    state.previewSourceView = (mode === 'source');
    renderApp();
}

async function copyReportSource() {
    const isEs = state.lang === 'es';
    try {
        await navigator.clipboard.writeText(renderPreview());
        alert(isEs ? 'Código fuente copiado al portapapeles' : 'Source code copied to clipboard');
    } catch (e) {
        alert((isEs ? 'No se pudo copiar: ' : 'Could not copy: ') + e.message);
    }
}

// Pestaña "Vista Previa": añade un selector para alternar entre el reporte
// renderizado y su código fuente HTML. La barra es no-print y se omite en modo
// impresión (PDF / exportación HTML) para no contaminar el documento final.
function renderPreviewArea() {
    if (state.activeTab !== 'preview' || state.showSplash || state.showReportSelector || state.showThemesPage) return '';

    const reportHtml = renderPreview();

    const printMode = new URLSearchParams(window.location.search).get('print_mode') === 'true';
    if (printMode) return reportHtml; // exportación/impresión: solo el reporte

    const isEs = state.lang === 'es';
    const src = !!state.previewSourceView;

    // Conmutador discreto (segmentado) alineado a la derecha sobre el informe.
    const toolbar = `
        <div class="preview-view-switch no-print">
            <div class="preview-view-seg" role="tablist">
                <button class="${!src ? 'active' : ''}" onclick="setPreviewView('rendered')" title="${isEs ? 'Vista renderizada' : 'Rendered view'}">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/></svg>
                    <span>${isEs ? 'Renderizado' : 'Rendered'}</span>
                </button>
                <button class="${src ? 'active' : ''}" onclick="setPreviewView('source')" title="${isEs ? 'Código fuente HTML' : 'HTML source'}">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                    <span>${isEs ? 'Código' : 'Source'}</span>
                </button>
            </div>
            ${src ? `<button class="preview-view-copy" onclick="copyReportSource()" title="${isEs ? 'Copiar código' : 'Copy source'}">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>` : ''}
        </div>`;

    if (!src) return toolbar + reportHtml;

    const code = escapeHTML(reportSourceForView(reportHtml));
    const sourceView = `
        <div class="no-print" style="max-width:980px;margin:0 auto;background:#0d1117;border:1px solid #1e293b;border-radius:10px;overflow:hidden;">
            <div style="padding:0.6rem 1rem;border-bottom:1px solid #1e293b;color:#93c5fd;font-family:ui-monospace,monospace;font-size:0.75rem;">
                ${isEs ? 'Código fuente del reporte (HTML)' : 'Report source code (HTML)'}
            </div>
            <pre style="margin:0;padding:1.1rem;overflow:auto;max-height:75vh;"><code style="font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:0.78rem;line-height:1.6;color:#e2e8f0;white-space:pre;">${code}</code></pre>
        </div>`;

    return toolbar + sourceView;
}

function renderApp() {
    const app = $('#app');

    // Mientras no se haya comprobado la sesión, no pintamos nada (evita parpadeo
    // del login antes de validar la cookie existente).
    if (!state.authChecked) {
        app.innerHTML = '';
        return;
    }

    // Puerta de autenticación: sin sesión válida sólo se muestra el login,
    // salvo en el primer arranque (sin usuarios), donde se pide crear la cuenta.
    if (!state.isAuthenticated) {
        app.innerHTML = state.needsSetup ? renderSetup() : renderLogin();
        return;
    }

    // Página de cuenta / gestión de usuarios (se abre en pestaña nueva con ?account=1).
    if (state.isAccountView) {
        app.innerHTML = renderAccountPage();
        return;
    }

    // Estudio de temas a página completa.
    if (state.isThemeStudio && state.themeEditor) {
        app.innerHTML = renderThemeStudio();
        return;
    }

    app.innerHTML = `
        ${renderSplashScreen()}
        ${renderNavbar()}
        <main class="main-content">
            ${renderReportsPage()}
            ${renderThemesPage()}
            ${renderEditor()}
            ${renderPreviewArea()}
        </main>
        ${renderSettingsModal()}
        ${renderCvssCalcModal()}
        ${renderDemoModal()}
        ${renderPdfModal()}
        ${renderBackupModal()}
        ${renderRevisionModal()}
        ${renderPasswordWarningModal()}
    `;
    postRenderEditor();
    renderThemeThumbs();
}

// Aviso al entrar con las credenciales por defecto (admin/admin). El usuario
// puede ir directo a cambiar la contraseña o cerrarlo si no le interesa.
function renderPasswordWarningModal() {
    if (!state.usingDefaultPassword || state.passwordWarningDismissed) return '';
    const t = UI[state.lang];
    return `
        <div class="settings-overlay pw-warn-overlay" style="align-items:center;justify-content:center;padding:1rem;" onclick="if(event.target===this)dismissPasswordWarning()">
            <div class="settings-modal pw-warn-modal" style="width:100%;max-width:440px;" role="alertdialog" aria-modal="true" onclick="event.stopPropagation()">
                <div class="settings-modal-header">
                    <span style="display:inline-flex;align-items:center;gap:0.5rem;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
                        ${t.pwWarnTitle}
                    </span>
                    <button class="settings-close-btn" onclick="dismissPasswordWarning()" aria-label="${t.pwWarnDismiss}">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </div>
                <div class="settings-section">
                    <p style="font-size:0.88rem;color:var(--gray-500,#6b7280);line-height:1.6;margin:0 0 1.1rem;">
                        ${t.pwWarnBody}
                    </p>
                    <div style="display:flex;gap:0.6rem;">
                        <button type="button" class="btn-secondary" style="flex:1;" onclick="dismissPasswordWarning()">${t.pwWarnDismiss}</button>
                        <button type="button" class="login-btn" style="flex:1;margin:0;" onclick="goToChangePassword()">${t.pwWarnCta}</button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function dismissPasswordWarning() {
    state.passwordWarningDismissed = true;
    renderApp();
}

// Lleva al usuario a la página de cuenta, donde está el formulario de cambio de
// contraseña. Cerramos antes el modal para no arrastrarlo a la nueva vista.
function goToChangePassword() {
    state.passwordWarningDismissed = true;
    window.location.href = '/?account=1';
}

// --------------------------------------------------------------------------- //
// Handlers de autenticación
// --------------------------------------------------------------------------- //
async function doLogin(event) {
    if (event) event.preventDefault();
    if (state.loginLoading) return;
    const t = UI[state.lang];

    state.loginError = '';
    state.loginLoading = true;
    renderApp();

    try {
        const result = await API.auth.login({
            username: state.loginUsername,
            password: state.loginPassword
        });
        state.isAuthenticated = true;
        state.authUsername = result.username;
        state.loginPassword = '';
        state.loginError = '';
        // Si se entra con la contraseña por defecto, mostramos el aviso al entrar.
        state.usingDefaultPassword = !!result.using_default_password;
        state.passwordWarningDismissed = false;
        // Tras iniciar sesión cargamos los temas personalizados y aplicamos el
        // tema guardado (la cookie no existía durante el arranque inicial).
        await loadCustomThemes();
        const savedTheme = localStorage.getItem('pwnly_theme');
        state.reportTheme = (savedTheme && listAllThemes().some(t => t.slug === savedTheme)) ? savedTheme : BUILTIN_THEME_SLUG;
        await loadSettings();
        applyThemeAttributes(state.reportTheme);
        // Si se inició sesión directamente en la página de cuenta, cargamos usuarios.
        if (state.isAccountView) {
            await loadUsers();
        }
    } catch (err) {
        state.loginError = (state.lang === 'es'
            ? 'Usuario o contraseña incorrectos'
            : 'Invalid username or password');
    } finally {
        state.loginLoading = false;
        renderApp();
    }
}

async function doSetup(event) {
    if (event) event.preventDefault();
    if (state.setupLoading) return;

    state.setupError = '';
    state.setupLoading = true;
    renderApp();

    try {
        const result = await API.auth.setup({
            username: (state.setupUsername || '').trim(),
            password: state.setupPassword || ''
        });
        // Cuenta creada: la respuesta deja la sesión iniciada (cookie). Entramos.
        state.needsSetup = false;
        state.isAuthenticated = true;
        state.authUsername = result.username;
        state.setupPassword = '';
        state.setupUsername = '';
        state.setupError = '';
        await loadCustomThemes();
        const savedTheme = localStorage.getItem('pwnly_theme');
        state.reportTheme = (savedTheme && listAllThemes().some(t => t.slug === savedTheme)) ? savedTheme : BUILTIN_THEME_SLUG;
        await loadSettings();
        applyThemeAttributes(state.reportTheme);
        if (state.isAccountView) {
            await loadUsers();
        }
    } catch (err) {
        state.setupError = err.message && !err.message.startsWith('HTTP ')
            ? err.message
            : UI[state.lang].setupError;
    } finally {
        state.setupLoading = false;
        renderApp();
    }
}

async function doLogout() {
    try {
        await API.auth.logout();
    } catch (e) { /* la cookie se limpia igualmente */ }
    state.isAuthenticated = false;
    state.showProfile = false;
    state.authUsername = '';
    state.loginUsername = '';
    state.loginPassword = '';
    state.usingDefaultPassword = false;
    state.passwordWarningDismissed = false;
    // Refrescamos la pista de credenciales por si cambió desde el último login.
    await refreshDefaultCredsHint();
    renderApp();
}

// Consulta al backend si el admin sigue con la contraseña por defecto para
// decidir si mostrar la pista bajo el formulario de login.
async function refreshDefaultCredsHint() {
    try {
        const res = await API.auth.defaultCredentials();
        state.showDefaultCredsHint = !!(res && res.default_admin);
    } catch (e) {
        state.showDefaultCredsHint = false;
    }
}

// El perfil ahora vive en una página propia que se abre en una pestaña nueva.
function openProfile() {
    window.open('/?account=1', '_blank');
}

// --------------------------------------------------------------------------- //
// Gestión de usuarios (página de cuenta)
// --------------------------------------------------------------------------- //
async function loadUsers() {
    try {
        state.users = await API.users.list();
    } catch (e) {
        state.users = [];
    }
}

async function createUser(event) {
    if (event) event.preventDefault();
    const username = (($('#newUserName') || {}).value || '').trim();
    const password = ($('#newUserPassword') || {}).value || '';

    state.userMgmtError = '';
    state.userMgmtSuccess = '';

    try {
        await API.users.create({ username, password });
        state.userMgmtSuccess = UI[state.lang].userCreated;
        await loadUsers();
    } catch (err) {
        state.userMgmtError = err.message && !err.message.startsWith('HTTP ')
            ? err.message
            : (state.lang === 'es' ? 'No se pudo crear el usuario' : 'Could not create user');
    }
    renderApp();
}

async function deleteUser(userId) {
    const t = UI[state.lang];
    // El nombre se resuelve desde el estado (no se interpola en el handler inline)
    // para evitar inyección de JavaScript a través del username.
    const target = state.users.find(u => u.id === userId);
    const username = target ? target.username : '';
    if (!confirm(`${t.confirmDeleteUser} "${username}"?`)) return;

    state.userMgmtError = '';
    state.userMgmtSuccess = '';

    try {
        const result = await API.users.delete(userId);
        // Si se eliminó la propia cuenta, la sesión deja de ser válida: cerramos
        // sesión en el cliente y volvemos al login.
        if (result && result.deleted_self) {
            state.isAuthenticated = false;
            state.authUsername = '';
            state.users = [];
            renderApp();
            return;
        }
        state.userMgmtSuccess = t.userDeleted;
        await loadUsers();
    } catch (err) {
        state.userMgmtError = err.message && !err.message.startsWith('HTTP ')
            ? err.message
            : (state.lang === 'es' ? 'No se pudo eliminar el usuario' : 'Could not delete user');
    }
    renderApp();
}

// --------------------------------------------------------------------------- //
// API / Integraciones — gestión de API keys y referencia REST
// --------------------------------------------------------------------------- //
async function loadApiKeys() {
    try {
        state.apiKeys = await API.apiKeys.list();
    } catch (e) {
        state.apiKeys = [];
    }
}

async function createApiKey(event) {
    if (event) event.preventDefault();
    const isEs = state.lang === 'es';
    const label = (state.apiKeyLabel || '').trim() || 'API Key';

    state.apiError = '';
    const btn = document.getElementById('api-generate-btn');
    if (btn) { btn.disabled = true; btn.textContent = UI[state.lang].apiGenerating; }

    try {
        const result = await API.apiKeys.create({ label });
        state.apiNewKey = result;
        state.apiKeyLabel = '';
        await loadApiKeys();
    } catch (err) {
        state.apiError = (err.message && !err.message.startsWith('HTTP '))
            ? err.message
            : (isEs ? 'Error al generar la API key' : 'Error generating API key');
    }
    renderApp();
}

async function revokeApiKey(keyId) {
    const t = UI[state.lang];
    if (!confirm(t.apiRevokeConfirm)) return;
    state.apiError = '';
    try {
        await API.apiKeys.delete(keyId);
        if (state.apiNewKey && state.apiNewKey.id === keyId) state.apiNewKey = null;
        await loadApiKeys();
    } catch (err) {
        state.apiError = (err.message && !err.message.startsWith('HTTP '))
            ? err.message
            : t.apiError;
    }
    renderApp();
}

async function copyText(elementId, btn) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.tagName === 'TEXTAREA' || el.tagName === 'INPUT' ? el.value : el.textContent;
    try {
        await navigator.clipboard.writeText(text || '');
        if (btn) {
            const orig = btn.textContent;
            btn.textContent = UI[state.lang].apiCopied || '✓';
            setTimeout(() => { if (btn) btn.textContent = orig; }, 2000);
        }
    } catch (e) {
        alert((state.lang === 'es' ? 'No se pudo copiar: ' : 'Could not copy: ') + e.message);
    }
}

function renderApiSection() {
    const t = UI[state.lang];
    const baseUrl = window.location.origin;

    // Lista de claves existentes
    const keyRows = state.apiKeys.length
        ? state.apiKeys.map(k => {
            const created = new Date(k.created_at).toLocaleDateString();
            const lastUsed = k.last_used_at
                ? new Date(k.last_used_at).toLocaleDateString()
                : t.apiNeverUsed;
            return `
                <div class="account-user-row">
                    <div class="account-user-info" style="flex:1;flex-direction:column;align-items:flex-start;gap:0.2rem;">
                        <div style="display:flex;align-items:center;gap:0.6rem;flex-wrap:wrap;">
                            <code style="font-size:0.78rem;background:var(--input-bg,#f8fafc);padding:0.15rem 0.45rem;border-radius:4px;border:1px solid var(--border,#e2e8f0);letter-spacing:0.02em;">${escapeHTML(k.prefix)}…</code>
                            <span style="font-weight:600;font-size:0.875rem;">${escapeHTML(k.label)}</span>
                        </div>
                        <div style="font-size:0.75rem;color:var(--text-muted,#64748b);">
                            ${t.apiCreatedAt}: ${created} &nbsp;·&nbsp; ${t.apiLastUsed}: ${lastUsed}
                        </div>
                    </div>
                    <button class="account-user-delete" onclick="revokeApiKey(${k.id})" title="${t.apiRevoke}">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                    </button>
                </div>`;
        }).join('')
        : `<p class="account-empty">${t.apiNoKeys}</p>`;

    // Bloque con la nueva clave (solo visible justo después de generarla)
    const newKeyBlock = state.apiNewKey ? `
        <div style="margin-top:0.75rem;background:rgba(245,158,11,0.07);border:1px solid rgba(245,158,11,0.3);border-radius:8px;padding:0.875rem 1rem;">
            <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.6rem;color:#f59e0b;font-size:0.8rem;font-weight:600;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                ${t.apiNewKeyWarning}
            </div>
            <div style="display:flex;gap:0.5rem;align-items:center;">
                <code id="api-new-key-value" style="flex:1;font-size:0.75rem;word-break:break-all;background:var(--input-bg,#f8fafc);padding:0.5rem 0.75rem;border-radius:6px;border:1px solid var(--border,#e2e8f0);display:block;">${escapeHTML(state.apiNewKey.key)}</code>
                <button class="btn-sm btn-primary" onclick="copyText('api-new-key-value', this)" style="flex-shrink:0;white-space:nowrap;">${t.apiCopy}</button>
            </div>
        </div>` : '';

    // Referencia REST: la clave mostrada en los ejemplos es la recién creada o
    // un marcador para que el usuario la sustituya por la suya.
    const exampleKey = state.apiNewKey ? state.apiNewKey.key : 'pwn_TU_CLAVE';

    const endpointRows = [
        ['GET', '/api/reports', t.apiListReports],
        ['POST', '/api/reports', t.apiCreateReport],
        ['GET', '/api/reports/{report_id}/findings', t.apiListFindings],
        ['GET', '/api/findings/{finding_id}', t.apiGetFinding],
        ['POST', '/api/reports/{report_id}/findings', t.apiCreateFinding],
        ['POST', '/api/reports/{report_id}/findings/bulk', t.apiBulkFindings],
        ['PATCH', '/api/findings/{finding_id}', t.apiPatchFinding],
        ['DELETE', '/api/findings/{finding_id}', t.apiDeleteFinding],
    ].map(([method, path, desc]) => `
        <tr>
            <td style="padding:0.45rem 0.6rem;border-bottom:1px solid var(--border,#e2e8f0);white-space:nowrap;">
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;font-weight:700;color:${method === 'GET' ? '#2563eb' : method === 'POST' ? '#059669' : method === 'DELETE' ? '#dc2626' : '#d97706'};">${method}</span>
            </td>
            <td style="padding:0.45rem 0.6rem;border-bottom:1px solid var(--border,#e2e8f0);">
                <code style="font-size:0.73rem;word-break:break-all;">${path}</code>
            </td>
            <td style="padding:0.45rem 0.6rem;border-bottom:1px solid var(--border,#e2e8f0);font-size:0.78rem;color:var(--text-muted,#64748b);">${desc}</td>
        </tr>`).join('');

    const example = `# 1. Crear un reporte\n` +
        `curl -X POST "${baseUrl}/api/reports" \\\n` +
        `  -H "Authorization: Bearer ${exampleKey}" \\\n` +
        `  -H "Content-Type: application/json" \\\n` +
        `  -d '{"document_title":"Auditoría web","client_company":"ACME","target_asset":"https://app.example.com"}'\n\n` +
        `# 2. Añadir un hallazgo al reporte (usa el id devuelto arriba)\n` +
        `curl -X POST "${baseUrl}/api/reports/1/findings" \\\n` +
        `  -H "Authorization: Bearer ${exampleKey}" \\\n` +
        `  -H "Content-Type: application/json" \\\n` +
        `  -d '{"title":"SQL Injection","severity":"crit","cvss":"9.8","description":"Inyección SQL en el parámetro id","poc":"GET /api/users?id=1%27","impact":"Acceso no autorizado a la base de datos","remediation":"Usar consultas parametrizadas"}'\n\n` +
        `# 3. Actualizar solo el estado del hallazgo\n` +
        `curl -X PATCH "${baseUrl}/api/findings/1" \\\n` +
        `  -H "Authorization: Bearer ${exampleKey}" \\\n` +
        `  -H "Content-Type: application/json" \\\n` +
        `  -d '{"status":"remediated","retest_notes":"Corregido en el sprint 12"}'`;

    return `
        <div class="account-card" style="margin-top:1.5rem;">
            <div style="display:flex;align-items:center;gap:0.65rem;margin-bottom:0.3rem;">
                <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent,#6366f1);flex-shrink:0;"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                <h2 class="account-section-title" style="margin:0;">${t.apiTitle}</h2>
            </div>
            <p style="font-size:0.875rem;color:var(--text-muted,#64748b);margin-bottom:1.25rem;">${t.apiSubtitle}</p>

            <h3 class="account-subsection-title">${t.apiKeysTitle}</h3>
            <p style="font-size:0.8rem;color:var(--text-muted,#64748b);margin-bottom:0.75rem;">${t.apiKeysDesc}</p>

            <div class="account-user-list">${keyRows}</div>
            ${newKeyBlock}

            <div class="account-divider"></div>

            <h3 class="account-subsection-title">${t.apiGenerateKey}</h3>
            <form onsubmit="createApiKey(event)" style="display:flex;gap:0.6rem;align-items:flex-end;flex-wrap:wrap;">
                <div style="flex:1;min-width:180px;">
                    <label class="login-label">${t.apiKeyLabelField}</label>
                    <input type="text" id="api-key-label" class="login-input" placeholder="${t.apiKeyLabelPlaceholder}"
                        value="${escapeHTML(state.apiKeyLabel || '')}"
                        oninput="state.apiKeyLabel=this.value"
                        style="margin-bottom:0;">
                </div>
                <button type="submit" class="login-btn" id="api-generate-btn"
                    style="flex-shrink:0;height:40px;margin-top:0;padding:0 1.25rem;">
                    ${t.apiGenerate}
                </button>
            </form>
            ${state.apiError ? `<div class="login-error" style="margin-top:0.5rem;">${escapeHTML(state.apiError)}</div>` : ''}

            <div class="account-divider"></div>

            <h3 class="account-subsection-title">${t.apiUsageTitle}</h3>
            <p style="font-size:0.8rem;color:var(--text-muted,#64748b);margin-bottom:0.75rem;">${t.apiUsageDesc}</p>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0.6rem;margin-bottom:1rem;">
                <div style="background:var(--input-bg,#f8fafc);border:1px solid var(--border,#e2e8f0);border-radius:8px;padding:0.6rem 0.75rem;">
                    <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted,#64748b);margin-bottom:0.25rem;">${t.apiBaseUrlLabel}</div>
                    <code style="font-size:0.76rem;word-break:break-all;">${escapeHTML(baseUrl)}</code>
                </div>
                <div style="background:var(--input-bg,#f8fafc);border:1px solid var(--border,#e2e8f0);border-radius:8px;padding:0.6rem 0.75rem;">
                    <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted,#64748b);margin-bottom:0.25rem;">${t.apiAuthHeaderLabel}</div>
                    <code style="font-size:0.76rem;word-break:break-all;">Authorization: Bearer pwn_…</code>
                </div>
            </div>

            <h3 class="account-subsection-title" style="margin-top:1.25rem;">${t.apiAuthTitle}</h3>
            <p style="font-size:0.8rem;color:var(--text-muted,#64748b);margin-bottom:0.6rem;">${t.apiAuthDesc}</p>
            <div style="position:relative;">
                <pre id="api-auth-block" style="font-size:0.72rem;background:#0f172a;color:#e2e8f0;padding:1rem 1.1rem;border-radius:8px;overflow-x:auto;margin:0;line-height:1.6;">${escapeHTML(`Authorization: Bearer ${exampleKey}`)}</pre>
                <button class="btn-sm btn-secondary" style="position:absolute;top:0.5rem;right:0.5rem;" onclick="copyText('api-auth-block', this)">${t.apiCopy}</button>
            </div>

            <h3 class="account-subsection-title" style="margin:1.25rem 0 0.4rem;">${t.apiEndpointsTitle}</h3>
            <p style="font-size:0.8rem;color:var(--text-muted,#64748b);margin-bottom:0.6rem;">${t.apiEndpointsDesc}</p>
            <div style="overflow-x:auto;border:1px solid var(--border,#e2e8f0);border-radius:8px;">
                <table style="width:100%;border-collapse:collapse;background:var(--card,#fff);">
                    <thead>
                        <tr style="background:var(--input-bg,#f8fafc);text-align:left;">
                            <th style="padding:0.5rem 0.6rem;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted,#64748b);">${t.apiMethod}</th>
                            <th style="padding:0.5rem 0.6rem;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted,#64748b);">${t.apiEndpoint}</th>
                            <th style="padding:0.5rem 0.6rem;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted,#64748b);">${t.apiDescription}</th>
                        </tr>
                    </thead>
                    <tbody>${endpointRows}</tbody>
                </table>
            </div>

            <h3 class="account-subsection-title" style="margin:1.25rem 0 0.4rem;">${t.apiExampleTitle}</h3>
            <p style="font-size:0.8rem;color:var(--text-muted,#64748b);margin-bottom:0.6rem;">${t.apiExampleDesc}</p>
            <div style="position:relative;">
                <pre id="api-example-block" style="font-size:0.72rem;background:#0f172a;color:#e2e8f0;padding:1rem 1.1rem;border-radius:8px;overflow-x:auto;margin:0;line-height:1.6;">${escapeHTML(example)}</pre>
                <button class="btn-sm btn-secondary" style="position:absolute;top:0.5rem;right:0.5rem;" onclick="copyText('api-example-block', this)">${t.apiCopy}</button>
            </div>

            <p style="font-size:0.75rem;color:var(--text-muted,#64748b);margin-top:0.75rem;">${t.apiDocsHint}</p>
        </div>`;
}
async function doChangePassword(event) {
    if (event) event.preventDefault();
    const t = UI[state.lang];
    const current = ($('#currentPassword') || {}).value || '';
    const next = ($('#newPassword') || {}).value || '';
    const confirm = ($('#confirmPassword') || {}).value || '';

    state.profileError = '';
    state.profileSuccess = '';

    if (next !== confirm) {
        state.profileError = t.passwordMismatch;
        renderApp();
        return;
    }

    try {
        const result = await API.auth.changePassword({
            current_password: current,
            new_password: next
        });
        state.profileSuccess = t.passwordChanged;
        state.authUsername = result.username;
        // Ya no usa la contraseña por defecto: el aviso y la pista dejan de salir.
        state.usingDefaultPassword = !!result.using_default_password;
        state.showDefaultCredsHint = false;
        // Limpiamos los campos del formulario tras el éxito.
        ['#currentPassword', '#newPassword', '#confirmPassword'].forEach(id => {
            const el = $(id);
            if (el) el.value = '';
        });
    } catch (err) {
        // El backend devuelve mensajes específicos en err.message (detail de FastAPI).
        state.profileError = err.message && !err.message.startsWith('HTTP ')
            ? err.message
            : (state.lang === 'es' ? 'No se pudo cambiar la contraseña' : 'Could not change password');
    }
    renderApp();
}

// El backend cierra la sesión devolviendo 401: limpiamos el estado y mostramos login.
function handleUnauthorized() {
    if (state.isAuthenticated) {
        state.isAuthenticated = false;
        state.showProfile = false;
        state.authChecked = true;
        renderApp();
    }
}

function enterApp() {
    state.showSplash = false;
    renderApp();
}

function openSettings() {
    state.showSettings = true;
    renderApp();
}

function closeSettings() {
    state.showSettings = false;
    renderApp();
}

function setLang(lang) {
    state.lang = lang;
    state.auditData.lang = lang;
    persistSettings();

    // Si se está editando un hallazgo cargado desde una plantilla de fábrica,
    // re-aplicamos su prosa en el nuevo idioma. Solo si la plantilla existe de
    // verdad; en caso contrario applyTemplate retornaría sin re-renderizar y el
    // cambio de idioma "se perdería".
    const tk = state.currentFinding.templateKey;
    if (tk && tk !== 'custom' && templates[tk]) {
        applyTemplate(tk);
        return;
    }

    renderApp();
}

function setTab(tab) {
    state.activeTab = tab;
    state.showThemesPage = false;
    renderApp();
}


function generatePdf() {
    openPdfModal();
}

// Parámetros de la vista de impresión del informe (compartidos por PDF y export HTML).
function _reportPrintParams(extra) {
    return new URLSearchParams(Object.assign({
        report_id: state.currentReportId,
        print_mode: 'true',
        lang: state.lang,
        theme: state.pdfPrintTheme,
        show_severity_bars: state.pdfShowSeverityBars,
        content_width: state.pdfContentWidth
    }, extra || {}));
}

function _reportFileName() {
    return [state.auditData.documentTitle, state.auditData.clientCompany]
        .filter(Boolean).join(' - ').replace(/[^a-zA-Z0-9_\-. ]/g, '').trim() || `Report_${state.currentReportId}`;
}

// Genera el PDF mediante la impresión nativa del navegador (Guardar como PDF)
// sobre la vista de impresión del informe. Sin dependencias de servidor.
async function executePdfGeneration() {
    if (state.generatingPdf) return;
    const isEs = state.lang === 'es';

    state.showPdfModal = false;
    state.generatingPdf = true;
    renderApp();

    try {
        await saveCurrentReport(true);
        if (!state.currentReportId) {
            throw new Error(isEs ? 'No se pudo guardar el reporte' : 'Could not save the report');
        }
        const win = window.open('/?' + _reportPrintParams({ auto_print: '1' }).toString(), '_blank');
        if (!win) {
            alert(isEs
                ? 'Permite las ventanas emergentes para generar el PDF (se abrirá el diálogo de impresión → Guardar como PDF).'
                : 'Allow pop-ups to generate the PDF (the print dialog will open → Save as PDF).');
        }
    } catch (e) {
        alert((isEs ? 'Error al generar PDF: ' : 'Error generating PDF: ') + e.message);
    } finally {
        state.generatingPdf = false;
        renderApp();
    }
}

// Construye, en el cliente, un documento HTML autocontenido del informe. Reutiliza
// el render real cargando la vista de impresión en un iframe oculto, incrusta el
// CSS y aísla el informe. Las imágenes ya son data URLs => fichero portable.
function buildSelfContainedReportHtml() {
    const url = '/?' + _reportPrintParams().toString();
    return fetch('/css/styles.css').then(r => r.text()).then(cssText => new Promise((resolve, reject) => {
        const iframe = document.createElement('iframe');
        iframe.style.cssText = 'position:fixed;left:-10000px;top:0;width:1280px;height:1200px;border:0;';
        let tries = 0;
        const cleanup = () => { try { document.body.removeChild(iframe); } catch (_) {} };
        const attempt = () => {
            try {
                const doc = iframe.contentDocument;
                const report = doc && doc.querySelector('.preview-container');
                if (!report) {
                    if (++tries > 50) { cleanup(); reject(new Error('No se pudo renderizar el informe')); return; }
                    setTimeout(attempt, 150);
                    return;
                }
                doc.querySelectorAll('script').forEach(s => s.remove());
                doc.querySelectorAll('link[rel="stylesheet"]').forEach(l => {
                    if ((l.getAttribute('href') || '').indexOf('styles.css') !== -1) l.remove();
                });
                const st = doc.createElement('style');
                st.textContent = cssText;
                doc.head.appendChild(st);
                Array.from(doc.body.children).forEach(el => el.remove());
                doc.body.appendChild(report);
                doc.body.style.cssText = 'margin:0;display:flex;justify-content:center;';
                const html = '<!DOCTYPE html>\n' + doc.documentElement.outerHTML;
                cleanup();
                resolve(html);
            } catch (e) { cleanup(); reject(e); }
        };
        iframe.onload = () => setTimeout(attempt, 500);
        iframe.src = url;
        document.body.appendChild(iframe);
    }));
}

function toggleExportMenu(e) {
    if (e) e.stopPropagation();
    state.exportMenuOpen = !state.exportMenuOpen;
    renderApp();
}

function chooseExport(kind) {
    state.exportMenuOpen = false;
    if (kind === 'pdf') {
        generatePdf();
    } else {
        exportHtml();
    }
}

// Cierra el menú de exportación al hacer clic fuera de él.
document.addEventListener('click', (e) => {
    if (state.exportMenuOpen && !e.target.closest('.export-dropdown')) {
        state.exportMenuOpen = false;
        renderApp();
    }
});

async function exportHtml() {
    if (state.exportingHtml) return;
    const isEs = state.lang === 'es';

    state.exportingHtml = true;
    renderApp();

    try {
        await saveCurrentReport(true);
        if (!state.currentReportId) {
            throw new Error(isEs ? 'No se pudo guardar el reporte' : 'Could not save the report');
        }
        const html = await buildSelfContainedReportHtml();
        _downloadBytes(new TextEncoder().encode(html), `${_reportFileName()}.html`, 'text/html;charset=utf-8');
    } catch (e) {
        alert((isEs ? 'Error al exportar HTML: ' : 'Error exporting HTML: ') + e.message);
    } finally {
        state.exportingHtml = false;
        renderApp();
    }
}

async function showReports() {
    await loadSavedReports();
    state.showReportSelector = true;
    state.showThemesPage = false;
    renderApp();
}

function hideReports() {
    state.showReportSelector = false;
    state.showThemesPage = false;
    renderApp();
}

function updateAuditData(field, value) {
    state.auditData[field] = value;
    state.isDirty = true;
}

function updateCurrentFinding(field, value) {
    state.currentFinding[field] = value;
    if (field === 'cvss') {
        const sev = calculateSeverityFromCvss(value);
        if (sev) {
            state.currentFinding.severity = sev;
            const severitySelect = document.getElementById('findingSeverity');
            if (severitySelect) {
                severitySelect.value = sev;
            }
        }
    }
}

// Campo multilínea -> array (una entrada por línea, sin vacíos).
function updateCurrentFindingList(field, value) {
    state.currentFinding[field] = value.split('\n').map(s => s.trim()).filter(Boolean);
}

// Campo separado por comas -> array.
function updateCurrentFindingCsv(field, value) {
    state.currentFinding[field] = value.split(',').map(s => s.trim()).filter(Boolean);
}

function applyTemplate(key) {
    if (key === 'custom') return;

    const template = templates[key];
    if (!template) return;

    const t = template[state.lang] || template.es;

    const calculatedSeverity = t.cvss ? (calculateSeverityFromCvss(t.cvss) || 'info') : (state.currentFinding.severity || 'med');

    state.currentFinding = {
        ...state.currentFinding,
        templateKey: key,
        title: t.title,
        severity: calculatedSeverity,
        description: t.description,
        poc: t.poc || '',
        exploit: t.exploit || state.currentFinding.exploit || '',
        impact: t.impact,
        remediation: t.remediation,
        cvss: t.cvss,
        cvssVector: t.cvss_vector || t.cvssVector || state.currentFinding.cvssVector || '',
        reference: t.reference,
        cwe: t.cwe || state.currentFinding.cwe || '',
        owasp: t.owasp || state.currentFinding.owasp || ''
    };

    renderApp();
}

function filterTemplates(query) {
    const select = document.getElementById('templateSelect');
    const filter = query.toLowerCase();

    if (!select) return;

    select.style.display = 'block';

    const options = select.querySelectorAll('option');
    const optgroups = select.querySelectorAll('optgroup');

    options.forEach(option => {
        const text = option.textContent.toLowerCase();
        const value = option.value.toLowerCase();
        if (text.includes(filter) || value.includes(filter) || filter === '') {
            option.style.display = '';
        } else {
            option.style.display = 'none';
        }
    });

    optgroups.forEach(group => {
        const visibleOptions = group.querySelectorAll('option:not([style*="display: none"])');
        group.style.display = visibleOptions.length > 0 ? '' : 'none';
    });
}

function showTemplateDropdown() {
    const select = document.getElementById('templateSelect');
    const searchInput = document.getElementById('templateSearch');
    if (select) {
        select.style.display = 'block';
        const options = select.querySelectorAll('option');
        const optgroups = select.querySelectorAll('optgroup');
        options.forEach(option => option.style.display = '');
        optgroups.forEach(group => group.style.display = '');
    }
    if (searchInput) searchInput.value = '';
}

function hideTemplateDropdown() {
    const select = document.getElementById('templateSelect');
    if (select) {
        select.style.display = 'none';
    }
}

document.addEventListener('click', function(e) {
    const container = document.querySelector('.template-search-container');
    const select = document.getElementById('templateSelect');
    if (container && !container.contains(e.target) && select) {
        select.style.display = 'none';
    }
});

// Aviso no bloqueante (toast). Evita usar alert() en cada auto-guardado.
function showToast(message, type = 'success') {
    let host = document.getElementById('ptf-toast-host');
    if (!host) {
        host = document.createElement('div');
        host.id = 'ptf-toast-host';
        host.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:8px;align-items:flex-end;pointer-events:none;';
        document.body.appendChild(host);
    }
    const el = document.createElement('div');
    const bg = type === 'error' ? '#dc2626' : (type === 'info' ? '#2563eb' : '#16a34a');
    el.style.cssText = `background:${bg};color:#fff;font-size:0.85rem;font-weight:600;padding:0.6rem 1rem;border-radius:8px;box-shadow:0 6px 20px rgba(0,0,0,0.25);opacity:0;transform:translateY(8px);transition:opacity .2s,transform .2s;max-width:340px;`;
    el.textContent = message;
    host.appendChild(el);
    requestAnimationFrame(() => { el.style.opacity = '1'; el.style.transform = 'translateY(0)'; });
    const ttl = type === 'error' ? 5000 : 1800;
    setTimeout(() => {
        el.style.opacity = '0'; el.style.transform = 'translateY(8px)';
        setTimeout(() => el.remove(), 250);
    }, ttl);
}

// Auto-guardado serializado: encadena las llamadas para que nunca se solapen dos
// guardados (p. ej. al registrar/eliminar hallazgos en ráfaga), lo que podría
// provocar carreras en la sincronización de hallazgos. Silencioso salvo error.
let _autoSaveChain = Promise.resolve();
function autoSaveReport(successMsg) {
    _autoSaveChain = _autoSaveChain.then(async () => {
        try {
            await saveCurrentReport(true);
            if (successMsg !== null) {
                showToast(successMsg || (state.lang === 'es' ? 'Guardado automáticamente ✓' : 'Auto-saved ✓'));
            }
        } catch (err) {
            console.error(err);
            state.isDirty = true;
            showToast((state.lang === 'es'
                ? 'No se pudo guardar automáticamente: '
                : 'Auto-save failed: ') + (err && err.message ? err.message : err), 'error');
        }
    });
    return _autoSaveChain;
}

function handleFindingSubmit(e) {
    e.preventDefault();

    const cf = state.currentFinding;
    const finding = {
        id: state.editingFindingIndex !== null ? state.findings[state.editingFindingIndex].id : Date.now(),
        templateKey: cf.templateKey,
        title: $('#findingTitle').value,
        severity: $('#findingSeverity').value,
        description: $('#findingDescription').value,
        cvss: $('#findingCvss').value,
        cvssVector: cf.cvssVector || '',
        poc: $('#findingPoc').value,
        exploit: $('#findingExploit') ? $('#findingExploit').value : (cf.exploit || ''),
        impact: $('#findingImpact').value,
        remediation: $('#findingRemediation').value,
        reference: $('#findingReference').value,
        references: cf.references || [],
        cve: $('#findingCve').value,
        cwe: $('#findingCwe') ? $('#findingCwe').value : (cf.cwe || ''),
        status: cf.status || 'open',
        affectedAssets: cf.affectedAssets || '',
        likelihood: cf.likelihood || '',
        impactRating: cf.impactRating || '',
        owasp: cf.owasp || '',
        compliance: cf.compliance || [],
        retestNotes: cf.retestNotes || '',
        fieldsVisibility: Object.assign({}, cf.fieldsVisibility || {}),
        images: cf.images
    };

    const wasEditing = state.editingFindingIndex !== null;
    if (wasEditing) {
        state.findings[state.editingFindingIndex] = finding;
        state.editingFindingIndex = null;
    } else {
        state.findings.push(finding);
    }

    sortFindingsBySeverity(state.findings);

    state.isDirty = true;

    if (state.currentReportId) {
        localStorage.removeItem('report_' + state.currentReportId + '_draft');
    }

    resetFindingForm();
    renderApp();

    // Auto-guardado: al registrar/actualizar un hallazgo se persiste sin tener que
    // pulsar "Guardar", evitando perder cambios por olvido.
    autoSaveReport(wasEditing
        ? (state.lang === 'es' ? 'Hallazgo actualizado y guardado ✓' : 'Finding updated & saved ✓')
        : (state.lang === 'es' ? 'Hallazgo guardado ✓' : 'Finding saved ✓'));
}

function resetFindingForm() {
    state.editingFindingIndex = null;
    state.currentFinding = {
        templateKey: 'custom',
        title: '',
        severity: 'med',
        description: '',
        cvss: '',
        cvssVector: '',
        poc: '',
        exploit: '',
        impact: '',
        remediation: '',
        reference: '',
        references: [],
        cve: '',
        cwe: '',
        status: 'open',
        affectedAssets: '',
        likelihood: '',
        impactRating: '',
        owasp: '',
        compliance: [],
        retestNotes: '',
        fieldsVisibility: {},
        images: []
    };
}

function deleteFinding(index) {
    state.findings.splice(index, 1);
    state.isDirty = true;
    renderApp();
    // Auto-guardado: el borrado se persiste de inmediato (coherente con el alta).
    autoSaveReport(state.lang === 'es' ? 'Hallazgo eliminado y guardado ✓' : 'Finding deleted & saved ✓');
}

function editFinding(index) {
    const finding = state.findings[index];
    if (!finding) return;

    normalizeFinding(finding);
    state.currentFinding = {
        templateKey: finding.templateKey || 'custom',
        title: finding.title || '',
        severity: finding.severity || 'med',
        description: finding.description || '',
        cvss: finding.cvss || '',
        cvssVector: finding.cvssVector || '',
        poc: finding.poc || '',
        exploit: finding.exploit || '',
        impact: finding.impact || '',
        remediation: finding.remediation || '',
        reference: finding.reference || '',
        references: Array.isArray(finding.references) ? [...finding.references] : [],
        cve: finding.cve || '',
        cwe: finding.cwe || '',
        status: finding.status || 'open',
        affectedAssets: finding.affectedAssets || '',
        likelihood: finding.likelihood || '',
        impactRating: finding.impactRating || '',
        owasp: finding.owasp || '',
        compliance: Array.isArray(finding.compliance) ? [...finding.compliance] : [],
        retestNotes: finding.retestNotes || '',
        fieldsVisibility: Object.assign({}, finding.fieldsVisibility || {}),
        images: finding.images ? [...finding.images] : [],
        imageCaptions: Array.isArray(finding.imageCaptions || finding.image_captions)
            ? [...(finding.imageCaptions || finding.image_captions)]
            : (finding.images ? finding.images.map(() => '') : [])
    };

    state.editingFindingIndex = index;

    renderApp();
    focusFindingForm();
}

async function handleImageUpload(event) {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    const imageFiles = Array.from(files).filter(file => file.type.startsWith('image/'));
    const dataUrls = await Promise.all(imageFiles.map(readFileAsDataURL));

    dataUrls.forEach(url => {
        if (url) {
            state.currentFinding.images.push(url);
            state.currentFinding.imageCaptions.push('');
        }
    });

    if (dataUrls.length > 0) renderApp();
    event.target.value = '';
}

function removeImage(index) {
    state.currentFinding.images.splice(index, 1);
    state.currentFinding.imageCaptions.splice(index, 1);
    renderApp();
}

// --- Reordenar evidencias por arrastre (drag & drop) ---
// El orden del array state.currentFinding.images es el que se imprime en el
// informe, así que reordenarlo aquí basta para que el cambio se refleje.
let _draggedImageIdx = null;

function imageDragStart(event, idx) {
    _draggedImageIdx = idx;
    if (event.dataTransfer) {
        event.dataTransfer.effectAllowed = 'move';
        try { event.dataTransfer.setData('text/plain', String(idx)); } catch (_e) {}
    }
    const item = event.currentTarget;
    if (item) setTimeout(() => item.classList.add('dragging'), 0);
}

function imageDragOver(event, idx) {
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'move';
    const item = event.currentTarget;
    if (item && _draggedImageIdx !== null && idx !== _draggedImageIdx) item.classList.add('drag-over');
}

function imageDragLeave(event) {
    const item = event.currentTarget;
    if (item) item.classList.remove('drag-over');
}

function imageDrop(event, targetIdx) {
    event.preventDefault();
    event.stopPropagation();
    const from = _draggedImageIdx;
    _draggedImageIdx = null;
    const imgs = state.currentFinding.images;
    const caps = state.currentFinding.imageCaptions;
    if (from === null || from === targetIdx || from < 0 || from >= imgs.length) { renderApp(); return; }
    const [movedImg] = imgs.splice(from, 1);
    const [movedCap] = caps.splice(from, 1);
    imgs.splice(targetIdx, 0, movedImg);
    caps.splice(targetIdx, 0, movedCap);
    state.isDirty = true;
    renderApp();
}

function imageDragEnd() {
    _draggedImageIdx = null;
    document.querySelectorAll('.image-preview-item.dragging, .image-preview-item.drag-over')
        .forEach(el => el.classList.remove('dragging', 'drag-over'));
}

async function handleImagePaste(event) {
    event.preventDefault();
    const items = event.clipboardData?.items;
    if (!items) return;

    const imageItems = Array.from(items).filter(item => item.type.startsWith('image/'));
    const blobs = imageItems.map(item => item.getAsFile()).filter(Boolean);
    const dataUrls = await Promise.all(blobs.map(readFileAsDataURL));

    dataUrls.forEach(url => {
        if (url) {
            state.currentFinding.images.push(url);
            state.currentFinding.imageCaptions.push('');
        }
    });

    if (dataUrls.length > 0) {
        renderApp();
        event.stopPropagation();
    }
}

async function handleClientLogoUpload(event, index) {
    const file = event.target.files[0];
    if (!file || !file.type.startsWith('image/')) return;

    const dataUrl = await readFileAsDataURL(file);
    if (dataUrl) {
        const newLogos = [...state.auditData.clientLogo];
        newLogos[index] = dataUrl;
        updateAuditData('clientLogo', newLogos);
        renderApp();
    }
}

function removeClientLogo(index) {
    const newLogos = [...state.auditData.clientLogo];
    newLogos[index] = '';
    updateAuditData('clientLogo', newLogos);
    renderApp();
}

async function loadSavedReports() {
    try {
        state.savedReports = await API.reports.getAll();
    } catch (err) {
        console.error('Error loading reports:', err);
    }
}

async function createNewReport() {
    try {
        const report = await API.reports.create({
            document_title: 'Nuevo Reporte',
            client_company: 'Empresa',
            client_logo: ['', ''],
            target_asset: 'Sistema',
            auditor_company: 'Auditor',
            auditor_name: 'Auditor',
            classification: 2,
            version: '1.0',
            date: new Date().toISOString().split('T')[0],
            lang: state.lang
        });

        await loadReport(report.id);
    } catch (err) {
        alert('Error creating report: ' + err.message);
    }
}

async function loadReport(id) {
    try {
        const report = await API.reports.getById(id);
        state.currentReportId = report.id;
        state.auditData = {
            documentTitle: report.document_title,
            clientCompany: report.client_company,
            clientLogo: report.client_logo && Array.isArray(report.client_logo) ? report.client_logo : ['', ''],
            targetAsset: report.target_asset,
            auditorCompany: report.auditor_company,
            auditorName: report.auditor_name,
            classification: report.classification.toString(),
            tlpLevel: report.tlp_level || 'amber',
            classificationMode: report.classification_mode || 'internal',
            version: report.version,
            date: report.date,
            lang: report.lang,
            auditType: report.audit_type || 'pentesting_web',
            hasIncidents: report.has_incidents === true || report.has_incidents === 'true' || report.has_incidents === 1,
            incidentsText: report.incidents_text || '',
            auditSummary: report.audit_summary || '',
            testsPerformed: report.tests_performed || '',
            recommendedSolutions: report.recommended_solutions || '',
            scopeIn: report.scope_in || '',
            scopeOut: report.scope_out || '',
            methodologyNotes: report.methodology_notes || '',
            methodologyStandards: Array.isArray(report.methodology_standards) ? report.methodology_standards : [],
            toolsUsed: report.tools_used || '',
            engagementStart: report.engagement_start || '',
            engagementEnd: report.engagement_end || '',
            revisionHistory: Array.isArray(report.revision_history) ? report.revision_history : [],
            scopeFieldsVisibility: (typeof report.scope_fields_visibility === 'object' && report.scope_fields_visibility) ? report.scope_fields_visibility : {}
        };
        state.lang = report.lang;
        // No tocamos el tema al abrir un reporte: se conserva el tema global de la
        // BD (cargado en el arranque desde ajustes) para garantizar uniformidad.
        // Reafirmamos el atributo por si el DOM se hubiera reseteado.
        applyThemeAttributes(state.reportTheme);
        state.findings = sortFindingsBySeverity(normalizeFindings(report.findings || []));

        const draft = localStorage.getItem('report_' + report.id + '_draft');
        if (draft) {
            try {
                state.currentFinding = JSON.parse(draft);
            } catch(e) {
                resetFindingForm();
            }
        } else {
            resetFindingForm();
        }
        
        state.isDirty = false;
        hideReports();
    } catch (err) {
        alert('Error loading report: ' + err.message);
    }
}

async function deleteReport(id) {
    if (!confirm('¿Eliminar este reporte?')) return;

    try {
        await API.reports.delete(id);
        if (state.currentReportId === id) {
            state.currentReportId = null;
        }
        loadSavedReports();
        renderApp();
    } catch (err) {
        alert('Error deleting report: ' + err.message);
    }
}

// =========================================================================== //
// COPIAS DE SEGURIDAD — ZIP (manifest + JSON + imágenes). La base de datos es
// interna: no se exporta como fichero. Opcionalmente se cifra en el navegador
// (PBKDF2 → AES-256-GCM) antes de descargarla.
// =========================================================================== //
const BK_ENC_MAGIC = 'PWNLYBK1';           // 8 bytes: copia cifrada
const BK_MIN_PASSWORD = 8;

// Deriva una clave AES-GCM de 256 bits a partir de la contraseña (PBKDF2-SHA256).
async function deriveBackupKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

function _downloadBytes(bytes, filename, mime) {
    const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

function _bk() {
    const es = state.lang === 'es';
    return es ? {
        title: 'Copia de seguridad', exportBtn: 'Exportar copia', importBtn: 'Importar copia',
        exportTitle: 'Exportar copia de seguridad', importTitle: 'Importar copia de seguridad',
        exportDesc: 'Se descarga un <b>.zip</b> portable con tus reportes y hallazgos (JSON), temas, plantillas, ajustes y las imágenes como ficheros independientes. <b>No incluye usuarios, contraseñas ni API keys.</b>',
        pw: 'Contraseña (opcional)', pw2: 'Confirmar contraseña',
        pwHint: 'Si la defines, el archivo se cifra (AES-256) y la necesitarás para importarlo. Si la pierdes, no se puede recuperar.',
        pwShort: `La contraseña debe tener al menos ${BK_MIN_PASSWORD} caracteres.`, pwMismatch: 'Las contraseñas no coinciden.',
        download: 'Descargar copia', downloadEnc: 'Descargar copia cifrada', working: 'Procesando…',
        exported: 'Copia de seguridad descargada.', exportedEnc: 'Copia cifrada descargada.', exportError: 'Error al exportar: ',
        cancel: 'Cancelar', close: 'Cerrar',
        encrypted: 'Esta copia está cifrada. Introduce la contraseña para leerla.', decrypt: 'Descifrar y continuar', badPw: 'Contraseña incorrecta o archivo dañado.',
        notBackup: 'Este archivo no es una copia de seguridad de Pwnly (.zip).',
        legacyDb: 'Esto es una base de datos SQLite antigua. Ya no se admite: importa una copia .zip exportada desde Pwnly.',
        file: 'Archivo', created: 'Creada', version: 'Versión de Pwnly', contents: 'Contenido',
        reports: 'reportes', findings: 'hallazgos', themes: 'temas', templates: 'plantillas', images: 'imágenes',
        excluded: 'No incluye usuarios, contraseñas ni API keys: tus cuentas actuales no cambian.',
        warnings: 'Avisos', howTitle: 'Cómo importar',
        merge: 'Añadir a lo existente', mergeDesc: 'Recomendado. Los reportes se añaden como copias nuevas; temas y plantillas con el mismo identificador se omiten. No se borra nada.',
        replace: 'Reemplazar todo el contenido', replaceDesc: 'Elimina los reportes, temas y plantillas actuales y restaura los de la copia, incluidos los ajustes.',
        replaceConfirm: 'Entiendo que se borrarán los reportes, temas y plantillas actuales.',
        importNow: 'Importar', importing: 'Importando…', importError: 'Error al importar: ',
        doneTitle: 'Importación completada', imported: 'Importado', skipped: 'Omitidos por duplicado', reload: 'Recargar la aplicación',
        validating: 'Validando la copia…', step: 'Paso'
    } : {
        title: 'Backup', exportBtn: 'Export backup', importBtn: 'Import backup',
        exportTitle: 'Export backup', importTitle: 'Import backup',
        exportDesc: 'Downloads a portable <b>.zip</b> with your reports and findings (JSON), themes, templates, settings and images as separate files. <b>It does not include users, passwords or API keys.</b>',
        pw: 'Password (optional)', pw2: 'Confirm password',
        pwHint: 'If set, the file is encrypted (AES-256) and you will need the password to import it. If you lose it, it cannot be recovered.',
        pwShort: `Password must be at least ${BK_MIN_PASSWORD} characters.`, pwMismatch: 'Passwords do not match.',
        download: 'Download backup', downloadEnc: 'Download encrypted backup', working: 'Working…',
        exported: 'Backup downloaded.', exportedEnc: 'Encrypted backup downloaded.', exportError: 'Export error: ',
        cancel: 'Cancel', close: 'Close',
        encrypted: 'This backup is encrypted. Enter the password to read it.', decrypt: 'Decrypt and continue', badPw: 'Wrong password or corrupted file.',
        notBackup: 'This file is not a Pwnly backup (.zip).',
        legacyDb: 'This is an old SQLite database. It is no longer supported: import a .zip backup exported from Pwnly.',
        file: 'File', created: 'Created', version: 'Pwnly version', contents: 'Contents',
        reports: 'reports', findings: 'findings', themes: 'themes', templates: 'templates', images: 'images',
        excluded: 'Users, passwords and API keys are not included: your current accounts stay as they are.',
        warnings: 'Warnings', howTitle: 'How to import',
        merge: 'Add to existing', mergeDesc: 'Recommended. Reports are added as new copies; themes and templates with the same identifier are skipped. Nothing is deleted.',
        replace: 'Replace all content', replaceDesc: 'Deletes current reports, themes and templates and restores those in the backup, including settings.',
        replaceConfirm: 'I understand current reports, themes and templates will be deleted.',
        importNow: 'Import', importing: 'Importing…', importError: 'Import error: ',
        doneTitle: 'Import complete', imported: 'Imported', skipped: 'Skipped (duplicates)', reload: 'Reload the app',
        validating: 'Validating the backup…', step: 'Step'
    };
}

const _bkInit = () => ({ open: false, kind: '', busy: false, error: '', fileName: '', bytes: null,
    needsPassword: false, preview: null, mode: 'merge', confirmReplace: false, result: null });
state.backupModal = _bkInit();

function closeBackupModal() { state.backupModal = _bkInit(); renderApp(); }

function openBackupExport() {
    state.backupModal = { ..._bkInit(), open: true, kind: 'export' };
    renderApp();
    setTimeout(() => { const el = document.getElementById('bkPw'); if (el) el.focus(); }, 30);
}

async function submitBackupExport(event) {
    if (event) event.preventDefault();
    const b = _bk();
    const pw = (document.getElementById('bkPw') || {}).value || '';
    const pw2 = (document.getElementById('bkPw2') || {}).value || '';
    if (pw && pw.length < BK_MIN_PASSWORD) { state.backupModal.error = b.pwShort; renderApp(); return; }
    if (pw !== pw2) { state.backupModal.error = b.pwMismatch; renderApp(); return; }
    state.backupModal.busy = true; state.backupModal.error = ''; renderApp();
    try {
        const response = await fetch('/api/backup/export');
        if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail || 'HTTP ' + response.status);
        const cd = response.headers.get('content-disposition') || '';
        const name = (cd.match(/filename="?([^";]+)"?/) || [])[1] || 'pwnly-backup.zip';
        const zipBytes = new Uint8Array(await response.arrayBuffer());
        if (!pw) {
            _downloadBytes(zipBytes, name, 'application/zip');
        } else {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await deriveBackupKey(pw, salt);
            const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, zipBytes));
            const magic = new TextEncoder().encode(BK_ENC_MAGIC);
            const out = new Uint8Array(magic.length + salt.length + iv.length + ct.length);
            out.set(magic, 0); out.set(salt, magic.length); out.set(iv, magic.length + salt.length); out.set(ct, magic.length + salt.length + iv.length);
            _downloadBytes(out, name + '.enc', 'application/octet-stream');
        }
        state.backupModal = _bkInit(); renderApp();
        showToast(pw ? b.exportedEnc : b.exported);
    } catch (err) {
        state.backupModal.busy = false; state.backupModal.error = b.exportError + err.message; renderApp();
    }
}

// Selección de archivo → detecta formato (zip / cifrada / SQLite antigua) → vista previa.
async function pickBackupFile(input) {
    const file = input.files && input.files[0];
    input.value = '';
    if (!file) return;
    const b = _bk();
    state.backupModal = { ..._bkInit(), open: true, kind: 'import', fileName: file.name, busy: true };
    renderApp();
    try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        const head = new TextDecoder().decode(bytes.slice(0, 16));
        if (head.startsWith(BK_ENC_MAGIC)) {
            state.backupModal.bytes = bytes; state.backupModal.needsPassword = true; state.backupModal.busy = false;
            renderApp();
            setTimeout(() => { const el = document.getElementById('bkImpPw'); if (el) el.focus(); }, 30);
            return;
        }
        if (head.startsWith('SQLite format 3') || head.startsWith('PWNYDB01')) {
            state.backupModal.busy = false; state.backupModal.error = b.legacyDb; renderApp(); return;
        }
        if (!(bytes[0] === 0x50 && bytes[1] === 0x4b)) {        // "PK" = ZIP
            state.backupModal.busy = false; state.backupModal.error = b.notBackup; renderApp(); return;
        }
        state.backupModal.bytes = bytes;
        await previewBackup();
    } catch (err) {
        state.backupModal.busy = false; state.backupModal.error = b.importError + err.message; renderApp();
    }
}

async function decryptBackupFile(event) {
    if (event) event.preventDefault();
    const b = _bk();
    const pw = (document.getElementById('bkImpPw') || {}).value || '';
    if (!pw) return;
    state.backupModal.busy = true; state.backupModal.error = ''; renderApp();
    try {
        const bytes = state.backupModal.bytes;
        const salt = bytes.slice(8, 24), iv = bytes.slice(24, 36), ct = bytes.slice(36);
        const key = await deriveBackupKey(pw, salt);
        const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
        state.backupModal.bytes = new Uint8Array(dec);
        state.backupModal.needsPassword = false;
        await previewBackup();
    } catch (e) {
        state.backupModal.busy = false; state.backupModal.error = b.badPw; renderApp();
    }
}

async function _postBackup(dryRun) {
    const m = state.backupModal;
    const fd = new FormData();
    fd.append('file', new Blob([m.bytes], { type: 'application/zip' }), 'backup.zip');
    fd.append('mode', m.mode);
    fd.append('dry_run', dryRun ? 'true' : 'false');
    const response = await fetch('/api/backup/import', { method: 'POST', body: fd });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || 'HTTP ' + response.status);
    return data;
}

async function previewBackup() {
    const b = _bk();
    state.backupModal.busy = true; state.backupModal.error = ''; renderApp();
    try {
        state.backupModal.preview = await _postBackup(true);
        state.backupModal.busy = false; renderApp();
    } catch (err) {
        state.backupModal.busy = false; state.backupModal.error = err.message; renderApp();
    }
}

function setBackupMode(mode) { state.backupModal.mode = mode; state.backupModal.confirmReplace = false; renderApp(); }
function setBackupConfirm(v) { state.backupModal.confirmReplace = !!v; renderApp(); }

async function confirmBackupImport() {
    const m = state.backupModal;
    const b = _bk();
    if (m.mode === 'replace' && !m.confirmReplace) return;
    m.busy = true; m.error = ''; renderApp();
    try {
        state.backupModal.result = await _postBackup(false);
        state.backupModal.busy = false; renderApp();
    } catch (err) {
        state.backupModal.busy = false; state.backupModal.error = b.importError + err.message; renderApp();
    }
}

function renderBackupModal() {
    const m = state.backupModal;
    if (!m || !m.open) return '';
    const b = _bk();
    const x = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
    const title = m.result ? b.doneTitle : (m.kind === 'export' ? b.exportTitle : b.importTitle);
    const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
    const countLine = (c) => [['reports', 'reports'], ['findings', 'findings'], ['themes', 'themes'], ['finding_templates', 'templates'], ['assets', 'images']]
        .map(([k, lk]) => `${cap(b[lk])}: ${c[k]}`).join(' · ');
    const err = m.error ? `<div class="login-error" role="alert" style="margin-top:0.8rem;">${escapeHTML(m.error)}</div>` : '';
    let body = '';

    if (m.kind === 'export') {
        body = `
            <p class="bk-text">${b.exportDesc}</p>
            <form onsubmit="submitBackupExport(event)" autocomplete="off">
                <label class="login-label" for="bkPw">${b.pw}</label>
                <input type="password" id="bkPw" class="login-input" autocomplete="new-password" aria-describedby="bkPwHint">
                <label class="login-label" for="bkPw2" style="margin-top:0.6rem;">${b.pw2}</label>
                <input type="password" id="bkPw2" class="login-input" autocomplete="new-password">
                <p class="bk-hint" id="bkPwHint">${b.pwHint}</p>
                ${err}
                <div class="bk-actions">
                    <button type="button" class="btn-secondary" onclick="closeBackupModal()">${b.cancel}</button>
                    <button type="submit" class="btn-primary" ${m.busy ? 'disabled' : ''}>${m.busy ? b.working : b.download}</button>
                </div>
            </form>`;
    } else if (m.result) {
        const r = m.result;
        body = `
            <div class="bk-done" role="status">
                <p class="bk-text"><b>${b.imported}:</b> ${countLine(r.imported)}</p>
                ${(r.skipped.themes || r.skipped.finding_templates) ? `<p class="bk-text"><b>${b.skipped}:</b> ${r.skipped.themes} ${b.themes}, ${r.skipped.finding_templates} ${b.templates}</p>` : ''}
                ${r.warnings.length ? `<p class="bk-hint">${r.warnings.map(escapeHTML).join('<br>')}</p>` : ''}
            </div>
            <div class="bk-actions"><button type="button" class="btn-primary" onclick="window.location.reload()">${b.reload}</button></div>`;
    } else if (m.needsPassword) {
        body = `
            <p class="bk-text">${b.encrypted}</p>
            <form onsubmit="decryptBackupFile(event)">
                <label class="login-label" for="bkImpPw">${b.pw.replace(' (opcional)', '').replace(' (optional)', '')}</label>
                <input type="password" id="bkImpPw" class="login-input" autocomplete="current-password">
                ${err}
                <div class="bk-actions">
                    <button type="button" class="btn-secondary" onclick="closeBackupModal()">${b.cancel}</button>
                    <button type="submit" class="btn-primary" ${m.busy ? 'disabled' : ''}>${m.busy ? b.working : b.decrypt}</button>
                </div>
            </form>`;
    } else if (m.preview) {
        const p = m.preview;
        const created = p.created_at ? new Date(p.created_at).toLocaleString(state.lang === 'es' ? 'es-ES' : 'en-GB') : '—';
        const canImport = !m.busy && (m.mode !== 'replace' || m.confirmReplace);
        body = `
            <dl class="bk-meta">
                <div><dt>${b.file}</dt><dd>${escapeHTML(m.fileName)}</dd></div>
                <div><dt>${b.created}</dt><dd>${escapeHTML(created)}</dd></div>
                <div><dt>${b.version}</dt><dd>${escapeHTML(p.app_version || '—')}</dd></div>
                <div><dt>${b.contents}</dt><dd>${countLine(p.counts)}</dd></div>
            </dl>
            ${p.reports && p.reports.length ? `<ul class="bk-list">${p.reports.slice(0, 5).map(r => `<li>${escapeHTML(r.title)} <span>· ${escapeHTML(r.client)} · ${r.findings} ${b.findings}</span></li>`).join('')}${p.reports.length > 5 ? `<li><span>… +${p.counts.reports - 5}</span></li>` : ''}</ul>` : ''}
            <p class="bk-hint">${b.excluded}</p>
            ${p.warnings && p.warnings.length ? `<div class="bk-warn" role="status"><b>${b.warnings}</b><br>${p.warnings.map(escapeHTML).join('<br>')}</div>` : ''}
            <fieldset class="bk-modes">
                <legend>${b.howTitle}</legend>
                <label class="bk-mode ${m.mode === 'merge' ? 'on' : ''}"><input type="radio" name="bkMode" value="merge" ${m.mode === 'merge' ? 'checked' : ''} onchange="setBackupMode('merge')"><span><b>${b.merge}</b><small>${b.mergeDesc}</small></span></label>
                <label class="bk-mode bk-mode--danger ${m.mode === 'replace' ? 'on' : ''}"><input type="radio" name="bkMode" value="replace" ${m.mode === 'replace' ? 'checked' : ''} onchange="setBackupMode('replace')"><span><b>${b.replace}</b><small>${b.replaceDesc}</small></span></label>
            </fieldset>
            ${m.mode === 'replace' ? `<label class="bk-confirm"><input type="checkbox" ${m.confirmReplace ? 'checked' : ''} onchange="setBackupConfirm(this.checked)"> ${b.replaceConfirm}</label>` : ''}
            ${err}
            <div class="bk-actions">
                <button type="button" class="btn-secondary" onclick="closeBackupModal()">${b.cancel}</button>
                <button type="button" class="btn-primary ${m.mode === 'replace' ? 'bk-danger' : ''}" onclick="confirmBackupImport()" ${canImport ? '' : 'disabled'}>${m.busy ? b.importing : b.importNow}</button>
            </div>`;
    } else {
        body = (m.busy ? `<p class="bk-text" role="status">${b.validating}</p>` : '') + err +
            `<div class="bk-actions"><button type="button" class="btn-secondary" onclick="closeBackupModal()">${b.close}</button></div>`;
    }

    return `
        <div class="settings-overlay bk-overlay" onclick="closeBackupModal()">
            <div class="settings-modal bk-modal" role="dialog" aria-modal="true" aria-labelledby="bkTitle" onclick="event.stopPropagation()">
                <div class="settings-modal-header">
                    <span id="bkTitle" style="display:inline-flex;align-items:center;gap:0.5rem;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        ${title}
                    </span>
                    <button class="settings-close-btn" onclick="closeBackupModal()" aria-label="${b.close}">${x}</button>
                </div>
                <div class="settings-section">${body}</div>
            </div>
        </div>`;
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && state.backupModal && state.backupModal.open && !state.backupModal.busy) closeBackupModal();
});


async function saveCurrentReport(silent = false) {
    try {
        const payload = {
            document_title: state.auditData.documentTitle,
            client_company: state.auditData.clientCompany,
            client_logo: state.auditData.clientLogo || ['', ''],
            target_asset: state.auditData.targetAsset,
            auditor_company: state.auditData.auditorCompany,
            auditor_name: state.auditData.auditorName,
            classification: parseInt(state.auditData.classification) || 2,
            tlp_level: state.auditData.tlpLevel || 'amber',
            classification_mode: state.auditData.classificationMode || 'internal',
            version: state.auditData.version,
            date: state.auditData.date,
            lang: state.auditData.lang || state.lang,
            has_incidents: state.auditData.hasIncidents || false,
            incidents_text: state.auditData.incidentsText || '',
            audit_summary: state.auditData.auditSummary || '',
            tests_performed: state.auditData.testsPerformed || '',
            recommended_solutions: state.auditData.recommendedSolutions || '',
            audit_type: state.auditData.auditType || 'pentesting_web',
            scope_in: state.auditData.scopeIn || '',
            scope_out: state.auditData.scopeOut || '',
            methodology_notes: state.auditData.methodologyNotes || '',
            methodology_standards: state.auditData.methodologyStandards || [],
            tools_used: state.auditData.toolsUsed || '',
            engagement_start: state.auditData.engagementStart || '',
            engagement_end: state.auditData.engagementEnd || '',
            revision_history: state.auditData.revisionHistory || [],
            scope_fields_visibility: state.auditData.scopeFieldsVisibility || {}
        };

        if (!state.currentReportId) {
            const report = await API.reports.create(payload);
            state.currentReportId = report.id;
        } else {
            await API.reports.update(state.currentReportId, payload);
        }
        const remoteReport = await API.reports.getById(state.currentReportId);
        const existingFindings = remoteReport.findings || [];
        const existingIds = existingFindings.map(f => f.id);
        const currentIds = state.findings.filter(f => f.id && typeof f.id !== 'string' && f.id < 1000000000000).map(f => f.id);

        for (const id of existingIds) {
            if (!currentIds.includes(id)) {
                await API.findings.delete(id);
            }
        }

        for (let i = 0; i < state.findings.length; i++) {
            const finding = state.findings[i];
            const payload = {
                template_key: finding.templateKey || finding.template_key || 'custom',
                title: finding.title,
                severity: finding.severity,
                description: finding.description || '',
                cvss: finding.cvss || '',
                cvss_vector: finding.cvssVector || finding.cvss_vector || '',
                poc: finding.poc || '',
                exploit: finding.exploit || '',
                impact: finding.impact || '',
                remediation: finding.remediation || '',
                reference: finding.reference || '',
                references: finding.references || [],
                cve: finding.cve || '',
                cwe: finding.cwe || '',
                status: finding.status || 'open',
                affected_assets: finding.affectedAssets || finding.affected_assets || '',
                likelihood: finding.likelihood || '',
                impact_rating: finding.impactRating || finding.impact_rating || '',
                owasp: finding.owasp || '',
                compliance: finding.compliance || [],
                retest_notes: finding.retestNotes || finding.retest_notes || '',
                fields_visibility: finding.fieldsVisibility || finding.fields_visibility || {},
                images: finding.images || [],
                image_captions: finding.imageCaptions || finding.image_captions || [],
                order_index: i
            };

            if (!finding.id || finding.id > 1000000000000) {
                const created = await API.findings.create(state.currentReportId, payload);
                finding.id = created.id;
            } else {
                await API.findings.update(finding.id, payload);
            }
        }

        localStorage.setItem('report_' + state.currentReportId + '_draft', JSON.stringify(state.currentFinding));

        state.isDirty = false;
        if (!silent) renderApp();
        if (!silent) alert(state.lang === 'es' ? 'Reporte guardado correctamente' : 'Report saved successfully');
    } catch (err) {
        console.error(err);
        if (!silent) alert('Error: ' + err.message);
        else throw err;
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    const params = new URLSearchParams(window.location.search);
    const printMode = params.get('print_mode');
    const reportId = params.get('report_id');

    // Inyectamos los bloques CSS de los temas de fábrica de inmediato (los
    // personalizados se añaden cuando se cargan desde la API).
    injectThemeStyles();

    const themeParam = params.get('theme');
    if (printMode === 'true' && reportId) {
        // En modo impresión (Playwright) la autenticación viaja en la cookie de
        // sesión inyectada por el backend; saltamos la pantalla de login.
        state.authChecked = true;
        state.isAuthenticated = true;
        state.activeTab = 'preview';
        state.currentReportId = parseInt(reportId);
        // Idioma del informe exportado: viene en la URL para reflejar EXACTAMENTE
        // el idioma elegido en la app (sin depender del guardado debounced de
        // ajustes, que podría no haberse persistido aún al exportar).
        const langParam = params.get('lang');
        if (langParam === 'es' || langParam === 'en') {
            state.lang = langParam;
            state.auditData.lang = langParam;
        }
        // Cargamos los temas personalizados para que el PDF pueda usar cualquiera.
        await loadCustomThemes();
        state.reportTheme = (themeParam && listAllThemes().some(t => t.slug === themeParam)) ? themeParam : BUILTIN_THEME_SLUG;
        applyThemeAttributes(state.reportTheme);
        if (params.get('show_severity_bars') === 'false') {
            state.pdfShowSeverityBars = false;
        }
        const cwParam = params.get('content_width');
        if (cwParam) {
            state.pdfContentWidth = parseInt(cwParam);
        }
        
        try {
            const remoteReport = await API.reports.getById(state.currentReportId);
            Object.keys(remoteReport).forEach(key => {
                const camelKey = key.replace(/([-_][a-z])/ig, ($1) => $1.toUpperCase().replace('-', '').replace('_', ''));
                if (state.auditData.hasOwnProperty(camelKey)) {
                    state.auditData[camelKey] = remoteReport[key];
                }
            });

            // Ensure incidents fields are properly set (handle both snake_case and direct assignment)
            if (remoteReport.has_incidents !== undefined) {
                state.auditData.hasIncidents = remoteReport.has_incidents === true || remoteReport.has_incidents === 'true' || remoteReport.has_incidents === 1;
            }
            if (remoteReport.incidents_text !== undefined) {
                state.auditData.incidentsText = remoteReport.incidents_text;
            }
            if (remoteReport.tlp_level !== undefined) {
                state.auditData.tlpLevel = remoteReport.tlp_level;
            }
            if (remoteReport.classification_mode !== undefined) {
                state.auditData.classificationMode = remoteReport.classification_mode;
            }

            state.findings = remoteReport.findings ? sortFindingsBySeverity(normalizeFindings(remoteReport.findings)) : [];
        } catch (e) {
            console.error("Error cargando reporte para imprimir", e);
        }
        renderApp();
        // Pintamos el fondo de la página con el color del tema para que el lienzo
        // del PDF (márgenes incluidos) coincida con cualquier tema, incluso los
        // personalizados.
        applyPrintBackground();
        // Generación de PDF: impresión nativa del navegador (Guardar como PDF).
        // Damos un margen para que imágenes y estilos terminen de pintar.
        if (params.get('auto_print') === '1') {
            setTimeout(() => { try { window.print(); } catch (e) {} }, 900);
        }
    } else {
        // Modo normal: comprobamos si ya hay una sesión válida (cookie) antes de
        // decidir entre mostrar el login o la aplicación.
        const accountParam = params.get('account');
        state.isAccountView = accountParam === '1' || accountParam === 'true';

        try {
            const me = await API.auth.me();
            state.isAuthenticated = true;
            state.authUsername = me.username;
            state.usingDefaultPassword = !!me.using_default_password;
            // Cargamos los temas personalizados y las preferencias guardadas en la
            // BD (idioma, tema activo, opciones de PDF). La BD es la fuente de verdad
            // para que la exportación capture el 100% del estado.
            await loadCustomThemes();
            const savedTheme = localStorage.getItem('pwnly_theme');
            state.reportTheme = (savedTheme && listAllThemes().some(t => t.slug === savedTheme)) ? savedTheme : BUILTIN_THEME_SLUG;
            await loadSettings();
            applyThemeAttributes(state.reportTheme);
            // En la página de cuenta cargamos usuarios y API keys.
            if (state.isAccountView) {
                await Promise.all([loadUsers(), loadApiKeys()]);
            }
        } catch (e) {
            state.isAuthenticated = false;
            // Sin sesión válida: ¿la app está sin configurar (primer arranque,
            // ningún usuario)? Si es así mostramos la configuración inicial.
            try {
                const setup = await API.auth.needsSetup();
                state.needsSetup = !!(setup && setup.needs_setup);
            } catch (_e) {
                state.needsSetup = false;
            }
            // Pista de credenciales por defecto bajo el formulario de login: sólo
            // se muestra mientras el admin conserve la contraseña 'admin'.
            await refreshDefaultCredsHint();
        }
        state.authChecked = true;
        renderApp();
    }
});

// Aplica el fondo del tema activo a html/body (usado en modo impresión para que
// el PDF no muestre franjas blancas con temas oscuros o personalizados).
// Pinta el fondo de la página (márgenes incluidos) con el color de fondo real
// del propio contenido del tema activo, para que coincida sea cual sea el CSS
// que haya escrito el usuario (ya no depende de una variable --rt-* fija).
function applyPrintBackground() {
    try {
        const probe = document.querySelector('.preview-container');
        if (!probe) return;
        const bg = getComputedStyle(probe).backgroundColor;
        if (bg && bg !== 'rgba(0, 0, 0, 0)' && bg !== 'transparent') {
            document.documentElement.style.background = bg;
            document.body.style.background = bg;
        }
    } catch (e) { /* dejamos el fondo por defecto */ }
}