from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import Settings
from app.engine import SigmaEngine
from app.models import HealthResponse, VersionResponse
from app.rpc import RpcDispatcher

DEFAULT_LANG = 'en'
SUPPORTED_LANGS = {'en', 'es', 'fr', 'it', 'pt', 'de', 'ru'}

LANGUAGE_OPTIONS = [
    {'code': 'en', 'label': 'English'},
    {'code': 'es', 'label': 'español'},
    {'code': 'fr', 'label': 'français'},
    {'code': 'it', 'label': 'italiano'},
    {'code': 'pt', 'label': 'português'},
    {'code': 'de', 'label': 'deutsch'},
    {'code': 'ru', 'label': 'русский'},
]

HOME_I18N: dict[str, dict[str, str]] = {
    'en': {
        'language_label': 'Language',
        'version': 'version',
        'status': 'status',
        'primary_endpoint': 'Primary endpoint:',
        'health_endpoint': 'Health endpoint:',
        'methods_title': 'Available JSON-RPC Methods',
        'examples_title': 'Quick cURL Examples',
        'copy_button': 'Copy cURL example',
        'copied_button': 'Copied',
        'note_label': 'Note:',
        'note_text': 'This service exposes JSON-RPC 2.0 on',
        'note_text_tail': 'HTTP endpoints are auxiliary for operations and humans.',
        # Endpoint table
        'http_endpoints_title': 'HTTP Endpoints',
        'endpoint_home': 'Home page · this page',
        'endpoint_health': 'Health check · service status and sigma availability',
        'endpoint_version': 'Service name and version',
        'endpoint_jsonrpc': 'JSON-RPC 2.0 · conversion dispatch · main entry point',
        # Method descriptions
        'method_desc_discover': 'Returns service metadata, available methods and active capabilities',
        'method_desc_plugins': 'Lists all installed Sigma plugins',
        'method_desc_backends': 'Lists available conversion backends (splunk, elastic, kql…)',
        'method_desc_pipelines': 'Lists available field-mapping pipelines',
        'method_desc_validate': 'Validates a Sigma rule YAML string',
        'method_desc_convert': 'Converts a Sigma rule to a target backend query format',
        # Try panel
        'try_button': '▶  Try it',
        'try_back': '← Back',
        'try_title': 'Sigma Live Converter',
        'try_token_label': 'Token',
        'try_token_no_auth': 'No authentication configured',
        'try_rule_placeholder': 'Paste a Sigma rule here...',
        'try_result_placeholder': 'Converted output will appear here',
        'try_backend_label': 'Backend',
        'try_pipeline_label': 'Pipeline',
        'try_pipeline_none': 'none',
        'try_convert_btn': 'Convert →',
        'try_loading': 'Converting...',
        'try_error_empty_rule': 'Please provide a Sigma rule.',
        'try_error_no_backend': 'Please select a backend.',
        # Footer
        'footer_coded': 'Coded with',
        'footer_by': 'by',
        'footer_license': 'MIT License',
        'footer_project': 'Project',
    },
    'es': {
        'language_label': 'idioma',
        'version': 'version',
        'status': 'estado',
        'primary_endpoint': 'endpoint principal:',
        'health_endpoint': 'endpoint de salud:',
        'methods_title': 'métodos JSON-RPC disponibles',
        'examples_title': 'ejemplos rápidos cURL',
        'copy_button': 'copiar ejemplo cURL',
        'copied_button': 'copiado',
        'note_label': 'nota:',
        'note_text': 'este servicio expone JSON-RPC 2.0 en',
        'note_text_tail': 'los endpoints HTTP son auxiliares para operación y usuarios.',
        # Endpoint table
        'http_endpoints_title': 'endpoints HTTP',
        'endpoint_home': 'página de inicio · esta página',
        'endpoint_health': 'estado · disponibilidad del servicio y sigma',
        'endpoint_version': 'nombre y versión del servicio',
        'endpoint_jsonrpc': 'JSON-RPC 2.0 · despacho de conversión · entrada principal',
        # Method descriptions
        'method_desc_discover': 'devuelve metadatos del servicio, métodos disponibles y capacidades activas',
        'method_desc_plugins': 'lista todos los plugins de Sigma instalados',
        'method_desc_backends': 'lista backends de conversión disponibles (splunk, elastic, kql…)',
        'method_desc_pipelines': 'lista las pipelines de mapeo de campos disponibles',
        'method_desc_validate': 'valida el YAML de una regla Sigma',
        'method_desc_convert': 'convierte una regla Sigma al formato de consulta del backend destino',
        # Try panel
        'try_button': '▶  probar',
        'try_back': '← volver',
        'try_title': 'conversor Sigma en vivo',
        'try_token_label': 'token',
        'try_token_no_auth': 'sin autenticación configurada',
        'try_rule_placeholder': 'pega aquí una regla Sigma...',
        'try_result_placeholder': 'el resultado de conversión aparecerá aquí',
        'try_backend_label': 'backend',
        'try_pipeline_label': 'pipeline',
        'try_pipeline_none': 'ninguna',
        'try_convert_btn': 'convertir →',
        'try_loading': 'convirtiendo...',
        'try_error_empty_rule': 'introduce una regla Sigma.',
        'try_error_no_backend': 'selecciona un backend.',
        # Footer
        'footer_coded': 'hecho con',
        'footer_by': 'por',
        'footer_license': 'licencia MIT',
        'footer_project': 'proyecto',
    },
    'fr': {
        'language_label': 'langue',
        'version': 'version',
        'status': 'statut',
        'primary_endpoint': 'point d\'entrée principal :',
        'health_endpoint': 'point de santé :',
        'methods_title': 'méthodes JSON-RPC disponibles',
        'examples_title': 'exemples cURL rapides',
        'copy_button': 'copier l\'exemple cURL',
        'copied_button': 'copié',
        'note_label': 'note :',
        'note_text': 'ce service expose JSON-RPC 2.0 sur',
        'note_text_tail': 'les endpoints HTTP sont auxiliaires pour les opérations et les utilisateurs.',
        'http_endpoints_title': 'endpoints HTTP',
        'endpoint_home': 'page d\'accueil · cette page',
        'endpoint_health': 'santé · état du service et disponibilité de sigma',
        'endpoint_version': 'nom et version du service',
        'endpoint_jsonrpc': 'JSON-RPC 2.0 · point d\'entrée principal de conversion',
        'method_desc_discover': 'retourne les métadonnées, méthodes et capacités actives du service',
        'method_desc_plugins': 'liste tous les plugins Sigma installés',
        'method_desc_backends': 'liste les backends de conversion disponibles (splunk, elastic, kql…)',
        'method_desc_pipelines': 'liste les pipelines de mappage de champs disponibles',
        'method_desc_validate': 'valide une règle Sigma au format YAML',
        'method_desc_convert': 'convertit une règle Sigma vers un backend cible',
        'try_button': '▶  essayer',
        'try_back': '← retour',
        'try_title': 'convertisseur Sigma en direct',
        'try_token_label': 'token',
        'try_token_no_auth': 'authentification non configurée',
        'try_rule_placeholder': 'collez une règle Sigma ici...',
        'try_result_placeholder': 'la sortie convertie apparaîtra ici',
        'try_backend_label': 'backend',
        'try_pipeline_label': 'pipeline',
        'try_pipeline_none': 'aucun',
        'try_convert_btn': 'convertir →',
        'try_loading': 'conversion en cours...',
        'try_error_empty_rule': 'veuillez saisir une règle Sigma.',
        'try_error_no_backend': 'veuillez choisir un backend.',
        'footer_coded': 'codé avec',
        'footer_by': 'par',
        'footer_license': 'licence MIT',
        'footer_project': 'projet',
    },
    'it': {
        'language_label': 'lingua',
        'version': 'versione',
        'status': 'stato',
        'primary_endpoint': 'endpoint principale:',
        'health_endpoint': 'endpoint di salute:',
        'methods_title': 'metodi JSON-RPC disponibili',
        'examples_title': 'esempi cURL rapidi',
        'copy_button': 'copia esempio cURL',
        'copied_button': 'copiato',
        'note_label': 'nota:',
        'note_text': 'questo servizio espone JSON-RPC 2.0 su',
        'note_text_tail': 'gli endpoint HTTP sono ausiliari per operazioni e utenti.',
        'http_endpoints_title': 'endpoint HTTP',
        'endpoint_home': 'home page · questa pagina',
        'endpoint_health': 'salute · stato del servizio e disponibilità di sigma',
        'endpoint_version': 'nome e versione del servizio',
        'endpoint_jsonrpc': 'JSON-RPC 2.0 · punto di ingresso principale per la conversione',
        'method_desc_discover': 'restituisce metadati, metodi disponibili e capacità attive',
        'method_desc_plugins': 'elenca tutti i plugin Sigma installati',
        'method_desc_backends': 'elenca i backend di conversione disponibili (splunk, elastic, kql…)',
        'method_desc_pipelines': 'elenca le pipeline di mappatura campi disponibili',
        'method_desc_validate': 'valida una regola Sigma in YAML',
        'method_desc_convert': 'converte una regola Sigma nel formato del backend di destinazione',
        'try_button': '▶  prova',
        'try_back': '← indietro',
        'try_title': 'convertitore Sigma live',
        'try_token_label': 'token',
        'try_token_no_auth': 'autenticazione non configurata',
        'try_rule_placeholder': 'incolla qui una regola Sigma...',
        'try_result_placeholder': 'l\'output convertito apparirà qui',
        'try_backend_label': 'backend',
        'try_pipeline_label': 'pipeline',
        'try_pipeline_none': 'nessuna',
        'try_convert_btn': 'converti →',
        'try_loading': 'conversione in corso...',
        'try_error_empty_rule': 'inserisci una regola Sigma.',
        'try_error_no_backend': 'seleziona un backend.',
        'footer_coded': 'realizzato con',
        'footer_by': 'da',
        'footer_license': 'licenza MIT',
        'footer_project': 'progetto',
    },
    'pt': {
        'language_label': 'idioma',
        'version': 'versão',
        'status': 'estado',
        'primary_endpoint': 'endpoint principal:',
        'health_endpoint': 'endpoint de saúde:',
        'methods_title': 'métodos JSON-RPC disponíveis',
        'examples_title': 'exemplos rápidos de cURL',
        'copy_button': 'copiar exemplo cURL',
        'copied_button': 'copiado',
        'note_label': 'nota:',
        'note_text': 'este serviço expõe JSON-RPC 2.0 em',
        'note_text_tail': 'os endpoints HTTP são auxiliares para operações e usuários.',
        'http_endpoints_title': 'endpoints HTTP',
        'endpoint_home': 'página inicial · esta página',
        'endpoint_health': 'saúde · estado do serviço e disponibilidade do sigma',
        'endpoint_version': 'nome e versão do serviço',
        'endpoint_jsonrpc': 'JSON-RPC 2.0 · ponto de entrada principal para conversão',
        'method_desc_discover': 'retorna metadados do serviço, métodos e capacidades ativas',
        'method_desc_plugins': 'lista todos os plugins Sigma instalados',
        'method_desc_backends': 'lista backends de conversão disponíveis (splunk, elastic, kql…)',
        'method_desc_pipelines': 'lista pipelines de mapeamento de campos disponíveis',
        'method_desc_validate': 'valida uma regra Sigma em YAML',
        'method_desc_convert': 'converte uma regra Sigma para o backend de destino',
        'try_button': '▶  testar',
        'try_back': '← voltar',
        'try_title': 'conversor Sigma ao vivo',
        'try_token_label': 'token',
        'try_token_no_auth': 'autenticação não configurada',
        'try_rule_placeholder': 'cole uma regra Sigma aqui...',
        'try_result_placeholder': 'a saída convertida aparecerá aqui',
        'try_backend_label': 'backend',
        'try_pipeline_label': 'pipeline',
        'try_pipeline_none': 'nenhuma',
        'try_convert_btn': 'converter →',
        'try_loading': 'convertendo...',
        'try_error_empty_rule': 'forneça uma regra Sigma.',
        'try_error_no_backend': 'selecione um backend.',
        'footer_coded': 'feito com',
        'footer_by': 'por',
        'footer_license': 'licença MIT',
        'footer_project': 'projeto',
    },
    'de': {
        'language_label': 'sprache',
        'version': 'version',
        'status': 'status',
        'primary_endpoint': 'haupt-endpunkt:',
        'health_endpoint': 'health-endpunkt:',
        'methods_title': 'verfügbare JSON-RPC-methoden',
        'examples_title': 'schnelle cURL-beispiele',
        'copy_button': 'cURL-beispiel kopieren',
        'copied_button': 'kopiert',
        'note_label': 'hinweis:',
        'note_text': 'dieser dienst stellt JSON-RPC 2.0 bereit unter',
        'note_text_tail': 'HTTP-endpunkte sind Hilfsendpunkte für betrieb und menschen.',
        'http_endpoints_title': 'HTTP-endpunkte',
        'endpoint_home': 'startseite · diese seite',
        'endpoint_health': 'gesundheit · dienststatus und sigma-verfügbarkeit',
        'endpoint_version': 'dienstname und version',
        'endpoint_jsonrpc': 'JSON-RPC 2.0 · haupteinstieg für konvertierung',
        'method_desc_discover': 'liefert metadaten, verfügbare methoden und aktive fähigkeiten',
        'method_desc_plugins': 'listet alle installierten Sigma-plugins auf',
        'method_desc_backends': 'listet verfügbare konvertierungs-backends auf (splunk, elastic, kql…)',
        'method_desc_pipelines': 'listet verfügbare feldzuordnungs-pipelines auf',
        'method_desc_validate': 'validiert eine Sigma-regel im YAML-format',
        'method_desc_convert': 'konvertiert eine Sigma-regel in ein ziel-backend-format',
        'try_button': '▶  testen',
        'try_back': '← zurück',
        'try_title': 'Sigma-live-konverter',
        'try_token_label': 'token',
        'try_token_no_auth': 'keine authentifizierung konfiguriert',
        'try_rule_placeholder': 'füge hier eine Sigma-regel ein...',
        'try_result_placeholder': 'die konvertierte ausgabe erscheint hier',
        'try_backend_label': 'backend',
        'try_pipeline_label': 'pipeline',
        'try_pipeline_none': 'keine',
        'try_convert_btn': 'konvertieren →',
        'try_loading': 'konvertiere...',
        'try_error_empty_rule': 'bitte eine Sigma-regel eingeben.',
        'try_error_no_backend': 'bitte ein backend auswählen.',
        'footer_coded': 'mit liebe entwickelt',
        'footer_by': 'von',
        'footer_license': 'MIT-lizenz',
        'footer_project': 'projekt',
    },
    'ru': {
        'language_label': 'yazyk',
        'version': 'versiya',
        'status': 'status',
        'primary_endpoint': 'osnovnoy endpoint:',
        'health_endpoint': 'endpoint zdorovya:',
        'methods_title': 'dostupnye metody JSON-RPC',
        'examples_title': 'bystrye primery cURL',
        'copy_button': 'kopirovat primer cURL',
        'copied_button': 'skopirovano',
        'note_label': 'primechanie:',
        'note_text': 'etot servis predostavlyaet JSON-RPC 2.0 na',
        'note_text_tail': 'HTTP-endpointy yavlyayutsya vspomogatelnymi dlya operatsiy i lyudey.',
        'http_endpoints_title': 'HTTP-endpointy',
        'endpoint_home': 'domashnyaya stranitsa · eta stranitsa',
        'endpoint_health': 'zdorove · status servisa i dostupnost sigma',
        'endpoint_version': 'imya i versiya servisa',
        'endpoint_jsonrpc': 'JSON-RPC 2.0 · glavnyy vhod dlya konvertatsii',
        'method_desc_discover': 'vozvrashchaet metadannye servisa, metody i aktivnye vozmozhnosti',
        'method_desc_plugins': 'pokazyvaet vse ustanovlennye pluginy Sigma',
        'method_desc_backends': 'pokazyvaet dostupnye backendy konvertatsii (splunk, elastic, kql…)',
        'method_desc_pipelines': 'pokazyvaet dostupnye pipeline dlya mapinga poley',
        'method_desc_validate': 'proveryaet pravilo Sigma v formate YAML',
        'method_desc_convert': 'konvertiruet pravilo Sigma v format vybrannogo backend',
        'try_button': '▶  probovat',
        'try_back': '← nazad',
        'try_title': 'zhivoy konverter Sigma',
        'try_token_label': 'token',
        'try_token_no_auth': 'autentifikatsiya ne nastroena',
        'try_rule_placeholder': 'vstavte pravilo Sigma syuda...',
        'try_result_placeholder': 'zdes poyavitsya rezultat konvertatsii',
        'try_backend_label': 'backend',
        'try_pipeline_label': 'pipeline',
        'try_pipeline_none': 'net',
        'try_convert_btn': 'konvertirovat →',
        'try_loading': 'konvertatsiya...',
        'try_error_empty_rule': 'ukazhite pravilo Sigma.',
        'try_error_no_backend': 'vyberite backend.',
        'footer_coded': 'sdelano s',
        'footer_by': 'ot',
        'footer_license': 'licenziya MIT',
        'footer_project': 'proekt',
    },
}


def build_http_router(
    settings: Settings,
    engine: SigmaEngine,
    dispatcher: RpcDispatcher,
    templates: Jinja2Templates,
) -> APIRouter:
    router = APIRouter()

    @router.get('/', response_class=HTMLResponse)
    async def home(request: Request) -> HTMLResponse:
        lang = _resolve_lang(request)
        ui = HOME_I18N[lang]
        token_hint = 'CHANGE_ME'
        curl_discover = _build_curl_example(
            settings.port,
            token_hint,
            '{"jsonrpc":"2.0","id":"1","method":"rpc.discover","params":{}}',
        )
        curl_backends = _build_curl_example(
            settings.port,
            token_hint,
            '{"jsonrpc":"2.0","id":"2","method":"sigma.backends.list","params":{}}',
        )

        method_descs: dict[str, str] = {
            'rpc.discover': ui['method_desc_discover'],
            'sigma.plugins.list': ui['method_desc_plugins'],
            'sigma.backends.list': ui['method_desc_backends'],
            'sigma.pipelines.list': ui['method_desc_pipelines'],
            'sigma.validate': ui['method_desc_validate'],
            'sigma.convert': ui['method_desc_convert'],
        }

        http_endpoints = [
            {'verb': 'GET',  'path': '/',        'desc': ui['endpoint_home']},
            {'verb': 'GET',  'path': '/health',  'desc': ui['endpoint_health']},
            {'verb': 'GET',  'path': '/version', 'desc': ui['endpoint_version']},
            {'verb': 'POST', 'path': '/jsonrpc', 'desc': ui['endpoint_jsonrpc']},
        ]

        auth_configured = bool((settings.sigma_rpc_token or '').strip())

        context = {
            'request': request,
            'lang': lang,
            'ui': ui,
            'language_options': LANGUAGE_OPTIONS,
            'service_name': settings.service_name,
            'service_version': settings.service_version,
            'service_description': settings.service_description,
            'status': 'ok' if engine.sigma_available() else 'degraded',
            'jsonrpc_endpoint': settings.jsonrpc_endpoint,
            'health_endpoint': '/health',
            'methods': dispatcher.supported_methods,
            'methods_detailed': [
                {'name': m, 'desc': method_descs.get(m, '')}
                for m in dispatcher.supported_methods
            ],
            'http_endpoints': http_endpoints,
            'auth_configured': auth_configured,
            'curl_discover': curl_discover,
            'curl_backends': curl_backends,
        }
        return templates.TemplateResponse('home.html', context)

    @router.get('/health', response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            status='ok' if engine.sigma_available() else 'degraded',
            service=settings.service_name,
            version=settings.service_version,
            sigma_available=engine.sigma_available(),
        )

    @router.get('/version', response_model=VersionResponse)
    async def version() -> VersionResponse:
        return VersionResponse(service=settings.service_name, version=settings.service_version)

    return router


def _build_curl_example(port: int, token_hint: str, payload: str) -> str:
    return (
        f'curl -X POST http://localhost:{port}/jsonrpc \\\n'
        '  -H "Content-Type: application/json" \\\n'
        f'  -H "Authorization: Bearer {token_hint}" \\\n'
        f"  -d '{payload}'"
    )


def _resolve_lang(request: Request) -> str:
    query_lang = (request.query_params.get('lang') or '').strip().lower()
    if query_lang in SUPPORTED_LANGS:
        return query_lang
    accept_language = (request.headers.get('accept-language') or '').strip().lower()
    for raw_part in accept_language.split(','):
        code = raw_part.strip().split(';', 1)[0].split('-', 1)[0]
        if code in SUPPORTED_LANGS:
            return code
    return DEFAULT_LANG
