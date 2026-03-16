from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.engine import SigmaEngine
from app.rpc import RpcDispatcher
from app.routes.http import build_http_router
from app.routes.jsonrpc import build_jsonrpc_router

settings = get_settings()

logging.basicConfig(
    level=settings.log_level.upper(),
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

engine = SigmaEngine(settings)
dispatcher = RpcDispatcher(settings, engine)
templates = Jinja2Templates(directory='app/templates')

app = FastAPI(
    title=settings.service_name,
    version=settings.service_version,
    description=settings.service_description,
    docs_url='/docs',
    redoc_url=None,
)


@app.on_event('startup')
def startup_event() -> None:
    logger.info('starting service %s v%s', settings.service_name, settings.service_version)
    if settings.auth_enabled:
        logger.info('jsonrpc authentication enabled')
    elif settings.auth_required:
        logger.warning('jsonrpc authentication is in insecure development mode (no token configured)')
    logger.info('jsonrpc endpoint: %s', settings.jsonrpc_endpoint)


app.include_router(build_http_router(settings, engine, dispatcher, templates))
app.include_router(build_jsonrpc_router(settings, dispatcher))
