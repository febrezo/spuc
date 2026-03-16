from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.auth import enforce_jsonrpc_auth
from app.config import Settings
from app.errors import (
    AuthException,
    INVALID_REQUEST,
    PARSE_ERROR,
    SERVER_AUTH_ERROR,
    RpcException,
)
from app.models import JsonRpcError, JsonRpcRequest, JsonRpcResponse
from app.rpc import RpcDispatcher

logger = logging.getLogger(__name__)


def build_jsonrpc_router(settings: Settings, dispatcher: RpcDispatcher) -> APIRouter:
    router = APIRouter()

    @router.post('/jsonrpc')
    async def jsonrpc_endpoint(request: Request) -> Response:
        try:
            enforce_jsonrpc_auth(request, settings)
        except AuthException as exc:
            payload = JsonRpcResponse(
                id=None,
                error=JsonRpcError(code=SERVER_AUTH_ERROR, message='authentication failed', data={'detail': str(exc)}),
            )
            return JSONResponse(status_code=401, content=payload.model_dump(exclude_none=False))

        try:
            body = await request.json()
        except Exception:
            payload = JsonRpcResponse(id=None, error=JsonRpcError(code=PARSE_ERROR, message='Parse error'))
            return JSONResponse(status_code=400, content=payload.model_dump(exclude_none=False))

        try:
            rpc_req = JsonRpcRequest.model_validate(body)
        except Exception:
            req_id = body.get('id') if isinstance(body, dict) else None
            payload = JsonRpcResponse(id=req_id, error=JsonRpcError(code=INVALID_REQUEST, message='Invalid Request'))
            return JSONResponse(status_code=400, content=payload.model_dump(exclude_none=False))

        try:
            result = dispatcher.dispatch(rpc_req.method, rpc_req.params)
            # Notifications should not return payload according to JSON-RPC 2.0
            if rpc_req.id is None:
                return Response(status_code=204)
            payload = JsonRpcResponse(id=rpc_req.id, result=result)
            return JSONResponse(status_code=200, content=payload.model_dump(exclude_none=False))
        except RpcException as exc:
            logger.warning('rpc error method=%s code=%s message=%s', rpc_req.method, exc.code, exc.message)
            if rpc_req.id is None:
                return Response(status_code=204)
            payload = JsonRpcResponse(
                id=rpc_req.id,
                error=JsonRpcError(code=exc.code, message=exc.message, data=exc.data),
            )
            return JSONResponse(status_code=200, content=payload.model_dump(exclude_none=False))

    return router
