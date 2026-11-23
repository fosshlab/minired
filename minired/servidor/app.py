"""Aplicación FastAPI: API REST, WebSocket de eventos y de terminal, y la interfaz compilada."""

import asyncio
import contextlib
import io
import json
import os
from ipaddress import IPv4Address

from fastapi import FastAPI, HTTPException, Path, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field, ValidationError

from ..captura.disector import ErrorDisector
from ..modelo.topologia import ID_RE, Lab
from ..runtime.controlador import Conflicto
from .seguridad import (CABECERAS_SEGURIDAD, SUBPROTOCOLO, MiddlewareSeguridad,
                        politica_contenido)

DIST = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'gui', 'dist')

MENSAJES = {
    'string_pattern_mismatch': 'formato inválido',
    'ip_v4_interface': 'no es una IPv4 con prefijo válida',
    'ip_v4_address': 'no es una dirección IPv4 válida',
    'extra_forbidden': 'campo no permitido',
    'missing': 'falta este dato',
    'too_long': 'demasiados elementos',
    'literal_error': 'valor no permitido',
    'enum': 'tipo no permitido',
}


def errores_en_espanol(exc, datos=None):
    errores = []
    for e in exc.errors():
        if e['type'] == 'value_error':
            msg = str(e.get('ctx', {}).get('error', e['msg']))
        else:
            msg = MENSAJES.get(e['type'], e['msg'])
        loc = list(e['loc'])
        lugar = _lugar(loc, datos)
        errores.extend(m for m in ([('%s: %s' % (lugar, msg)) if lugar else msg]) if m)
    # un error de coherencia trae varios separados por "; "
    return [parte for err in errores for parte in err.split('; ')]


def _lugar(loc, datos):
    if not loc:
        return ''
    if isinstance(datos, dict) and len(loc) >= 2 and loc[0] in ('nodos', 'enlaces') and isinstance(loc[1], int):
        try:
            item = datos[loc[0]][loc[1]]
            nombre = item.get('nombre') or item.get('id')
            return ' '.join(str(x) for x in [nombre] + loc[2:])
        except (KeyError, IndexError, TypeError, AttributeError):
            pass
    return '.'.join(str(x) for x in loc)


class PedidoPing(BaseModel):
    destino: IPv4Address
    cantidad: int = Field(default=1, ge=1, le=5)


class PedidoEnlace(BaseModel):
    arriba: bool


ID = Path(pattern=ID_RE)


def crear_app(controlador, config):
    @contextlib.asynccontextmanager
    async def vida(app):
        controlador.conectar_bus(asyncio.get_running_loop())
        yield
        await controlador.apagar()

    app = FastAPI(title='minired', debug=False, lifespan=vida, docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.controlador = controlador
    app.state.config = config
    app.add_middleware(MiddlewareSeguridad, config=config)

    @app.middleware('http')
    async def cabeceras(request: Request, call_next):
        resp = await call_next(request)
        for k, v in CABECERAS_SEGURIDAD.items():
            resp.headers.setdefault(k, v)
        resp.headers.setdefault('Content-Security-Policy', politica_contenido(config))
        return resp

    @app.exception_handler(Conflicto)
    async def _conflicto(request, exc):
        return JSONResponse({'detalle': str(exc)}, status_code=409)

    # --- laboratorio y red -------------------------------------------------

    @app.get('/api/estado')
    async def estado():
        return controlador.estado_dict()

    @app.get('/api/lab')
    async def leer_lab():
        return controlador.lab.model_dump(mode='json')

    async def _leer_lab(request):
        try:
            datos = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(400, 'el cuerpo no es JSON') from None
        try:
            return Lab.model_validate(datos), []
        except ValidationError as exc:
            return None, errores_en_espanol(exc, datos)

    @app.post('/api/lab/validar')
    async def validar(request: Request):
        lab, errores = await _leer_lab(request)
        return {'ok': lab is not None, 'errores': errores}

    @app.put('/api/lab')
    async def guardar(request: Request):
        lab, errores = await _leer_lab(request)
        if lab is None:
            return JSONResponse({'detalle': 'laboratorio inválido', 'errores': errores}, status_code=422)
        await controlador.guardar_lab(lab)
        return {'ok': True}

    @app.post('/api/red/iniciar')
    async def iniciar():
        try:
            await controlador.iniciar()
        except Conflicto:
            raise
        except Exception as exc:
            return JSONResponse({'detalle': controlador.error or str(exc)}, status_code=500)
        return controlador.estado_dict()

    @app.post('/api/red/detener')
    async def detener():
        try:
            await controlador.detener()
        except Conflicto:
            raise
        except Exception as exc:
            return JSONResponse({'detalle': controlador.error or str(exc)}, status_code=500)
        return controlador.estado_dict()

    @app.post('/api/nodos/{nodo_id}/ping')
    async def ping(pedido: PedidoPing, nodo_id: str = ID):
        if controlador.lab.nodo(nodo_id) is None:
            raise HTTPException(404, 'nodo inexistente')
        return await controlador.ping(nodo_id, pedido.destino, pedido.cantidad)

    @app.post('/api/enlaces/{enlace_id}/estado')
    async def estado_enlace(pedido: PedidoEnlace, enlace_id: str = ID):
        try:
            await controlador.enlace(enlace_id, pedido.arriba)
        except KeyError:
            raise HTTPException(404, 'enlace inexistente') from None
        return {'ok': True}

    # --- captura -----------------------------------------------------------

    @app.post('/api/captura/iniciar')
    async def captura_iniciar():
        try:
            await controlador.iniciar_captura()
        except Conflicto:
            raise
        except Exception as exc:
            return JSONResponse({'detalle': 'no se pudo iniciar la captura: %s' % exc}, status_code=500)
        return controlador.captura.estado()

    @app.post('/api/captura/detener')
    async def captura_detener():
        await controlador.detener_captura()
        return controlador.captura.estado()

    def _sesion():
        if controlador.captura is None:
            raise HTTPException(404, 'no hay captura')
        return controlador.captura

    @app.get('/api/captura/observaciones')
    async def observaciones(desde: int = Query(0, ge=0)):
        sesion = _sesion()
        return {'items': sesion.lista(desde), **sesion.estado()}

    @app.get('/api/captura/observaciones/{obs_id}/capas')
    async def capas(obs_id: str = Path(pattern=r'^o[0-9]{1,9}$')):
        sesion = _sesion()
        try:
            datos = await asyncio.to_thread(sesion.capas, obs_id)
        except ErrorDisector as exc:
            raise HTTPException(500, str(exc)) from None
        if datos is None:
            raise HTTPException(404, 'observación inexistente')
        return datos

    @app.get('/api/captura/pcap')
    async def pcap():
        sesion = _sesion()
        buf = io.BytesIO()
        await asyncio.to_thread(sesion.escribir_pcapng, buf)
        return Response(buf.getvalue(), media_type='application/octet-stream',
                        headers={'Content-Disposition': 'attachment; filename="minired-captura.pcapng"'})

    # --- WebSocket ---------------------------------------------------------

    @app.websocket('/ws/eventos')
    async def ws_eventos(ws: WebSocket):
        await ws.accept(subprotocol=SUBPROTOCOLO)
        cola = controlador.bus.suscribir()
        try:
            await ws.send_json(controlador.estado_dict())
            if controlador.captura is not None:
                await ws.send_json({'tipo': 'observaciones', 'reinicio': True,
                                    'items': controlador.captura.lista(0),
                                    'descartadas_vista': controlador.captura.descartadas_vista})
            avisados = 0
            while True:
                msg = await cola.get()
                if cola.perdidos != avisados:
                    avisados = cola.perdidos
                    await ws.send_json({'tipo': 'aviso', 'perdidos': avisados,
                                        'texto': 'la vista en vivo perdió eventos; se recarga la lista'})
                await ws.send_json(msg)
        except WebSocketDisconnect:
            pass
        finally:
            controlador.bus.desuscribir(cola)

    @app.websocket('/ws/terminal/{nodo_id}')
    async def ws_terminal(ws: WebSocket, nodo_id: str):
        nodo = controlador.lab.nodo(nodo_id)
        await ws.accept(subprotocol=SUBPROTOCOLO)
        if nodo is None or nodo.tipo.value == 'switch':
            await ws.close(4404, 'solo PC y routers tienen terminal')
            return
        try:
            terminal = await controlador.abrir_terminal(nodo_id)
        except Exception as exc:
            await ws.close(4409, str(exc)[:120])
            return
        await _puente_pty(ws, controlador, terminal)

    # --- interfaz compilada ------------------------------------------------

    if os.path.isdir(DIST):
        @app.get('/{ruta:path}', include_in_schema=False)
        async def estaticos(ruta: str):
            destino = os.path.realpath(os.path.join(DIST, ruta))
            if ruta and destino.startswith(os.path.realpath(DIST) + os.sep) and os.path.isfile(destino):
                return FileResponse(destino)
            return FileResponse(os.path.join(DIST, 'index.html'))

    return app


async def _puente_pty(ws, controlador, terminal):
    loop = asyncio.get_running_loop()
    salida = asyncio.Queue(256)

    def legible():
        if salida.full():
            loop.remove_reader(terminal.maestro)      # contrapresión: se reanuda al vaciar
            salida.reanudar = True
            return
        try:
            datos = os.read(terminal.maestro, 65536)
        except OSError:                               # EIO: bash terminó y se cerró el esclavo
            datos = b''
        if not datos:
            loop.remove_reader(terminal.maestro)
        salida.put_nowait(datos)

    salida.reanudar = False
    loop.add_reader(terminal.maestro, legible)

    async def hacia_navegador():
        while True:
            datos = await salida.get()
            if salida.reanudar and salida.qsize() < 128:
                salida.reanudar = False
                loop.add_reader(terminal.maestro, legible)
            if not datos:
                await ws.close(1000, 'terminal cerrada')
                return
            await ws.send_bytes(datos)

    tarea = asyncio.create_task(hacia_navegador())
    try:
        while True:
            msg = await ws.receive()
            if msg['type'] == 'websocket.disconnect':
                break
            if msg.get('bytes') is not None:
                os.write(terminal.maestro, msg['bytes'])
            elif msg.get('text') is not None:
                try:
                    ctl = json.loads(msg['text'])
                    if ctl.get('tipo') == 'resize':
                        terminal.redimensionar(ctl['filas'], ctl['columnas'])
                except (ValueError, KeyError, TypeError):
                    pass
    except (WebSocketDisconnect, OSError, RuntimeError):
        pass
    finally:
        tarea.cancel()
        with contextlib.suppress(Exception):
            loop.remove_reader(terminal.maestro)
        controlador.cerrar_terminal(terminal)

