"""Seguridad del servidor local.

El backend corre como root y ofrece terminales: ninguna página web ajena debe
poder usarlo. Por eso:

- escucha solo en 127.0.0.1;
- exige el Host esperado (frena el DNS rebinding);
- la API REST pide el token en `Authorization: Bearer <token>`; si llega un
  Origin, tiene que ser el nuestro. No hay CORS: el navegador no deja que otra
  página mande esa cabecera;
- los WebSocket (a los que el navegador no les aplica CORS) exigen Origin
  propio y el token como subprotocolo `token.<token>`.
"""

import secrets
from dataclasses import dataclass, field

from starlette.responses import PlainTextResponse

SUBPROTOCOLO = 'minired'


def nuevo_token():
    return secrets.token_urlsafe(32)


@dataclass
class Config:
    puerto: int
    token: str
    origenes_extra: list = field(default_factory=list)

    @property
    def origenes(self):
        return {'http://127.0.0.1:%d' % self.puerto, 'http://localhost:%d' % self.puerto,
                *self.origenes_extra}

    @property
    def hosts(self):
        return {'127.0.0.1:%d' % self.puerto, 'localhost:%d' % self.puerto}

    def token_valido(self, candidato):
        return bool(candidato) and secrets.compare_digest(candidato.encode(), self.token.encode())


def _cabeceras(scope):
    return {k.decode('latin-1').lower(): v.decode('latin-1') for k, v in scope.get('headers', [])}


def token_de_subprotocolos(valor):
    for parte in (valor or '').split(','):
        parte = parte.strip()
        if parte.startswith('token.'):
            return parte[len('token.'):]
    return None


class MiddlewareSeguridad:
    def __init__(self, app, config):
        self.app = app
        self.config = config

    async def __call__(self, scope, receive, send):
        if scope['type'] not in ('http', 'websocket'):
            return await self.app(scope, receive, send)
        cab = _cabeceras(scope)
        motivo = self._rechazo(scope, cab)
        if motivo is None:
            return await self.app(scope, receive, send)
        if scope['type'] == 'websocket':
            await receive()      # websocket.connect
            await send({'type': 'websocket.close', 'code': 4403, 'reason': motivo})
            return
        resp = PlainTextResponse(motivo, status_code=401 if 'token' in motivo else 403)
        await resp(scope, receive, send)

    def _rechazo(self, scope, cab):
        if cab.get('host') not in self.config.hosts:
            return 'host no permitido'
        origen = cab.get('origin')
        ruta = scope.get('path', '')
        if scope['type'] == 'websocket':
            if origen not in self.config.origenes:
                return 'origen no permitido'
            if not self.config.token_valido(token_de_subprotocolos(cab.get('sec-websocket-protocol'))):
                return 'token inválido'
            return None
        if origen is not None and origen not in self.config.origenes:
            return 'origen no permitido'
        if ruta.startswith('/api/'):
            auth = cab.get('authorization', '')
            if not auth.startswith('Bearer ') or not self.config.token_valido(auth[len('Bearer '):]):
                return 'falta el token o es inválido'
        return None


CABECERAS_SEGURIDAD = {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Cache-Control': 'no-store',
}


def politica_contenido(config):
    ws = ' '.join('ws://%s' % h for h in sorted(config.hosts))
    return ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' %s; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'none'" % ws)
