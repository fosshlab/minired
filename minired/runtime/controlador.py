"""Estado de la aplicación: laboratorio en diseño, red en marcha, captura y terminales.

Las operaciones que tocan Mininet se ejecutan en el Worker. Las de ciclo de
vida se serializan con un candado asyncio para que dos clics no se crucen.
"""

import asyncio
import fcntl
import os
import pty
import struct
import termios

from ..captura.sesion_captura import SesionCaptura
from ..modelo.a_mininet import planificar
from ..modelo.topologia import Lab
from .procesos import matar_sesion
from .worker import Worker

DISENO = 'diseño'
INICIANDO = 'iniciando'
ACTIVA = 'activa'
DETENIENDO = 'deteniendo'
ERROR = 'error'


class Conflicto(Exception):
    """Operación no permitida en el estado actual (HTTP 409)."""


class Bus:
    """Difunde eventos a los WebSocket conectados. publicar() se puede llamar desde cualquier hilo."""

    MAX_COLA = 2000

    def __init__(self, loop):
        self.loop = loop
        self.colas = set()

    def suscribir(self):
        cola = asyncio.Queue(self.MAX_COLA)
        cola.perdidos = 0
        self.colas.add(cola)
        return cola

    def desuscribir(self, cola):
        self.colas.discard(cola)

    def publicar(self, msg):
        try:
            self.loop.call_soon_threadsafe(self._difundir, msg)
        except RuntimeError:      # loop cerrado al apagar
            pass

    def _difundir(self, msg):
        for cola in list(self.colas):
            try:
                cola.put_nowait(msg)
            except asyncio.QueueFull:
                cola.perdidos += 1     # el WS lo avisa; la lista completa sigue en /api/captura


class Terminal:
    def __init__(self, proceso, maestro):
        self.proceso = proceso
        self.maestro = maestro
        self.cerrada = False

    def redimensionar(self, filas, columnas):
        filas = max(1, min(int(filas), 500))
        columnas = max(1, min(int(columnas), 1000))
        fcntl.ioctl(self.maestro, termios.TIOCSWINSZ, struct.pack('HHHH', filas, columnas, 0, 0))

    def cerrar(self):
        if self.cerrada:
            return
        self.cerrada = True
        matar_sesion(self.proceso.pid)
        try:
            os.close(self.maestro)
        except OSError:
            pass
        try:
            self.proceso.wait(5)
        except Exception:
            pass


class Controlador:
    def __init__(self, fabrica_red, directorio_capturas=None, fabrica_captura=SesionCaptura):
        self.fabrica_red = fabrica_red
        self.fabrica_captura = fabrica_captura
        self.directorio_capturas = directorio_capturas
        self.worker = Worker()
        self.lab = Lab()
        self.estado = DISENO
        self.error = None
        self.plan = None
        self.red = None
        self.captura = None
        self.terminales = set()
        self.enlaces_caidos = set()   # enlaces bajados a mano con la red activa
        self.bus = None
        self._candado = asyncio.Lock()

    def conectar_bus(self, loop):
        self.bus = Bus(loop)

    def publicar(self, msg):
        if self.bus is not None:
            self.bus.publicar(msg)

    def estado_dict(self):
        return {
            'tipo': 'estado',
            'estado': self.estado,
            'error': self.error,
            'enlaces': self.plan.mapa_publico() if self.plan else None,
            'enlaces_caidos': sorted(self.enlaces_caidos),
            'captura': self.captura.estado() if self.captura else None,
        }

    def _cambiar(self, estado, error=None):
        self.estado = estado
        self.error = error
        self.publicar(self.estado_dict())

    # --- laboratorio y red -------------------------------------------------

    async def guardar_lab(self, lab):
        async with self._candado:
            if self.estado not in (DISENO, ERROR):
                raise Conflicto('detené la red antes de cambiar la topología')
            self.lab = lab
            if self.estado == ERROR:
                self._cambiar(DISENO)

    async def iniciar(self):
        async with self._candado:
            if self.estado not in (DISENO, ERROR):
                raise Conflicto('la red ya está %s' % self.estado)
            if not self.lab.nodos:
                raise Conflicto('el laboratorio está vacío')
            plan = planificar(self.lab)
            red = self.fabrica_red(plan)
            self._cambiar(INICIANDO)
            try:
                await self.worker.run(red.iniciar)
            except Exception as exc:
                self._cambiar(ERROR, 'no se pudo iniciar la red: %s' % exc)
                raise
            self.plan, self.red = plan, red
            self.enlaces_caidos = set()
            self._cambiar(ACTIVA)

    async def detener(self):
        async with self._candado:
            if self.estado != ACTIVA:
                raise Conflicto('la red no está activa')
            self._cambiar(DETENIENDO)
            try:
                for terminal in list(self.terminales):
                    terminal.cerrar()
                self.terminales.clear()
                await self._detener_captura()
                await self.worker.run(self.red.detener)
            except Exception as exc:
                self._cambiar(ERROR, 'error al detener la red: %s' % exc)
                raise
            finally:
                if self.captura is not None:
                    await asyncio.to_thread(self.captura.descartar)
                    self.captura = None
                self.red = None
                self.plan = None
                self.enlaces_caidos = set()
            self._cambiar(DISENO)

    async def apagar(self):
        if self.estado == ACTIVA:
            try:
                await self.detener()
            except Exception:
                pass
        self.worker.cerrar(5)

    def _exigir_activa(self):
        if self.estado != ACTIVA:
            raise Conflicto('primero iniciá la red')

    # --- acciones ----------------------------------------------------------

    async def ping(self, nodo_id, destino, cantidad):
        self._exigir_activa()
        nodo = self.lab.nodo(nodo_id)
        if nodo is None or nodo.tipo.value == 'switch':
            raise Conflicto('solo PC y routers hacen ping')
        return await self.worker.run(lambda: self.red.ping(nodo_id, destino, cantidad))

    async def dhcp(self, nodo_id):
        self._exigir_activa()
        nodo = self.lab.nodo(nodo_id)
        if nodo is None or not nodo.dhcp:
            raise Conflicto('esa PC no está configurada para pedir IP por DHCP')
        return await self.worker.run(lambda: self.red.dhcp(nodo_id))

    async def diagnostico(self, nodo_id):
        self._exigir_activa()
        return await self.worker.run(lambda: self.red.diagnostico(nodo_id))

    async def enlace(self, enlace_id, arriba):
        self._exigir_activa()
        if enlace_id not in self.plan.enlaces:
            raise KeyError(enlace_id)
        await self.worker.run(lambda: self.red.enlace(enlace_id, arriba))
        if arriba:
            self.enlaces_caidos.discard(enlace_id)
        else:
            self.enlaces_caidos.add(enlace_id)
        self.publicar(self.estado_dict())
        return self.estado_dict()

    # --- captura (modo simulación) -----------------------------------------

    async def iniciar_captura(self):
        async with self._candado:
            self._exigir_activa()
            if self.captura is not None and self.captura.activa:
                raise Conflicto('la captura ya está en marcha')
            if self.captura is not None:
                await asyncio.to_thread(self.captura.descartar)
                self.captura = None
            red = self.red
            sesion = self.fabrica_captura(self.plan, lambda nodo, argv, **kw: red.popen(nodo, argv, **kw),
                                          self.publicar, self.directorio_capturas)
            try:
                await self.worker.run(sesion.iniciar)
            except Exception:
                await asyncio.to_thread(sesion.descartar)
                raise
            self.captura = sesion
            self.publicar({'tipo': 'captura', 'reinicio': True, **sesion.estado()})
            self.publicar(self.estado_dict())

    async def detener_captura(self):
        async with self._candado:
            if self.captura is None or not self.captura.activa:
                raise Conflicto('no hay una captura en marcha')
            await self._detener_captura()
            self.publicar(self.estado_dict())

    async def _detener_captura(self):
        if self.captura is not None and self.captura.activa:
            await asyncio.to_thread(self.captura.detener)

    # --- terminales --------------------------------------------------------

    async def abrir_terminal(self, nodo_id):
        self._exigir_activa()

        def crear():
            maestro, esclavo = pty.openpty()
            try:
                proceso = self.red.popen_terminal(nodo_id, esclavo)
            except Exception:
                os.close(maestro)
                raise
            finally:
                os.close(esclavo)
            return Terminal(proceso, maestro)

        terminal = await self.worker.run(crear)
        self.terminales.add(terminal)
        return terminal

    def cerrar_terminal(self, terminal):
        terminal.cerrar()
        self.terminales.discard(terminal)
