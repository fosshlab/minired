"""Sesión de captura: un capturador por extremo de cada enlace, correlación en vivo y PCAPng."""

import os
import shutil
import tempfile
import threading
import time

from . import disector
from .capturador import Capturador
from .correlador import Correlador, Observacion
from .decodificar import decodificar
from .pcap import escribir_pcapng, leer_archivo


class ErrorCaptura(Exception):
    pass


class SesionCaptura:
    MAX_OBSERVACIONES = 5000
    INTERVALO_S = 0.1

    def __init__(self, plan, popen, publicar, directorio_base=None, reloj=time.time_ns, en_espera=()):
        """popen(nodo_id, argv, **kw): proceso en el namespace del nodo.
        publicar(dict): envía un evento a la interfaz (debe ser seguro entre hilos).
        en_espera: enlaces caídos al empezar; tcpdump no abre una interfaz caída
        ("That device is not up"), así que sus extremos arrancan en activar_enlace().
        """
        self.en_espera = set(en_espera)
        self.plan = plan
        self._popen = popen
        self._publicar = publicar
        self._reloj = reloj
        self.directorio = tempfile.mkdtemp(prefix='minired-captura-', dir=directorio_base)  # 0700
        self.correlador = Correlador({n.id: n.tipo for n in plan.lab.nodos})
        self.observaciones = []
        self.por_id = {}
        self._por_registro = {}       # (archivo, n) -> Observacion
        self.descartadas_vista = 0
        self.t0_ns = None
        self.activa = False
        self._seq = 0
        self._lock = threading.Lock()
        self._fin = threading.Event()
        self._ticker = None
        self._capas = {}
        extremos = sorted(plan.por_intf.values(), key=lambda e: (e.enlace, e.extremo))
        self.capturadores = [Capturador(ep, os.path.join(self.directorio, ep.intf + '.pcap'),
                                        self._al_recibir) for ep in extremos]

    # --- ciclo de vida -----------------------------------------------------

    def iniciar(self, timeout=5.0):
        self.t0_ns = self._reloj()
        try:
            activos = [c for c in self.capturadores if c.extremo.enlace not in self.en_espera]
            self._arrancar(activos, timeout)
        except Exception:
            for cap in self.capturadores:
                cap.detener()
            raise
        self.activa = True
        self._ticker = threading.Thread(target=self._bucle, name='captura-correlador', daemon=True)
        self._ticker.start()

    def activar_enlace(self, enlace_id, timeout=5.0):
        """Arranca los capturadores que esperaban a que este enlace se suba."""
        if not self.activa or enlace_id not in self.en_espera:
            return
        self.en_espera.discard(enlace_id)
        self._arrancar([c for c in self.capturadores
                        if c.extremo.enlace == enlace_id and c.proceso is None], timeout)

    def _arrancar(self, capturadores, timeout):
        for cap in capturadores:
            cap.iniciar(lambda argv, _ep=cap.extremo, **kw: self._popen(_ep.nodo, argv, **kw))
        limite = time.monotonic() + timeout
        for cap in capturadores:
            cap.esperar_listo(max(0.0, limite - time.monotonic()))
            if cap.proceso.poll() is not None:
                raise ErrorCaptura('tcpdump en %s terminó: %s' % (cap.extremo.intf, cap.mensaje_error()))
            if not cap._listo.is_set():
                raise ErrorCaptura('tcpdump en %s no empezó a capturar a tiempo' % cap.extremo.intf)

    def detener(self):
        if not self.activa:
            return
        for cap in self.capturadores:
            cap.detener()
        self._fin.set()
        self._ticker.join()
        with self._lock:
            self._guardar(self.correlador.confirmar_todo())
        self.activa = False
        self._publicar({'tipo': 'captura', **self.estado()})

    def descartar(self):
        self.detener()
        shutil.rmtree(self.directorio, ignore_errors=True)

    # --- datos en vivo -----------------------------------------------------

    def _al_recibir(self, ep, reg):
        opuesto = self.plan.extremo_opuesto(ep.enlace, ep.extremo)
        resumen = decodificar(reg.datos)
        with self._lock:
            self._seq += 1
            obs = Observacion(self._seq, reg.ts_ns, ep.enlace, ep.extremo, ep.nodo, opuesto.nodo,
                              ep.intf, reg.datos, reg.largo_original, ep.intf + '.pcap', reg.n, resumen)
            self.correlador.agregar(obs)

    def _bucle(self):
        while not self._fin.wait(self.INTERVALO_S):
            with self._lock:
                self._guardar(self.correlador.confirmar(self._reloj()))

    def _guardar(self, confirmadas):
        nuevas = []
        for obs in confirmadas:
            if len(self.observaciones) >= self.MAX_OBSERVACIONES:
                self.descartadas_vista += 1
                continue
            self.observaciones.append(obs)
            self.por_id[obs.id] = obs
            self._por_registro[(obs.pcap_archivo, obs.pcap_n)] = obs
            nuevas.append(obs.a_dict(self.t0_ns))
        if nuevas or confirmadas:
            self._publicar({'tipo': 'observaciones', 'items': nuevas,
                            'descartadas_vista': self.descartadas_vista})

    # --- consultas ---------------------------------------------------------

    def lista(self, desde=0):
        """Observaciones confirmadas en orden de tiempo, a partir de la posición `desde`."""
        with self._lock:
            return [o.a_dict(self.t0_ns) for o in self.observaciones[desde:]]

    def estado(self):
        return {
            'activa': self.activa,
            'observaciones': len(self.observaciones),
            'descartadas_vista': self.descartadas_vista,
            'capturadores': [c.estadisticas() for c in self.capturadores],
        }

    def capas(self, obs_id):
        obs = self.por_id.get(obs_id)
        if obs is None:
            return None
        if obs_id not in self._capas:
            self._capas[obs_id] = disector.disecar(obs.ts_ns, obs.largo, obs.datos)
        return {'id': obs.id, 'intf': obs.intf, 'pcap': {'archivo': obs.pcap_archivo, 'n': obs.pcap_n},
                'hex': obs.datos.hex(), 'capas': self._capas[obs_id]}

    def escribir_pcapng(self, f):
        """Une los PCAP de todos los extremos en un PCAPng ordenado por tiempo.

        Cada frame queda en la interfaz donde se capturó, marcado como entrada,
        con el comentario "<observación> <paquete lógico>" que usa la interfaz web.
        """
        interfaces = []
        paquetes = []
        for idx, cap in enumerate(self.capturadores):
            ep = cap.extremo
            opuesto = self.plan.extremo_opuesto(ep.enlace, ep.extremo)
            interfaces.append((ep.intf, 'enlace %s: llega a %s desde %s'
                               % (ep.enlace, ep.nombre_nodo, opuesto.nombre_nodo)))
            if not os.path.exists(cap.ruta):
                continue
            archivo = os.path.basename(cap.ruta)
            for reg in leer_archivo(cap.ruta):
                obs = self._por_registro.get((archivo, reg.n))
                comentario = None
                if obs is not None:
                    comentario = 'minired %s %s %s' % (obs.id, obs.paquete, obs.confianza)
                paquetes.append((idx, reg.ts_ns, reg.largo_original, reg.datos, comentario))
        paquetes.sort(key=lambda p: p[1])
        escribir_pcapng(f, interfaces, paquetes)
        return len(paquetes)
