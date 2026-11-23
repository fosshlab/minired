"""Un tcpdump por extremo de enlace, capturando solo lo que LLEGA a esa interfaz (-Q in).

tcpdump escribe el PCAP por stdout; un hilo lo guarda tal cual en el archivo
del extremo (el original, para auditar) y a la vez lo decodifica en vivo.
"""

import os
import re
import shutil
import subprocess
import threading

from .pcap import LectorIncremental

RE_CAIDOS = re.compile(rb'(\d+) packets? dropped by kernel')
RE_CAPTURADOS = re.compile(rb'(\d+) packets? captured')


def argv_tcpdump(intf, tcpdump=None):
    return [tcpdump or shutil.which('tcpdump') or 'tcpdump', '-i', intf, '-Q', 'in', '-U', '-n',
            '-s', '0', '--immediate-mode', '--time-stamp-precision=nano', '-w', '-']


class Capturador:
    def __init__(self, extremo, ruta, al_recibir):
        """extremo: ExtremoPlan; ruta: archivo .pcap; al_recibir(extremo, registro) por cada frame."""
        self.extremo = extremo
        self.ruta = ruta
        self.al_recibir = al_recibir
        self.proceso = None
        self.error = None
        self.caidos_kernel = None
        self.capturados = None
        self._stderr = b''
        self._listo = threading.Event()
        self._hilos = []

    def iniciar(self, popen):
        """popen(argv, **kw) lanza el proceso en el namespace correcto."""
        self.proceso = popen(argv_tcpdump(self.extremo.intf), stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, bufsize=0)
        for destino in (self._leer_stdout, self._leer_stderr):
            hilo = threading.Thread(target=destino, daemon=True,
                                    name='captura-%s' % self.extremo.intf)
            hilo.start()
            self._hilos.append(hilo)

    def esperar_listo(self, timeout):
        return self._listo.wait(timeout)

    def _leer_stderr(self):
        for linea in iter(self.proceso.stderr.readline, b''):
            self._stderr += linea
            if b'listening on' in linea:
                self._listo.set()
        self._listo.set()

    def _leer_stdout(self):
        lector = LectorIncremental()
        fd = self.proceso.stdout.fileno()
        with open(self.ruta, 'wb') as archivo:
            while True:
                trozo = os.read(fd, 65536)
                if not trozo:
                    break
                archivo.write(trozo)
                archivo.flush()
                try:
                    for reg in lector.alimentar(trozo):
                        self.al_recibir(self.extremo, reg)
                except Exception as exc:  # flujo corrupto: se deja de decodificar, el archivo sigue
                    self.error = str(exc)
                    self._volcar_resto(fd, archivo)
                    break

    @staticmethod
    def _volcar_resto(fd, archivo):
        while True:
            trozo = os.read(fd, 65536)
            if not trozo:
                return
            archivo.write(trozo)

    def detener(self, timeout=5):
        if self.proceso is None:
            return
        if self.proceso.poll() is None:
            self.proceso.terminate()
        try:
            self.proceso.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proceso.kill()
            self.proceso.wait()
        for hilo in self._hilos:
            hilo.join(timeout)
        m = RE_CAIDOS.search(self._stderr)
        self.caidos_kernel = int(m.group(1)) if m else None
        m = RE_CAPTURADOS.search(self._stderr)
        self.capturados = int(m.group(1)) if m else None

    def estadisticas(self):
        return {'intf': self.extremo.intf, 'enlace': self.extremo.enlace,
                'capturados': self.capturados, 'caidos_kernel': self.caidos_kernel,
                'error': self.error}

    def mensaje_error(self):
        return self._stderr.decode(errors='replace').strip()
