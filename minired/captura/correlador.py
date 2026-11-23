"""Correlación de observaciones en paquetes lógicos.

Cada observación es un frame REAL capturado al llegar a un extremo de un
enlace (tcpdump -Q in). Entonces se sabe sin ambigüedad qué enlace cruzó y en
qué sentido: lo envió el nodo del extremo opuesto. A partir de eso:

- Si el emisor es una PC o un router y no hay de dónde vino, la PC/router lo
  originó: es la raíz de un paquete lógico nuevo.
- Si el emisor es un switch, el frame tuvo que haber entrado al switch por otro
  puerto con los mismos bytes poco antes: esa observación es su padre. Si un
  switch inunda, un padre tiene varios hijos (ramas).
- Si el emisor es un router, el padre es un IPv4 que entró al router con el
  mismo contenido y un TTL mayor en uno (confianza "media": cambian MAC y TTL).
- Si no aparece un padre que debería existir (p. ej. el capturador perdió el
  frame de entrada), la observación queda "sin_correlacionar": se muestra
  suelta y no se inventa un camino.
"""

from collections import deque

from ..modelo.topologia import TipoNodo
from .decodificar import clave_ipv4_reenviada

ALTA = 'alta'
MEDIA = 'media'
SIN_CORRELACIONAR = 'sin_correlacionar'


class Observacion:
    __slots__ = ('id', 'seq', 'ts_ns', 'enlace', 'hacia', 'nodo', 'emisor', 'intf', 'datos',
                 'largo', 'pcap_archivo', 'pcap_n', 'resumen', 'paquete', 'padre', 'confianza',
                 'profundidad', '_hijos_enlaces', '_clave_ip')

    def __init__(self, seq, ts_ns, enlace, hacia, nodo, emisor, intf, datos, largo,
                 pcap_archivo, pcap_n, resumen):
        self.seq = seq
        self.id = 'o%d' % seq
        self.ts_ns = ts_ns
        self.enlace = enlace
        self.hacia = hacia            # extremo del enlace donde llegó: 'a' o 'b'
        self.nodo = nodo              # id del nodo que lo recibió
        self.emisor = emisor          # id del nodo que lo envió (extremo opuesto)
        self.intf = intf
        self.datos = datos
        self.largo = largo
        self.pcap_archivo = pcap_archivo
        self.pcap_n = pcap_n
        self.resumen = resumen
        self.paquete = None
        self.padre = None
        self.confianza = None
        self.profundidad = 0
        self._hijos_enlaces = set()
        self._clave_ip = None

    def a_dict(self, t0_ns=0):
        return {
            'id': self.id, 'seq': self.seq, 'ts_ns': str(self.ts_ns),
            't_us': (self.ts_ns - t0_ns) // 1000,
            'enlace': self.enlace, 'hacia': self.hacia, 'nodo': self.nodo, 'emisor': self.emisor,
            'intf': self.intf, 'largo': self.largo,
            'pcap': {'archivo': self.pcap_archivo, 'n': self.pcap_n},
            'resumen': self.resumen, 'paquete': self.paquete, 'padre': self.padre,
            'confianza': self.confianza, 'profundidad': self.profundidad,
        }


class Correlador:
    def __init__(self, tipos_nodo, ventana_ns=250_000_000, retardo_ns=300_000_000):
        """tipos_nodo: {id_nodo: TipoNodo}. ventana_ns: demora máxima de reenvío aceptada.

        retardo_ns: cuánto se espera antes de confirmar una observación, porque
        cada extremo tiene su propio tcpdump y las lecturas llegan desordenadas.
        """
        self.tipos = tipos_nodo
        self.ventana_ns = ventana_ns
        self.retardo_ns = retardo_ns
        self._pendientes = []
        self._recientes = {}          # id_nodo -> deque de observaciones que llegaron a ese nodo
        self._n_paquetes = 0
        self.ultimo_confirmado_ns = 0

    def agregar(self, obs):
        self._pendientes.append(obs)

    def confirmar(self, ahora_ns):
        """Confirma (en orden de tiempo) lo capturado hasta ahora_ns - retardo."""
        return self._confirmar_hasta(ahora_ns - self.retardo_ns)

    def confirmar_todo(self):
        return self._confirmar_hasta(None)

    def _confirmar_hasta(self, limite):
        if limite is None:
            listas, self._pendientes = self._pendientes, []
        else:
            listas = [o for o in self._pendientes if o.ts_ns <= limite]
            self._pendientes = [o for o in self._pendientes if o.ts_ns > limite]
        listas.sort(key=lambda o: (o.ts_ns, o.seq))
        for obs in listas:
            self._correlacionar(obs)
        return listas

    def _correlacionar(self, obs):
        if obs.ts_ns < self.ultimo_confirmado_ns:
            # Llegó después de confirmar observaciones posteriores: no se le busca padre
            # para no reescribir la historia que ya vio la interfaz.
            self._suelta(obs)
            self._recordar(obs)
            return
        self.ultimo_confirmado_ns = obs.ts_ns
        tipo = self.tipos.get(obs.emisor)
        padre = None
        if tipo == TipoNodo.switch:
            padre = self._buscar(obs, lambda p: p.datos == obs.datos)
            if padre is not None:
                self._enlazar(obs, padre, ALTA)
            else:
                self._suelta(obs)
        elif tipo == TipoNodo.router:
            clave = self._clave(obs)
            if clave is not None:
                padre = self._buscar(obs, lambda p: (self._clave(p) is not None
                                                     and self._clave(p)[0] == clave[0]
                                                     and self._clave(p)[1] == clave[1] + 1))
            if padre is not None:
                self._enlazar(obs, padre, MEDIA)
            else:
                self._raiz(obs)
        elif tipo == TipoNodo.pc:
            self._raiz(obs)
        else:
            self._suelta(obs)
        self._recordar(obs)

    def _buscar(self, obs, coincide):
        mejor = None
        for p in self._recientes.get(obs.emisor, ()):
            if p.enlace == obs.enlace or obs.enlace in p._hijos_enlaces:
                continue
            if not 0 <= obs.ts_ns - p.ts_ns <= self.ventana_ns:
                continue
            if coincide(p) and (mejor is None or p.ts_ns > mejor.ts_ns):
                mejor = p
        return mejor

    def _clave(self, obs):
        if obs._clave_ip is None:
            obs._clave_ip = clave_ipv4_reenviada(obs.datos) or False
        return obs._clave_ip or None

    def _enlazar(self, obs, padre, confianza):
        obs.padre = padre.id
        obs.paquete = padre.paquete
        obs.profundidad = padre.profundidad + 1
        obs.confianza = confianza
        padre._hijos_enlaces.add(obs.enlace)

    def _raiz(self, obs):
        self._n_paquetes += 1
        obs.paquete = 'p%d' % self._n_paquetes
        obs.confianza = ALTA
        obs.profundidad = 0

    def _suelta(self, obs):
        self._n_paquetes += 1
        obs.paquete = 'p%d' % self._n_paquetes
        obs.confianza = SIN_CORRELACIONAR
        obs.profundidad = 0

    def _recordar(self, obs):
        cola = self._recientes.setdefault(obs.nodo, deque())
        cola.append(obs)
        while cola and obs.ts_ns - cola[0].ts_ns > self.ventana_ns:
            cola.popleft()
