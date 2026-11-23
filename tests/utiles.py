import os


from minired.captura.correlador import Observacion
from minired.captura.decodificar import decodificar
from minired.captura.pcap import leer_archivo
from minired.modelo.a_mininet import planificar
from minired.modelo.topologia import Lab

DATOS = os.path.join(os.path.dirname(__file__), 'datos')


def lab_3pc(nombres=('xa1', 'xa2', 'xa3'), switch='xs1'):
    """3 PC + 1 switch, igual a la captura grabada en la VM (tests/datos/lan_3pc_ping)."""
    nodos = [{'id': 'sw', 'tipo': 'switch', 'nombre': switch, 'x': 0, 'y': 0}]
    enlaces = []
    for i, nombre in enumerate(nombres, start=1):
        nodos.append({'id': 'pc%d' % i, 'tipo': 'pc', 'nombre': nombre, 'x': 100 * i, 'y': 100,
                      'interfaces': [{'puerto': 0, 'ip': '10.0.0.%d/24' % i}]})
        enlaces.append({'id': 'e%d' % i, 'a': {'nodo': 'pc%d' % i, 'puerto': 0},
                        'b': {'nodo': 'sw', 'puerto': i}})
    return Lab.model_validate({'version': 1, 'nodos': nodos, 'enlaces': enlaces})


def observaciones_de(directorio, plan):
    """Lee un pcap por interfaz (nombre <intf>.pcap) y arma observaciones como lo hace la sesión."""
    obs = []
    seq = 0
    for intf, ep in sorted(plan.por_intf.items()):
        ruta = os.path.join(directorio, intf + '.pcap')
        if not os.path.exists(ruta):
            continue
        opuesto = plan.extremo_opuesto(ep.enlace, ep.extremo)
        for reg in leer_archivo(ruta):
            seq += 1
            obs.append(Observacion(seq, reg.ts_ns, ep.enlace, ep.extremo, ep.nodo, opuesto.nodo,
                                   intf, reg.datos, reg.largo_original, intf + '.pcap', reg.n,
                                   decodificar(reg.datos)))
    return obs




# --- dobles de prueba para el servidor (sin root) ---------------------------

import subprocess  # noqa: E402
import sys  # noqa: E402

TCPDUMP_FALSO = r'''
import os, sys, time, signal
signal.signal(signal.SIGTERM, lambda *a: (sys.stderr.write("%d packets captured\n0 packets dropped by kernel\n" % n), sys.exit(0)))
n = 0
sys.stderr.write("tcpdump: listening on %s\n" % sys.argv[2]); sys.stderr.flush()
time.sleep(0.2)
datos = open(sys.argv[1], "rb").read() if os.path.exists(sys.argv[1]) else b""
os.write(1, datos)
n = max(0, (len(datos) - 24) // 50)
while True:
    time.sleep(1)
'''


class RedFalsa:
    """Imita RedMininet: los 'tcpdump' reproducen las capturas reales de tests/datos."""

    def __init__(self, plan, directorio_pcap, desplazar_ns=0):
        self.plan = plan
        self.directorio = directorio_pcap
        self.iniciada = False
        self.terminales = []

    def iniciar(self):
        self.iniciada = True

    def detener(self):
        self.iniciada = False

    def popen(self, nodo_id, argv, **kw):
        intf = argv[argv.index('-i') + 1]
        ruta = os.path.join(self.directorio, intf + '.pcap')
        return subprocess.Popen([sys.executable, '-c', TCPDUMP_FALSO, ruta, intf], **kw)

    def popen_terminal(self, nodo_id, esclavo):
        import fcntl
        import termios
        return subprocess.Popen(['bash', '--norc', '--noprofile', '-i'], stdin=esclavo, stdout=esclavo,
                                stderr=esclavo, start_new_session=True,
                                preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0),
                                env={'PATH': '/usr/bin:/bin', 'PS1': 'falso$ ', 'TERM': 'dumb'})

    def ping(self, nodo_id, destino, cantidad):
        return {'codigo': 0, 'salida': 'ping %s' % destino}

    def enlace(self, enlace_id, arriba):
        pass
