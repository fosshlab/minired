"""Red Mininet construida desde un PlanRed. Todos sus métodos corren en el hilo del Worker.

Nunca se arma texto de shell con valores del usuario: los comandos se pasan
como lista de argumentos y los valores ya vienen validados por el modelo.
"""

import fcntl
import os
import shutil
import subprocess
import termios

from ..modelo.topologia import TipoNodo


class ErrorRed(Exception):
    pass


def _mac(indice_nodo, puerto):
    # Administrada localmente y legible: 02:00:00:00:<nodo>:<puerto>
    return '02:00:00:00:%02x:%02x' % (indice_nodo, puerto)


def _clase_router():
    """Router Linux: un Node en su namespace con reenvío IPv4 (no depende de nodelib.LinuxRouter,
    que no está en todas las versiones instaladas del fork)."""
    from mininet.node import Node

    class RouterLinux(Node):
        def config(self, **params):
            r = super().config(**params)
            self.cmd('sysctl -qw net.ipv4.ip_forward=1')
            return r

    return RouterLinux


class RedMininet:
    def __init__(self, plan):
        self.plan = plan
        self.net = None
        self._nodos = {}            # id -> nodo Mininet

    # --- ciclo de vida -----------------------------------------------------

    def iniciar(self):
        from mininet.log import setLogLevel
        from mininet.net import Mininet
        from mininet.node import OVSBridge

        setLogLevel('warning')
        self._verificar_nombres_libres()
        lab = self.plan.lab
        net = Mininet(topo=None, switch=OVSBridge, controller=None, build=False,
                      autoSetMacs=False, autoStaticArp=False, waitConnected=False)
        self.net = net
        indices = {}
        try:
            for i, nodo in enumerate(lab.nodos, start=1):
                indices[nodo.id] = i
                if nodo.tipo == TipoNodo.pc:
                    n = net.addHost(nodo.nombre, ip=None)
                elif nodo.tipo == TipoNodo.router:
                    n = net.addHost(nodo.nombre, cls=_clase_router(), ip=None)
                else:
                    n = net.addSwitch(nodo.nombre, cls=OVSBridge, dpid=self.plan.dpids[nodo.id])
                self._nodos[nodo.id] = n
            for enlace in lab.enlaces:
                a, b = self.plan.enlaces[enlace.id]
                net.addLink(self._nodos[a.nodo], self._nodos[b.nodo],
                            port1=enlace.a.puerto, port2=enlace.b.puerto,
                            intfName1=a.intf, intfName2=b.intf,
                            addr1=_mac(indices[a.nodo], enlace.a.puerto),
                            addr2=_mac(indices[b.nodo], enlace.b.puerto))
            net.build()
            net.start()
            self._configurar()
        except Exception:
            self.detener()
            raise

    def _verificar_nombres_libres(self):
        """No pisar otra red: si ya existe una interfaz o un bridge con nuestros nombres, no se inicia."""
        existentes = set(os.listdir('/sys/class/net'))
        ocupados = sorted(existentes & (set(self.plan.por_intf) |
                                        {n.nombre for n in self.plan.lab.nodos
                                         if n.tipo == TipoNodo.switch}))
        if ocupados:
            raise ErrorRed('ya existen en el sistema: %s (¿hay otra red Mininet en marcha?)'
                           % ', '.join(ocupados))

    def _configurar(self):
        ethtool = shutil.which('ethtool')
        for nodo in self.plan.lab.nodos:
            n = self._nodos[nodo.id]
            if nodo.tipo != TipoNodo.switch:
                for clave in ('all', 'default', 'lo'):
                    self._ejecutar(n, ['sysctl', '-qw', 'net.ipv6.conf.%s.disable_ipv6=1' % clave])
        for ep in self.plan.por_intf.values():
            n = self._nodos[ep.nodo]
            # Sin IPv6 (evita ruido de ND/MLD en la simulación) y sin offloads (checksums reales).
            self._ejecutar(n, ['sysctl', '-qw', 'net.ipv6.conf.%s.disable_ipv6=1' % ep.intf])
            if ethtool:
                self._ejecutar(n, [ethtool, '-K', ep.intf, 'tx', 'off', 'rx', 'off'], tolerar=True)
            if ep.ip and ep.tipo != TipoNodo.switch:
                self._ejecutar(n, ['ip', 'addr', 'flush', 'dev', ep.intf])
                self._ejecutar(n, ['ip', 'addr', 'add', ep.ip, 'dev', ep.intf])
            self._ejecutar(n, ['ip', 'link', 'set', 'dev', ep.intf, 'up'])
        for nodo in self.plan.lab.nodos:
            if nodo.gateway is not None:
                self._ejecutar(self._nodos[nodo.id],
                               ['ip', 'route', 'replace', 'default', 'via', str(nodo.gateway)])

    def _ejecutar(self, n, argv, tolerar=False):
        p = n.popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(timeout=20)
        if p.returncode != 0 and not tolerar:
            raise ErrorRed('%s en %s falló: %s' % (' '.join(argv), n.name,
                                                   err.decode(errors='replace').strip()))
        return out.decode(errors='replace')

    def detener(self):
        net, self.net = self.net, None
        self._nodos = {}
        if net is not None:
            net.stop()

    # --- acceso a nodos ----------------------------------------------------

    def nodo(self, nodo_id):
        try:
            return self._nodos[nodo_id]
        except KeyError:
            raise ErrorRed('nodo inexistente o red detenida: %s' % nodo_id) from None

    def tiene_namespace(self, nodo_id):
        return bool(getattr(self.nodo(nodo_id), 'inNamespace', False))

    def popen(self, nodo_id, argv, **kwargs):
        """Proceso dentro del namespace del nodo (los switches viven en el namespace raíz)."""
        return self.nodo(nodo_id).popen(argv, **kwargs)

    def popen_terminal(self, nodo_id, esclavo):
        """bash interactivo con el PTY `esclavo` como terminal de control, dentro del namespace."""
        n = self.nodo(nodo_id)
        if not getattr(n, 'inNamespace', False):
            raise ErrorRed('%s no tiene namespace propio: no se abre terminal' % n.name)
        entorno = {'TERM': 'xterm-256color', 'LANG': 'C.UTF-8', 'HOME': '/root',
                   'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                   'PS1': 'root@%s:\\w# ' % n.name}

        def tty_de_control():
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        return subprocess.Popen(['mnexec', '-a', str(n.pid), 'bash', '--norc', '--noprofile', '-i'],
                                stdin=esclavo, stdout=esclavo, stderr=esclavo, env=entorno,
                                cwd='/root' if os.path.isdir('/root') else '/',
                                start_new_session=True, preexec_fn=tty_de_control, close_fds=True)

    # --- acciones guiadas --------------------------------------------------

    def ping(self, nodo_id, destino, cantidad=1):
        p = self.popen(nodo_id, ['ping', '-c', str(int(cantidad)), '-W', '2', str(destino)],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = p.communicate(timeout=10 + 2 * cantidad)
        return {'codigo': p.returncode, 'salida': out.decode(errors='replace')}

    def enlace(self, enlace_id, arriba):
        a, b = self.plan.enlaces[enlace_id]
        for ep in (a, b):
            self._ejecutar(self.nodo(ep.nodo), ['ip', 'link', 'set', 'dev', ep.intf,
                                                'up' if arriba else 'down'])
