"""Red Mininet construida desde un PlanRed. Todos sus métodos corren en el hilo del Worker.

Nunca se arma texto de shell con valores del usuario: los comandos se pasan
como lista de argumentos y los valores ya vienen validados por el modelo.
"""

import fcntl
import os
import shutil
import subprocess
import tempfile
import termios
import time

from ..modelo.topologia import HOSTS, TipoNodo, nombre_intf, nombre_subintf
from . import servicios as sv
from .procesos import inodo_netns, matar_netns


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
        self._netns = {}            # id -> inodo del namespace de red (nodos con namespace)
        self._rutas_guardadas = {}  # id -> rutas a reponer al subir un enlace
        self._procesos = []         # servicios lanzados (FRR, dnsmasq, HTTP, udhcpc)
        self.directorio = None      # archivos privados de los nodos (frr.conf, leases, logs)

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
                if nodo.tipo in HOSTS:
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
            for nodo_id, n in self._nodos.items():
                if getattr(n, 'inNamespace', False):
                    self._netns[nodo_id] = inodo_netns(n.pid)
            self.directorio = tempfile.mkdtemp(prefix='minired-red-')      # 0700, solo root
            self._configurar()
            self._servicios()
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
            n = self._nodos[nodo.id]
            if nodo.tipo == TipoNodo.switch:
                self._vlan_switch(nodo, n)
            if nodo.tipo == TipoNodo.router:
                self._subinterfaces(nodo, n, ethtool)
                if not nodo.frr:
                    for ruta in nodo.rutas:
                        self._ejecutar(n, ['ip', 'route', 'replace', str(ruta.destino), 'via', str(ruta.via)])
            if nodo.gateway is not None:
                self._ejecutar(n, ['ip', 'route', 'replace', 'default', 'via', str(nodo.gateway)])

    def _vlan_switch(self, nodo, n):
        for intf in nodo.interfaces:
            puerto = nombre_intf(nodo, intf.puerto)
            if puerto not in self.plan.por_intf:
                continue            # puerto configurado pero sin enlace
            if intf.vlan is not None:
                self._ejecutar(n, ['ovs-vsctl', 'set', 'port', puerto, 'tag=%d' % intf.vlan,
                                   'vlan_mode=access'])
            elif intf.troncal is not None:
                self._ejecutar(n, ['ovs-vsctl', 'set', 'port', puerto,
                                   'trunks=%s' % ','.join(str(v) for v in intf.troncal),
                                   'vlan_mode=trunk'])

    def _subinterfaces(self, nodo, n, ethtool):
        for intf in nodo.interfaces:
            base = nombre_intf(nodo, intf.puerto)
            for sub in intf.subinterfaces:
                nombre = nombre_subintf(nodo, intf.puerto, sub.vlan)
                self._ejecutar(n, ['ip', 'link', 'add', 'link', base, 'name', nombre,
                                   'type', 'vlan', 'id', str(sub.vlan)])
                self._ejecutar(n, ['sysctl', '-qw', 'net/ipv6/conf/%s/disable_ipv6=1' % nombre])
                if ethtool:
                    self._ejecutar(n, [ethtool, '-K', nombre, 'tx', 'off', 'rx', 'off'], tolerar=True)
                self._ejecutar(n, ['ip', 'addr', 'add', str(sub.ip), 'dev', nombre])
                self._ejecutar(n, ['ip', 'link', 'set', 'dev', nombre, 'up'])

    # --- servicios por nodo (etapa 3) --------------------------------------

    def _dir_nodo(self, nodo, sub=''):
        d = os.path.join(self.directorio, nodo.nombre, sub) if sub else os.path.join(self.directorio, nodo.nombre)
        os.makedirs(d, mode=0o700, exist_ok=True)
        return d

    def _lanzar(self, n, argv, log, env=None):
        with open(log, 'ab') as salida:
            p = n.popen(argv, stdin=subprocess.DEVNULL, stdout=salida, stderr=subprocess.STDOUT,
                        **({'env': env} if env else {}))
        self._procesos.append(p)
        return p

    def _servicios(self):
        lab = self.plan.lab
        guion = os.path.join(self.directorio, 'udhcpc.sh')
        bin_dir = os.path.join(self.directorio, 'bin')
        os.makedirs(bin_dir, mode=0o755)
        os.chmod(self.directorio, 0o711)       # que FRR/dnsmasq (sin root) lleguen a su carpeta
        for ruta, texto in ((guion, sv.UDHCPC_SCRIPT), (os.path.join(bin_dir, 'renovar-dhcp'), sv.RENOVAR_DHCP)):
            with open(ruta, 'w') as f:
                f.write(texto)
            os.chmod(ruta, 0o755)
        # resolv.conf privado en cada nodo con namespace: el DNS del sistema no se filtra al lab.
        for nodo in lab.nodos:
            if nodo.id not in self._netns:
                continue
            resolv = os.path.join(self._dir_nodo(nodo), 'resolv.conf')
            with open(resolv, 'w') as f:
                if nodo.dns is not None:
                    f.write('nameserver %s\n' % nodo.dns)
            destino = os.path.realpath('/etc/resolv.conf')     # suele ser un enlace simbólico
            if os.path.isfile(destino):
                self._ejecutar(self._nodos[nodo.id], ['mount', '--bind', resolv, destino])
        for nodo in lab.nodos:
            n = self._nodos[nodo.id]
            if nodo.tipo == TipoNodo.router:
                if nodo.frr:
                    self._iniciar_frr(nodo, n)
                if sv.necesita_nft(nodo):
                    ruta = os.path.join(self._dir_nodo(nodo), 'minired.nft')
                    with open(ruta, 'w') as f:
                        f.write(sv.nft_ruleset(nodo))
                    self._ejecutar(n, ['nft', '-f', ruta])
            elif nodo.tipo == TipoNodo.servidor and nodo.servicios is not None:
                self._iniciar_servidor(nodo, n)
        # Las PC con DHCP piden su IP cuando los servidores ya escuchan.
        for nodo in lab.nodos:
            if nodo.dhcp:
                self._lanzar(self._nodos[nodo.id], self._argv_dhcp(nodo),
                             os.path.join(self._dir_nodo(nodo), 'dhcp.log'),
                             env=dict(os.environ, **self._entorno_dhcp(nodo)))

    def _argv_dhcp(self, nodo):
        return sv.argv_udhcpc(nombre_intf(nodo, 0), self.directorio)

    def _entorno_dhcp(self, nodo):
        return {'MINIRED_RESOLV': os.path.join(self.directorio, nodo.nombre, 'resolv.conf'),
                'MINIRED_DIR': self.directorio, 'MINIRED_INTF': nombre_intf(nodo, 0)}

    def _iniciar_frr(self, nodo, n):
        if not (os.path.exists(sv.FRR_DIR + '/zebra') and os.path.isdir('/run/frr')):
            raise ErrorRed('%s usa FRR, pero FRRouting no está instalado (apt install frr)' % nodo.nombre)
        etc = self._dir_nodo(nodo, 'etc-frr')
        run = self._dir_nodo(nodo, 'run-frr')
        import grp
        import pwd
        uid, gid = pwd.getpwnam('frr').pw_uid, grp.getgrnam('frr').gr_gid
        with open(os.path.join(etc, 'frr.conf'), 'w') as f:
            f.write(sv.frr_conf(nodo, self.plan.lab))
        open(os.path.join(etc, 'vtysh.conf'), 'w').close()
        for d in (etc, run):
            os.chown(d, uid, gid)
            os.chmod(d, 0o770)
        for nombre in os.listdir(etc):
            os.chown(os.path.join(etc, nombre), uid, gid)
            os.chmod(os.path.join(etc, nombre), 0o660)
        # Carpetas privadas montadas en el namespace del router: vtysh, sockets y PID no se
        # mezclan con el FRR del sistema ni con el de otro router.
        self._ejecutar(n, ['mount', '--bind', etc, '/etc/frr'])
        self._ejecutar(n, ['mount', '--bind', run, '/run/frr'])
        log = os.path.join(self._dir_nodo(nodo), 'frr.salida')
        for daemon in sv.daemons_frr(nodo):
            self._lanzar(n, sv.argv_frr(daemon), log)
            vty = os.path.join(run, '%s.vty' % daemon)
            limite = time.monotonic() + 10
            while not os.path.exists(vty):
                if time.monotonic() > limite or self._procesos[-1].poll() is not None:
                    raise ErrorRed('FRR (%s) no arrancó en %s: %s' % (daemon, nodo.nombre, _cola(log)))
                time.sleep(0.05)

    def _iniciar_servidor(self, nodo, n):
        d = self._dir_nodo(nodo)
        intf = nombre_intf(nodo, 0)
        if sv.necesita_dnsmasq(nodo):
            os.chmod(d, 0o755)          # dnsmasq escribe su log después de dejar root
            p = self._lanzar(n, sv.argv_dnsmasq(nodo, intf, d), os.path.join(d, 'dnsmasq.salida'))
            limite = time.monotonic() + 5
            while not os.path.exists(os.path.join(d, 'dnsmasq.pid')):
                if time.monotonic() > limite or p.poll() is not None:
                    raise ErrorRed('dnsmasq no arrancó en %s: %s'
                                   % (nodo.nombre, _cola(os.path.join(d, 'dnsmasq.salida'))))
                time.sleep(0.05)
        if nodo.servicios.http:
            www = self._dir_nodo(nodo, 'www')
            with open(os.path.join(www, 'index.html'), 'w') as f:
                f.write(sv.pagina_http(nodo))
            ip = next(i.ip.ip for i in nodo.interfaces if i.ip is not None)
            self._lanzar(n, sv.argv_http(ip, www), os.path.join(d, 'http.log'))

    def _ejecutar(self, n, argv, tolerar=False):
        p = n.popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(timeout=20)
        if p.returncode != 0 and not tolerar:
            raise ErrorRed('%s en %s falló: %s' % (' '.join(argv), n.name,
                                                   err.decode(errors='replace').strip()))
        return out.decode(errors='replace')

    def detener(self):
        net, self.net = self.net, None
        nodos, self._nodos = self._nodos, {}
        netns, self._netns = self._netns, {}
        shells = {n.pid for n in nodos.values() if getattr(n, 'pid', None)}
        # Primero los servicios (sin tocar las shells que Mininet usa para limpiar)...
        matar_netns(netns.values(), excepto=shells)
        try:
            if net is not None:
                net.stop()
        finally:
            # ...y después cualquier resto que mantenga vivo un namespace.
            matar_netns(netns.values())
            for p in self._procesos:
                try:
                    p.wait(1)
                except Exception:
                    pass
            self._procesos = []
            if self.directorio:
                shutil.rmtree(self.directorio, ignore_errors=True)
                self.directorio = None

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
        nodo = self.plan.lab.nodo(nodo_id)
        if self.directorio:
            entorno['PATH'] = os.path.join(self.directorio, 'bin') + ':' + entorno['PATH']
            if nodo.tipo in HOSTS:
                entorno.update(self._entorno_dhcp(nodo))

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

    def dhcp(self, nodo_id):
        """Vuelve a pedir la IP por DHCP (para ver DISCOVER/OFFER/REQUEST/ACK en la simulación)."""
        nodo = self.plan.lab.nodo(nodo_id)
        entorno = dict(os.environ, **self._entorno_dhcp(nodo))
        p = self.popen(nodo_id, self._argv_dhcp(nodo), stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, env=entorno)
        out, _ = p.communicate(timeout=30)
        return {'codigo': p.returncode, 'salida': out.decode(errors='replace')}

    def diagnostico(self, nodo_id):
        """Estado legible del nodo para el inspector: direcciones, rutas, VLAN, FRR, NAT/ACL, leases."""
        nodo = self.plan.lab.nodo(nodo_id)
        comandos = []
        if nodo.tipo == TipoNodo.switch:
            comandos += [('Puertos y VLAN', ['ovs-vsctl', '--columns=name,tag,trunks,vlan_mode',
                                             'list', 'port']),
                         ('Tabla MAC (FDB)', ['ovs-appctl', 'fdb/show', nodo.nombre])]
        else:
            comandos += [('Direcciones', ['ip', '-br', 'addr']), ('Rutas', ['ip', 'route']),
                         ('Vecinos ARP', ['ip', 'neigh'])]
        if nodo.tipo == TipoNodo.router and nodo.frr:
            comandos += [('FRR: show ip route', ['vtysh', '-c', 'show ip route'])]
            if nodo.ospf:
                comandos += [('FRR: vecinos OSPF', ['vtysh', '-c', 'show ip ospf neighbor'])]
        if nodo.tipo == TipoNodo.router and sv.necesita_nft(nodo):
            comandos += [('nftables (ACL y NAT, con contadores)', ['nft', 'list', 'table', 'ip', 'minired'])]
        secciones = []
        for titulo, argv in comandos:
            if nodo.tipo == TipoNodo.switch and argv[0] == 'ovs-vsctl':
                argv = argv + [nombre_intf(nodo, p) for p in sorted(self._puertos_conectados(nodo))]
            p = self.popen(nodo_id, argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out, _ = p.communicate(timeout=10)
            secciones.append({'titulo': titulo, 'comando': ' '.join(argv), 'salida': out.decode(errors='replace')})
        d = os.path.join(self.directorio or '', nodo.nombre)
        for titulo, archivo in (('Concesiones DHCP', 'dnsmasq.leases'), ('Log de dnsmasq', 'dnsmasq.log'),
                                ('Log del cliente DHCP', 'dhcp.log'), ('Log de HTTP', 'http.log')):
            ruta = os.path.join(d, archivo)
            if self.directorio and os.path.exists(ruta):
                secciones.append({'titulo': titulo, 'comando': None, 'salida': _cola(ruta, 4000)})
        return {'nodo': nodo_id, 'secciones': secciones}

    def _puertos_conectados(self, nodo):
        r = []
        for e in self.plan.lab.enlaces:
            for ext in (e.a, e.b):
                if ext.nodo == nodo.id:
                    r.append(ext.puerto)
        return r

    def enlace(self, enlace_id, arriba):
        """Baja o sube los dos extremos de un enlace (como desenchufar el cable).

        Al bajar una interfaz, Linux borra las rutas que salen por ella (gateway, estáticas,
        la que dejó el DHCP) y al subirla no las repone: se guardan antes y se reponen después.
        Las rutas que instala FRR (con "proto") las repone zebra.
        """
        a, b = self.plan.enlaces[enlace_id]
        if not arriba:
            for ep in (a, b):
                if ep.tipo != TipoNodo.switch:
                    self._rutas_guardadas.setdefault(ep.nodo, set()).update(self._rutas_manuales(ep.nodo))
        for ep in (a, b):
            self._ejecutar(self.nodo(ep.nodo), ['ip', 'link', 'set', 'dev', ep.intf,
                                                'up' if arriba else 'down'])
        if arriba:
            for ep in (a, b):
                for ruta in sorted(self._rutas_guardadas.get(ep.nodo, ()), key=lambda r: r[0] == 'default'):
                    # tolerar: la ruta puede salir por otro enlace que sigue caído
                    self._ejecutar(self.nodo(ep.nodo), ['ip', 'route', 'replace', *ruta], tolerar=True)

    def _rutas_manuales(self, nodo_id):
        """Rutas IPv4 del nodo que no son de una red conectada ni de FRR (sin 'proto' ni 'scope link')."""
        salida = self._ejecutar(self.nodo(nodo_id), ['ip', '-4', 'route', 'show'])
        rutas = set()
        for linea in salida.splitlines():
            partes = tuple(linea.split())
            if partes and 'proto' not in partes and 'scope' not in partes and 'via' in partes:
                rutas.add(partes)
        return rutas

def _cola(ruta, maximo=600):
    try:
        with open(ruta, 'rb') as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - maximo))
            return f.read().decode(errors='replace').strip()
    except OSError:
        return ''
