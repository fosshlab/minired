"""Configuración de los servicios de la etapa 3, generada desde el modelo ya validado.

Funciones puras (sin root ni Mininet): devuelven texto de configuración o listas
de argumentos. Ningún valor pasa por un shell; los que llegan al texto de FRR o
de nftables son IP, redes, números y nombres de interfaz ya validados.
"""

from ..modelo.topologia import TipoNodo, ips_nodo, nombre_intf, nombre_subintf

FRR_DIR = '/usr/lib/frr'

UDHCPC_SCRIPT = r'''#!/bin/sh
# Gancho de udhcpc (minired): configura la interfaz con lo que entregó el servidor DHCP.
# Escribe el DNS en el resolv.conf PRIVADO del nodo ($MINIRED_RESOLV), nunca en el del sistema.
case "$1" in
  deconfig)
    ip -4 addr flush dev "$interface"
    ip link set dev "$interface" up
    ;;
  bound|renew)
    ip -4 addr flush dev "$interface"
    ip addr add "$ip/${mask:-24}" dev "$interface"
    if [ -n "$router" ]; then
      set -- $router
      ip route replace default via "$1" dev "$interface"
    fi
    if [ -n "$MINIRED_RESOLV" ]; then
      : > "$MINIRED_RESOLV"
      for d in $dns; do echo "nameserver $d" >> "$MINIRED_RESOLV"; done
    fi
    echo "DHCP: $interface recibió $ip/${mask:-24}${router:+, gateway $router}${dns:+, DNS $dns}${serverid:+ (servidor $serverid)}"
    ;;
esac
exit 0
'''

RENOVAR_DHCP = r'''#!/bin/sh
# renovar-dhcp [interfaz]: vuelve a pedir la IP por DHCP (DISCOVER, OFFER, REQUEST, ACK).
intf="${1:-$MINIRED_INTF}"
exec busybox udhcpc -i "$intf" -f -q -n -t 4 -T 2 -s "$MINIRED_DIR/udhcpc.sh"
'''


def argv_udhcpc(intf, directorio):
    return ['busybox', 'udhcpc', '-i', intf, '-f', '-q', '-n', '-t', '4', '-T', '2',
            '-s', directorio + '/udhcpc.sh']


def argv_http(ip, directorio_www):
    return ['python3', '-m', 'http.server', '80', '--bind', str(ip), '--directory', directorio_www]


def pagina_http(nodo):
    return ('<!doctype html><meta charset="utf-8"><title>%s</title>\n'
            '<h1>Hola desde %s</h1>\n<p>Servidor HTTP del laboratorio minired.</p>\n'
            % (nodo.nombre, nodo.nombre))


def argv_dnsmasq(nodo, intf, directorio):
    """dnsmasq en el namespace del servidor: DHCP con su rango y DNS con sus registros."""
    srv = nodo.servicios
    argv = ['dnsmasq', '--keep-in-foreground', '--conf-file=/dev/null', '--no-resolv', '--no-hosts',
            '--bind-interfaces', '--interface=' + intf, '--no-ping',
            '--pid-file=%s/dnsmasq.pid' % directorio,
            '--log-facility=%s/dnsmasq.log' % directorio, '--log-async']
    if srv.dns:
        argv.append('--log-queries')
        for r in srv.dns:
            argv.append('--host-record=%s,%s' % (r.nombre, r.ip))
    else:
        argv.append('--port=0')                 # sin DNS
    if srv.dhcp is not None:
        pool = srv.dhcp
        red = next(i.ip.network for i in nodo.interfaces if i.ip is not None)
        argv += ['--dhcp-range=%s,%s,%s,1h' % (pool.desde, pool.hasta, red.netmask),
                 '--dhcp-authoritative', '--log-dhcp',
                 '--dhcp-leasefile=%s/dnsmasq.leases' % directorio,
                 # Sin valor, la opción no se envía (dnsmasq si no se ofrecería a sí mismo).
                 '--dhcp-option=3' + (',%s' % pool.gateway if pool.gateway else '')]
        if pool.dns is not None:
            argv.append('--dhcp-option=6,%s' % pool.dns)
        elif not srv.dns:
            argv.append('--dhcp-option=6')
    return argv


def necesita_dnsmasq(nodo):
    srv = nodo.servicios
    return srv is not None and (srv.dhcp is not None or bool(srv.dns))


# --- FRR -------------------------------------------------------------------

def daemons_frr(nodo):
    return ['zebra', 'staticd'] + (['ospfd'] if nodo.ospf else [])


def frr_conf(nodo, lab):
    """frr.conf integrado del router: hostname, direcciones, rutas estáticas y OSPF."""
    vecinos = _vecinos(nodo, lab)
    lineas = ['frr defaults traditional', 'hostname %s' % nodo.nombre,
              'log file /run/frr/frr.log informational', 'service integrated-vtysh-config', '!']
    for intf in sorted(nodo.interfaces, key=lambda i: i.puerto):
        nombres = []
        if intf.ip is not None:
            nombres.append((nombre_intf(nodo, intf.puerto), intf.ip))
        nombres += [(nombre_subintf(nodo, intf.puerto, s.vlan), s.ip) for s in intf.subinterfaces]
        for nombre, ip in nombres:
            lineas.append('interface %s' % nombre)
            lineas.append(' ip address %s' % ip)
            if nodo.ospf and vecinos.get(intf.puerto) == TipoNodo.router and nombre == nombre_intf(nodo, intf.puerto):
                # Enlace directo entre routers: sin elección de DR, adyacencia en segundos.
                lineas.append(' ip ospf network point-to-point')
            lineas.append('!')
    for ruta in nodo.rutas:
        lineas.append('ip route %s %s' % (ruta.destino, ruta.via))
    if nodo.rutas:
        lineas.append('!')
    if nodo.ospf:
        ips = ips_nodo(nodo)
        lineas.append('router ospf')
        if ips:
            lineas.append(' ospf router-id %s' % min(ip.ip for _, ip in ips))
        for nombre, ip in ips:
            lineas.append(' network %s area 0' % ip.network)
        for intf in nodo.interfaces:
            if vecinos.get(intf.puerto) in (TipoNodo.pc, TipoNodo.servidor):
                # Hacia una PC no hay routers: no mandar hellos ahí.
                lineas.append(' passive-interface %s' % nombre_intf(nodo, intf.puerto))
        lineas.append('!')
    lineas.append('line vty')
    lineas.append('!')
    return '\n'.join(lineas) + '\n'


def _vecinos(nodo, lab):
    """{puerto: tipo del nodo del otro extremo}."""
    r = {}
    for e in lab.enlaces:
        for este, otro in ((e.a, e.b), (e.b, e.a)):
            if este.nodo == nodo.id:
                vecino = lab.nodo(otro.nodo)
                if vecino is not None:
                    r[este.puerto] = vecino.tipo
    return r


def argv_frr(daemon):
    return [FRR_DIR + '/' + daemon, '-F', 'traditional', '-A', '127.0.0.1',
            '-f', '/etc/frr/frr.conf', '-i', '/run/frr/%s.pid' % daemon, '--log', 'file:/run/frr/%s.log' % daemon]


# --- nftables --------------------------------------------------------------

def _nombres_puerto(nodo, intf):
    return [nombre_intf(nodo, intf.puerto)] + [nombre_subintf(nodo, intf.puerto, s.vlan)
                                                for s in intf.subinterfaces]


def _conjunto(nombres):
    return '{ %s }' % ', '.join('"%s"' % n for n in nombres)


def _regla(regla, n):
    partes = []
    if regla.origen is not None:
        partes.append('ip saddr %s' % regla.origen)
    if regla.destino is not None:
        partes.append('ip daddr %s' % regla.destino)
    if regla.protocolo != 'ip':
        partes.append('ip protocol %s' % regla.protocolo)
        if regla.puerto is not None:
            partes.append('%s dport %d' % (regla.protocolo, regla.puerto))
    partes.append('counter')
    partes.append('accept' if regla.accion == 'permitir' else 'drop')
    partes.append('comment "regla %d"' % n)
    return ' '.join(partes)


def necesita_nft(nodo):
    return nodo.tipo == TipoNodo.router and any(i.nat or i.acl_entrada for i in nodo.interfaces)


def nft_ruleset(nodo):
    """Tabla `ip minired` del router: ACL de entrada por interfaz (con deny implícito) y NAT."""
    cadenas = []
    saltos = []
    for intf in sorted(nodo.interfaces, key=lambda i: i.puerto):
        if not intf.acl_entrada:
            continue
        cadena = 'acl_entrada_eth%d' % intf.puerto
        reglas = [_regla(r, n) for n, r in enumerate(intf.acl_entrada, start=1)]
        reglas.append('counter drop comment "deny any implícito"')
        cadenas.append('  chain %s {\n%s\n  }' % (cadena, '\n'.join('    ' + r for r in reglas)))
        saltos.append('iifname %s jump %s' % (_conjunto(_nombres_puerto(nodo, intf)), cadena))
    partes = ['table ip minired {']
    partes += cadenas
    if saltos:
        for gancho in ('forward', 'input'):
            partes.append('  chain %s {\n    type filter hook %s priority filter; policy accept;\n%s\n  }'
                          % (gancho, gancho, '\n'.join('    ' + s for s in saltos)))
    interiores = [n for i in nodo.interfaces if i.nat == 'interior' for n in _nombres_puerto(nodo, i)]
    exteriores = [n for i in nodo.interfaces if i.nat == 'exterior' for n in _nombres_puerto(nodo, i)]
    if interiores and exteriores:
        partes.append('  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n'
                      '    iifname %s oifname %s counter masquerade comment "NAT (PAT) de la red interior"\n  }'
                      % (_conjunto(interiores), _conjunto(exteriores)))
    partes.append('}')
    return '\n'.join(partes) + '\n'
