"""Integración con root de la etapa 3 (VM de laboratorio): una práctica por tema.

    sudo <venv>/bin/python -m pytest -m root tests/test_integracion_etapa3.py

Cada prueba arranca la red desde la API, verifica el comportamiento con
comandos reales dentro de los namespaces y con la captura del modo simulación,
y al final comprueba que no quedan restos (interfaces, procesos, montajes,
reglas ni archivos) y que el sistema no cambió.
"""

import glob
import hashlib
import os
import re
import shutil
import subprocess
import time

import pytest

pytestmark = pytest.mark.root

if os.geteuid() != 0 or not shutil.which('mnexec'):
    pytest.skip('requiere root y Mininet', allow_module_level=True)

from fastapi.testclient import TestClient  # noqa: E402

from minired.runtime.controlador import Controlador  # noqa: E402
from minired.runtime.edunet import RedMininet  # noqa: E402
from minired.servidor.app import crear_app  # noqa: E402
from minired.servidor.seguridad import Config  # noqa: E402

from escenarios import lab_nat_acl, lab_ospf, lab_servicios, lab_vlan  # noqa: E402

TOKEN = 'token-etapa3'
AUTH = {'Authorization': 'Bearer ' + TOKEN}


def _huella_sistema():
    """Lo que el laboratorio no debe tocar: FRR del sistema, resolv.conf y reglas nftables."""
    nft = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True).stdout
    with open(os.path.realpath('/etc/resolv.conf'), 'rb') as f:
        resolv = f.read()
    return {'run_frr': sorted(os.listdir('/run/frr')) if os.path.isdir('/run/frr') else None,
            'resolv': hashlib.sha256(resolv).hexdigest(),
            'nft': hashlib.sha256(re.sub(r'counter packets \d+ bytes \d+', '', nft).encode()).hexdigest()}


def _interfaces(prefijos):
    return sorted(i for i in os.listdir('/sys/class/net') if i.startswith(prefijos))


def _procesos_del_lab():
    r = subprocess.run(['ps', '-eo', 'pid,args'], capture_output=True, text=True).stdout.splitlines()
    patrones = ('/etc/frr/frr.conf -i /run/frr', 'dnsmasq --keep-in-foreground', 'busybox udhcpc',
                'http.server 80', 'minired-red-')
    return [l for l in r if any(p in l for p in patrones) and 'pytest' not in l]


@pytest.fixture
def red(tmp_path):
    """Levanta un laboratorio; al salir verifica limpieza y que el sistema quedó igual."""
    estado = {}
    antes = _huella_sistema()
    # Otra red de minired puede estar en marcha en la VM (la de otra persona): se compara contra
    # lo que había antes de esta prueba, no contra "nada".
    dirs_antes = set(glob.glob('/tmp/minired-red-*'))
    procesos_antes = set(_procesos_del_lab())
    ctl = Controlador(RedMininet, directorio_capturas=str(tmp_path))
    app = crear_app(ctl, Config(puerto=8787, token=TOKEN))

    def iniciar(lab):
        estado['prefijos'] = tuple(n.nombre + '-' for n in lab.nodos) + tuple(
            n.nombre for n in lab.nodos if n.tipo.value == 'switch')
        assert _interfaces(estado['prefijos']) == [], 'restos de una corrida anterior'
        assert c.put('/api/lab', json=lab.model_dump(mode='json'), headers=AUTH).status_code == 200
        r = c.post('/api/red/iniciar', headers=AUTH)
        assert r.status_code == 200, r.text
        return ctl

    with TestClient(app, base_url='http://127.0.0.1:8787') as c:
        c.iniciar = iniciar
        c.ctl = ctl
        yield c
        if ctl.estado == 'activa':
            assert c.post('/api/red/detener', headers=AUTH).json()['estado'] == 'diseño'
    deadline = time.monotonic() + 5
    while _interfaces(estado.get('prefijos', ('-',))) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert _interfaces(estado.get('prefijos', ('-',))) == []
    assert set(_procesos_del_lab()) <= procesos_antes
    assert set(glob.glob('/tmp/minired-red-*')) <= dirs_antes
    assert _huella_sistema() == antes


def sh(c, nodo, *argv, timeout=15):
    p = c.ctl.red.popen(nodo, list(argv), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = p.communicate(timeout=timeout)
    return p.returncode, out.decode(errors='replace')


def ping(c, nodo, destino):
    return c.post('/api/nodos/%s/ping' % nodo, json={'destino': destino}, headers=AUTH).json()


def esperar(fn, segundos=10, paso=0.2):
    limite = time.monotonic() + segundos
    while time.monotonic() < limite:
        v = fn()
        if v:
            return v
        time.sleep(paso)
    return fn()


def capturar(c, accion, espera=1.0):
    assert c.post('/api/captura/iniciar', headers=AUTH).status_code == 200
    resultado = accion()
    time.sleep(espera)
    estado = c.post('/api/captura/detener', headers=AUTH).json()
    assert all(x['caidos_kernel'] == 0 for x in estado['capturadores']), estado
    items = c.get('/api/captura/observaciones', headers=AUTH).json()['items']
    return resultado, items


def camino(items, paquete):
    return [(o['enlace'], o['nodo'], o['confianza'], o['resumen'].get('vlan', {}).get('id'))
            for o in items if o['paquete'] == paquete]


# --- VLAN, troncal e inter-VLAN ----------------------------------------------

def test_vlan_troncal_e_intervlan(red):
    red.iniciar(lab_vlan())
    # El primer eco entre VLAN puede perderse mientras se resuelven los ARP: se calienta antes.
    for origen, destino in (('v1', '10.10.0.2'), ('v1', '10.20.0.1')):
        assert esperar(lambda: ping(red, origen, destino)['codigo'] == 0, 6), (origen, destino)
    assert ping(red, 'v4', '10.10.0.1')['codigo'] != 0          # VLAN 20 no ve a la 10
    # Ese ping fallido deja la entrada ARP de v4 en INCOMPLETE/FAILED: si el ping capturado llega en
    # ese momento, Linux no vuelve a preguntar. Se vacía para que el ARP de v4 se vea siempre.
    sh(red, 'v4', 'ip', 'neigh', 'flush', 'dev', 'v4-eth0')

    def trafico():
        return [ping(red, 'v1', '10.10.0.2'), ping(red, 'v1', '10.20.0.1'), ping(red, 'v4', '10.10.0.1')]
    res, items = capturar(red, trafico)
    assert [r['codigo'] == 0 for r in res] == [True, True, False]

    ecos = [o for o in items if o['resumen'].get('icmp', {}).get('tipo') == 8 and o['profundidad'] == 0]
    por_destino = {o['resumen']['ip']['dst']: o['paquete'] for o in ecos}
    # Misma VLAN en dos switches: cruza la troncal con etiqueta 10.
    assert camino(items, por_destino['10.10.0.2']) == [
        ('e1', 'sa', 'alta', None), ('e3', 'sb', 'alta', 10), ('e5', 'v2', 'alta', None)]
    # Inter-VLAN: sube al router con etiqueta 10 y vuelve por el mismo enlace con etiqueta 20.
    assert camino(items, por_destino['10.20.0.1']) == [
        ('e1', 'sa', 'alta', None), ('e4', 'r', 'alta', 10), ('e4', 'sa', 'media', 20),
        ('e2', 'v3', 'alta', None)]
    # Aislamiento: el ARP de v4 (VLAN 20) nunca llega a v1 ni a v2 (VLAN 10).
    arp_v4 = [o for o in items if o['resumen'].get('arp', {}).get('spa') == '10.10.0.4']
    assert arp_v4 and not any(o['nodo'] in ('v1', 'v2') for o in arp_v4)
    assert {o['resumen'].get('vlan', {}).get('id') for o in arp_v4 if o['enlace'] in ('e3', 'e4')} == {20}

    # Vista OSI del switch: la trama entra por acceso VLAN 10 y sale por la troncal con etiqueta.
    en_sa = next(o for o in items if o['paquete'] == por_destino['10.20.0.1'] and o['nodo'] == 'sa')
    osi = red.get('/api/captura/observaciones/%s/osi' % en_sa['id'], headers=AUTH).json()
    textos = [d['texto'] for d in osi['decisiones']]
    assert osi['resultado'] == 'reenviado' and osi['tipo'] == 'switch'
    assert any('puerto de acceso de la VLAN 10' in t for t in textos)
    assert any('troncal: agrega la etiqueta 802.1Q de la VLAN 10' in t for t in textos)
    assert any('la tabla MAC de vsa lo confirma' in t for t in textos)            # leída al detener
    assert osi['origen']['nombre'] == 'v1'

    diag = red.get('/api/nodos/sa/diagnostico', headers=AUTH).json()
    texto = '\n'.join(s['salida'] for s in diag['secciones'])
    assert re.search(r'name\s*: "?vsa-eth3"?\s*\ntag\s*: \[\]\s*\ntrunks\s*: \[10, 20\]', texto), texto
    assert 'vsa-eth1' in texto
    assert sh(red, 'r', 'ip', '-br', 'addr', 'show', 'dev', 'vr-eth0.20')[1].split()[2] == '10.20.0.254/24'


# --- FRR con OSPF --------------------------------------------------------------

def test_frr_ospf_dos_routers_aislados(red):
    red.iniciar(lab_ospf())
    assert esperar(lambda: ping(red, 'f1', '10.62.0.1')['codigo'] == 0, 40, 1), 'OSPF no convergió'
    rc, rutas = sh(red, 'r1', 'vtysh', '-c', 'show ip route ospf')
    assert rc == 0 and re.search(r'O>\* 10\.62\.0\.0/24 \[110/\d+\] via 10\.60\.0\.2', rutas), rutas
    rc, vecinos = sh(red, 'r2', 'vtysh', '-c', 'show ip ospf neighbor')
    assert '10.60.0.1' in vecinos and 'Full' in vecinos, vecinos
    assert 'proto ospf' in sh(red, 'r1', 'ip', 'route', 'show', '10.62.0.0/24')[1]
    # Cada router tiene su propio zebra, sus sockets y su configuración.
    pids = {sh(red, r, 'cat', '/run/frr/zebra.pid')[1].strip() for r in ('r1', 'r2')}
    assert len(pids) == 2 and all(p.isdigit() for p in pids)
    assert 'hostname fr2' in sh(red, 'r2', 'vtysh', '-c', 'show running-config')[1]

    def trafico():
        return ping(red, 'f1', '10.62.0.1')
    res, items = capturar(red, trafico)
    assert res['codigo'] == 0
    eco = next(o for o in items if o['resumen'].get('icmp', {}).get('tipo') == 8 and o['profundidad'] == 0)
    assert [(o['enlace'], o['resumen']['ip']['ttl'], o['confianza']) for o in items
            if o['paquete'] == eco['paquete']] == [('e1', 64, 'alta'), ('e2', 63, 'media'), ('e3', 62, 'media')]
    _, items = capturar(red, lambda: None, espera=11)           # hellos cada 10 s
    hellos = [o for o in items if o['resumen']['protocolo'] == 'ospf']
    assert {o['enlace'] for o in hellos} == {'e2'}               # pasivas hacia las PC
    assert all('Hello' in o['resumen']['info'] for o in hellos)


# --- DHCP, DNS y HTTP ----------------------------------------------------------

def _ip_de(c, nodo, intf):
    salida = sh(c, nodo, 'ip', '-4', '-br', 'addr', 'show', 'dev', intf)[1].split()
    return salida[2].split('/')[0] if len(salida) > 2 else None


def test_dhcp_dns_http(red):
    red.iniciar(lab_servicios())
    ips = {n: esperar(lambda n=n, i=i: _ip_de(red, n, i), 15)
           for n, i in (('ca', 'dc1-eth0'), ('ca2', 'dc2-eth0'), ('cb', 'dc3-eth0'))}
    import ipaddress
    rango_a = (ipaddress.ip_address('10.30.0.100'), ipaddress.ip_address('10.30.0.150'))
    assert all(rango_a[0] <= ipaddress.ip_address(ips[n]) <= rango_a[1] for n in ('ca', 'ca2'))
    assert ips['ca'] != ips['ca2']
    assert ipaddress.ip_address('10.31.0.200') <= ipaddress.ip_address(ips['cb']) <= ipaddress.ip_address('10.31.0.210')
    assert 'default via 10.30.0.254' in sh(red, 'ca', 'ip', 'route')[1]
    assert 'default' not in sh(red, 'cb', 'ip', 'route')[1]            # el servidor B no da gateway
    assert sh(red, 'ca', 'cat', '/etc/resolv.conf')[1].strip() == 'nameserver 10.30.0.1'
    assert sh(red, 'cb', 'cat', '/etc/resolv.conf')[1].strip() == ''
    assert sh(red, 'ca', 'getent', 'hosts', 'web.lab')[1].split()[0] == '10.30.0.1'
    assert 'Hola desde da1' in sh(red, 'ca', 'curl', '-s', '-m', '5', 'http://web.lab/')[1]
    leases = sh(red, 'srva', 'cat', red.ctl.red.directorio + '/da1/dnsmasq.leases')[1]
    assert ips['ca'] in leases and ips['ca2'] in leases

    def trafico():
        r = red.post('/api/nodos/ca/dhcp', headers=AUTH).json()
        web = sh(red, 'ca', 'curl', '-s', '-m', '5', 'http://web.lab/')
        return r, web
    (r, web), items = capturar(red, trafico)
    assert r['codigo'] == 0 and 'DHCP: dc1-eth0 recibió' in r['salida'], r
    assert 'Hola desde da1' in web[1]
    dhcp = [o for o in items if o['resumen']['protocolo'] == 'dhcp']
    tipos = [o['resumen']['dhcp']['tipo'] for o in dhcp if o['profundidad'] == 0]
    assert tipos == [1, 2, 3, 5], tipos                                 # DORA
    discover = [o for o in dhcp if o['resumen']['dhcp']['tipo'] == 1]
    # El DISCOVER es broadcast: el switch lo inunda al servidor y a la otra PC.
    assert sorted(o['nodo'] for o in discover if o['profundidad'] == 1) == ['ca2', 'srva']
    assert len({o['paquete'] for o in discover}) == 1
    protos = {o['resumen']['protocolo'] for o in items}
    assert {'dns', 'http'} <= protos
    consulta = next(o for o in items if o['resumen']['protocolo'] == 'dns')
    assert 'web.lab' in consulta['resumen']['info']


# --- NAT y ACL -----------------------------------------------------------------

def _contador(tabla, comentario):
    m = re.search(r'counter packets (\d+) bytes \d+ .*comment "%s"' % re.escape(comentario), tabla)
    return int(m.group(1)) if m else None


def test_nat_y_acl(red):
    red.iniciar(lab_nat_acl())
    assert 'default' not in sh(red, 'web', 'ip', 'route')[1]        # el servidor no conoce 10.40/24
    assert '198.51.100.0/24 via 203.0.113.10' in sh(red, 'r', 'ip', 'route')[1]
    assert esperar(lambda: ping(red, 'n1', '203.0.113.10')['codigo'] == 0, 6)
    assert ping(red, 'n2', '203.0.113.10')['codigo'] != 0           # ACL: n2 sin ICMP
    rc, web = sh(red, 'n2', 'curl', '-s', '-m', '5', 'http://203.0.113.10/')
    assert rc == 0 and 'Hola desde nsrv' in web                     # pero HTTP sí
    tabla = sh(red, 'r', 'nft', 'list', 'table', 'ip', 'minired')[1]
    assert _contador(tabla, 'regla 1') >= 1 and _contador(tabla, 'regla 2') >= 1
    assert _contador(tabla, 'NAT (PAT) de la red interior') >= 1
    log = sh(red, 'web', 'cat', red.ctl.red.directorio + '/nsrv/http.log')[1]
    assert '203.0.113.1 ' in log and '10.40.0.' not in log           # el servidor ve la IP traducida

    res, items = capturar(red, lambda: ping(red, 'n1', '203.0.113.10'))
    assert res['codigo'] == 0
    ida = next(o for o in items if o['resumen'].get('icmp', {}).get('tipo') == 8 and o['profundidad'] == 0)
    pasos = [(o['enlace'], o['confianza'], o['resumen']['ip']['src']) for o in items if o['paquete'] == ida['paquete']]
    assert pasos == [('e1', 'alta', '10.40.0.1'), ('e3', 'alta', '10.40.0.1'), ('e4', 'baja', '203.0.113.1')]
    vuelta = next(o for o in items if o['resumen'].get('icmp', {}).get('tipo') == 0 and o['profundidad'] == 0)
    assert [(o['enlace'], o['confianza'], o['resumen']['ip']['dst']) for o in items
            if o['paquete'] == vuelta['paquete']] == [
        ('e4', 'alta', '203.0.113.1'), ('e3', 'baja', '10.40.0.1'), ('e1', 'alta', '10.40.0.1')]
    diag = red.get('/api/nodos/r/diagnostico', headers=AUTH).json()
    assert any('masquerade' in s['salida'] for s in diag['secciones'])

    # Vista OSI (modo simple) sobre la red real: NAT observado y ACL que descarta a n2.
    en_router = next(o for o in items if o['nodo'] == 'r' and o['paquete'] == ida['paquete'])
    osi = red.get('/api/captura/observaciones/%s/osi' % en_router['id'], headers=AUTH).json()
    assert osi['resultado'] == 'traducido' and osi['estado_red'] == ['fin', 'inicio']
    assert any(d['fuente'] == 'observado' and 'NAT (PAT) traduce la IP de origen 10.40.0.1 → 203.0.113.1' in d['texto']
               for d in osi['decisiones'])
    assert any(d['fuente'] == 'estado' and 'Busca 203.0.113.10 en la tabla de rutas' in d['texto'] for d in osi['decisiones'])
    _, items = capturar(red, lambda: ping(red, 'n2', '203.0.113.10'))
    bloqueado = next(o for o in items if o['nodo'] == 'r' and o['resumen'].get('icmp', {}).get('tipo') == 8)
    osi = red.get('/api/captura/observaciones/%s/osi' % bloqueado['id'], headers=AUTH).json()
    assert osi['resultado'] == 'descartado' and osi['salidas'] == []
    assert any('regla 1 (denegar icmp desde 10.40.0.2/32)' in d['texto'] for d in osi['decisiones'])
