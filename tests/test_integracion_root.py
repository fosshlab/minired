"""Integración con root (VM de laboratorio): Mininet real, OVS, tcpdump y tshark.

    sudo <venv>/bin/python -m pytest -m root tests/test_integracion_root.py

Usa nombres propios (ti1, ti2, ti3, tisw) para no chocar con otras redes de la VM.
"""

import json
import os
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

from utiles import lab_3pc  # noqa: E402

TOKEN = 'token-integracion'
AUTH = {'Authorization': 'Bearer ' + TOKEN}
NOMBRES = ('ti1', 'ti2', 'ti3')
SWITCH = 'tisw'
WS = 'ws://127.0.0.1:8787'
PROTO = ['minired', 'token.' + TOKEN]


def interfaces_nuestras():
    return sorted(i for i in os.listdir('/sys/class/net') if i.startswith(NOMBRES + (SWITCH,)))


def procesos(patron):
    r = subprocess.run(['pgrep', '-af', patron], capture_output=True, text=True)
    return [l for l in r.stdout.splitlines() if 'pgrep' not in l and 'pytest' not in l]


@pytest.fixture
def cliente(tmp_path):
    assert interfaces_nuestras() == [], 'quedaron restos de una corrida anterior'
    ctl = Controlador(RedMininet, directorio_capturas=str(tmp_path))
    app = crear_app(ctl, Config(puerto=8787, token=TOKEN))
    with TestClient(app, base_url='http://127.0.0.1:8787') as c:
        yield c
    # al salir (lifespan) se detiene la red si quedó activa


def esperar(fn, segundos=10):
    limite = time.monotonic() + segundos
    while time.monotonic() < limite:
        valor = fn()
        if valor:
            return valor
        time.sleep(0.2)
    return fn()


def test_ping_arp_icmp_capas_pcap_y_limpieza(cliente, tmp_path):
    lab = lab_3pc(NOMBRES, SWITCH).model_dump(mode='json')
    assert cliente.put('/api/lab', json=lab, headers=AUTH).status_code == 200
    r = cliente.post('/api/red/iniciar', headers=AUTH)
    assert r.status_code == 200, r.text
    assert r.json()['estado'] == 'activa'
    assert 'ti1-eth0' not in interfaces_nuestras()        # está dentro del namespace de ti1
    assert {'tisw-eth1', 'tisw-eth2', 'tisw-eth3'} <= set(interfaces_nuestras())

    # Terminal real dentro del namespace: ve solo su interfaz y su IP
    with cliente.websocket_connect(WS + '/ws/terminal/pc1', headers={'origin': 'http://127.0.0.1:8787'},
                                   subprotocols=PROTO) as ws:
        ws.send_bytes(b'ip -br addr show dev ti1-eth0; ls /sys/class/net\n')
        salida = b''
        limite = time.monotonic() + 5
        while b'10.0.0.1/24' not in salida and time.monotonic() < limite:
            salida += ws.receive_bytes()
        assert b'ti1-eth0' in salida and b'10.0.0.1/24' in salida
        assert b'tisw-eth1' not in salida

    r = cliente.post('/api/captura/iniciar', headers=AUTH)
    assert r.status_code == 200, r.text
    r = cliente.post('/api/nodos/pc1/ping', json={'destino': '10.0.0.2', 'cantidad': 1}, headers=AUTH)
    assert r.json()['codigo'] == 0, r.json()

    def completas():
        items = cliente.get('/api/captura/observaciones', headers=AUTH).json()['items']
        return items if len(items) >= 9 else None
    items = esperar(completas)
    assert items, 'no llegaron las 9 observaciones'
    estado = cliente.post('/api/captura/detener', headers=AUTH).json()
    items = cliente.get('/api/captura/observaciones', headers=AUTH).json()['items']
    (tmp_path / 'observaciones.json').write_text(json.dumps(items, indent=1))

    assert all(c['caidos_kernel'] == 0 for c in estado['capturadores']), estado
    assert all(o['confianza'] == 'alta' for o in items), items
    paquetes = {}
    for o in items:
        paquetes.setdefault(o['paquete'], []).append(o)
    arp_req = [v for v in paquetes.values() if v[0]['resumen'].get('arp', {}).get('op') == 1]
    assert len(arp_req) == 1
    arp_req = arp_req[0]
    # entra al switch desde pc1 y sale por AMBOS puertos de salida
    assert [(o['enlace'], o['nodo']) for o in arp_req if o['profundidad'] == 0] == [('e1', 'sw')]
    assert sorted((o['enlace'], o['nodo']) for o in arp_req if o['profundidad'] == 1) == [
        ('e2', 'pc2'), ('e3', 'pc3')]
    eco = [v for v in paquetes.values() if v[0]['resumen'].get('icmp', {}).get('tipo') == 8]
    assert len(eco) == 1
    assert [(o['enlace'], o['nodo']) for o in eco[0]] == [('e1', 'sw'), ('e2', 'pc2')]   # solo hacia pc2
    assert not any(o['enlace'] == 'e3' and o['resumen']['protocolo'] == 'icmp' for o in items)

    # Capas con tshark
    capas = cliente.get('/api/captura/observaciones/%s/capas' % arp_req[0]['id'], headers=AUTH).json()
    nombres = [c['nombre'] for c in capas['capas']]
    assert nombres[-2:] == ['eth', 'arp'], nombres
    arp = capas['capas'][-1]
    valores = {c['nombre']: c['valor'] for c in arp['campos']}
    assert valores['arp.opcode'] == '1' and valores['arp.dst.proto_ipv4'] == '10.0.0.2'
    capas_eco = cliente.get('/api/captura/observaciones/%s/capas' % eco[0][1]['id'], headers=AUTH).json()
    assert [c['nombre'] for c in capas_eco['capas']][-3:] == ['eth', 'ip', 'icmp']

    # PCAPng descargado == lo que muestra la interfaz, verificado por tshark
    ruta = tmp_path / 'descarga.pcapng'
    ruta.write_bytes(cliente.get('/api/captura/pcap', headers=AUTH).content)
    tshark = subprocess.run(['tshark', '-n', '-r', str(ruta), '-T', 'fields', '-E', 'separator=|',
                             '-e', 'frame.interface_name', '-e', 'frame.comment',
                             '-e', '_ws.col.Protocol', '-e', 'frame.time_epoch'],
                            capture_output=True, text=True, check=True).stdout.splitlines()
    filas = [l.split('|') for l in tshark]
    por_id = {o['id']: o for o in items}
    vistas = set()
    for intf, comentario, proto, _ in filas:
        if not comentario:
            continue
        _, oid, paquete, _ = comentario.split(' ')
        o = por_id[oid]
        assert o['intf'] == intf and o['paquete'] == paquete
        assert proto.lower() == o['resumen']['protocolo'].replace('ipv4', 'ip')
        vistas.add(oid)
    assert vistas == set(por_id), 'el PCAP y la interfaz no coinciden'

    # Detener: sin restos
    assert cliente.post('/api/red/detener', headers=AUTH).json()['estado'] == 'diseño'
    assert esperar(lambda: interfaces_nuestras() == [], 5)
    bridges = subprocess.run(['ovs-vsctl', 'list-br'], capture_output=True, text=True).stdout.split()
    assert SWITCH not in bridges
    assert procesos('tcpdump -i ti') == []
    assert procesos('bash --norc --noprofile -i') == []


def test_router_entre_dos_redes(tmp_path):
    """pc–router–pc: el eco se correlaciona a través del router (TTL 64 → 63, confianza media)."""
    from minired.modelo.topologia import Lab
    lab = Lab.model_validate({'version': 1, 'nodos': [
        {'id': 'h1', 'tipo': 'pc', 'nombre': 'tq1', 'interfaces': [{'puerto': 0, 'ip': '10.1.1.1/24'}],
         'gateway': '10.1.1.254'},
        {'id': 'r', 'tipo': 'router', 'nombre': 'tr1', 'interfaces': [
            {'puerto': 0, 'ip': '10.1.1.254/24'}, {'puerto': 1, 'ip': '10.1.2.254/24'}]},
        {'id': 'h2', 'tipo': 'pc', 'nombre': 'tq2', 'interfaces': [{'puerto': 0, 'ip': '10.1.2.1/24'}],
         'gateway': '10.1.2.254'}],
        'enlaces': [{'id': 'e1', 'a': {'nodo': 'h1', 'puerto': 0}, 'b': {'nodo': 'r', 'puerto': 0}},
                    {'id': 'e2', 'a': {'nodo': 'r', 'puerto': 1}, 'b': {'nodo': 'h2', 'puerto': 0}}]})
    ctl = Controlador(RedMininet, directorio_capturas=str(tmp_path))
    app = crear_app(ctl, Config(puerto=8787, token=TOKEN))
    with TestClient(app, base_url='http://127.0.0.1:8787') as c:
        assert c.put('/api/lab', json=lab.model_dump(mode='json'), headers=AUTH).status_code == 200
        r = c.post('/api/red/iniciar', headers=AUTH)
        assert r.status_code == 200, r.text
        assert c.post('/api/captura/iniciar', headers=AUTH).status_code == 200
        r = c.post('/api/nodos/h1/ping', json={'destino': '10.1.2.1'}, headers=AUTH).json()
        assert r['codigo'] == 0, r
        time.sleep(1)
        c.post('/api/captura/detener', headers=AUTH)
        items = c.get('/api/captura/observaciones', headers=AUTH).json()['items']
        (tmp_path / 'observaciones_router.json').write_text(json.dumps(items, indent=1))
        eco = [o for o in items if o['resumen'].get('icmp', {}).get('tipo') == 8]
        assert [(o['enlace'], o['resumen']['ip']['ttl'], o['confianza']) for o in eco] == [
            ('e1', 64, 'alta'), ('e2', 63, 'media')]
        assert eco[1]['padre'] == eco[0]['id'] and eco[1]['paquete'] == eco[0]['paquete']
        assert c.post('/api/red/detener', headers=AUTH).json()['estado'] == 'diseño'
    assert not [i for i in os.listdir('/sys/class/net') if i.startswith(('tq', 'tr1'))]


def test_bajar_y_subir_enlace(tmp_path):
    """Bajar un enlace corta el tráfico y se informa; al subirlo vuelve todo, gateway incluido."""
    from minired.modelo.topologia import Lab
    lab = Lab.model_validate({'version': 1, 'nodos': [
        {'id': 'h1', 'tipo': 'pc', 'nombre': 'tk1', 'interfaces': [{'puerto': 0, 'ip': '10.7.1.1/24'}],
         'gateway': '10.7.1.254'},
        {'id': 'sw', 'tipo': 'switch', 'nombre': 'tksw'},
        {'id': 'r', 'tipo': 'router', 'nombre': 'tkr', 'interfaces': [
            {'puerto': 0, 'ip': '10.7.1.254/24'}, {'puerto': 1, 'ip': '10.7.2.254/24'}]},
        {'id': 'h2', 'tipo': 'pc', 'nombre': 'tk2', 'interfaces': [{'puerto': 0, 'ip': '10.7.2.1/24'}],
         'gateway': '10.7.2.254'}],
        'enlaces': [{'id': 'e1', 'a': {'nodo': 'h1', 'puerto': 0}, 'b': {'nodo': 'sw', 'puerto': 1}},
                    {'id': 'e2', 'a': {'nodo': 'sw', 'puerto': 2}, 'b': {'nodo': 'r', 'puerto': 0}},
                    {'id': 'e3', 'a': {'nodo': 'r', 'puerto': 1}, 'b': {'nodo': 'h2', 'puerto': 0}}]})
    ctl = Controlador(RedMininet, directorio_capturas=str(tmp_path))
    app = crear_app(ctl, Config(puerto=8787, token=TOKEN))

    def ping():
        return c.post('/api/nodos/h1/ping', json={'destino': '10.7.2.1'}, headers=AUTH).json()['codigo']

    def rutas(nodo):
        p = ctl.red.popen(nodo, ['ip', 'route'], stdout=subprocess.PIPE)
        return p.communicate(timeout=5)[0].decode()

    with TestClient(app, base_url='http://127.0.0.1:8787') as c:
        assert c.put('/api/lab', json=lab.model_dump(mode='json'), headers=AUTH).status_code == 200
        assert c.post('/api/red/iniciar', headers=AUTH).status_code == 200
        assert esperar(lambda: ping() == 0, 6)
        for enlace in ('e1', 'e3'):            # lado PC (con gateway) y lado router
            r = c.post('/api/enlaces/%s/estado' % enlace, json={'arriba': False}, headers=AUTH)
            assert r.status_code == 200, r.text
            assert c.get('/api/estado', headers=AUTH).json()['enlaces_caidos'] == [enlace]
            assert ping() != 0
            assert c.post('/api/enlaces/%s/estado' % enlace, json={'arriba': True}, headers=AUTH).status_code == 200
            assert c.get('/api/estado', headers=AUTH).json()['enlaces_caidos'] == []
            assert 'default via 10.7.1.254' in rutas('h1') and 'default via 10.7.2.254' in rutas('h2')
            assert esperar(lambda: ping() == 0, 6), 'no vuelve la conectividad al subir %s' % enlace
        c.post('/api/enlaces/e1/estado', json={'arriba': False}, headers=AUTH)
        assert c.post('/api/red/detener', headers=AUTH).json()['enlaces_caidos'] == []
    assert not [i for i in os.listdir('/sys/class/net') if i.startswith(('tk1', 'tk2', 'tkr', 'tksw'))]


def test_enlace_desconectado_arranca_caido_y_la_captura_lo_espera(tmp_path):
    """Un enlace "desconectado" arranca caído; la simulación arranca igual (tcpdump no abre una
    interfaz caída: ese extremo espera) y captura el enlace en cuanto se sube."""
    lab = lab_3pc(('td1', 'td2', 'td3'), 'tdsw').model_dump(mode='json')
    lab['enlaces'][1]['desconectado'] = True                         # e2: td2 sin cable
    ctl = Controlador(RedMininet, directorio_capturas=str(tmp_path))
    app = crear_app(ctl, Config(puerto=8787, token=TOKEN))
    with TestClient(app, base_url='http://127.0.0.1:8787') as c:
        assert c.put('/api/lab', json=lab, headers=AUTH).status_code == 200
        r = c.post('/api/red/iniciar', headers=AUTH)
        assert r.status_code == 200, r.text
        assert r.json()['enlaces_caidos'] == ['e2']

        def ping():
            return c.post('/api/nodos/pc1/ping', json={'destino': '10.0.0.2'}, headers=AUTH).json()['codigo']
        assert ping() != 0
        r = c.post('/api/captura/iniciar', headers=AUTH)
        assert r.status_code == 200, r.text
        estado = c.get('/api/estado', headers=AUTH).json()['captura']
        assert {x['intf'] for x in estado['capturadores'] if x['en_espera']} == {'td2-eth0', 'tdsw-eth2'}
        assert c.post('/api/enlaces/e2/estado', json={'arriba': True}, headers=AUTH).status_code == 200
        assert esperar(lambda: ping() == 0, 6)
        time.sleep(1)
        estado = c.post('/api/captura/detener', headers=AUTH).json()
        assert not any(x['en_espera'] for x in estado['capturadores'])
        items = c.get('/api/captura/observaciones', headers=AUTH).json()['items']
        assert any(o['enlace'] == 'e2' and o['nodo'] == 'pc2' for o in items)
        # Subirlo en vivo no cambia el diseño: sigue "desconectado" para la próxima vez.
        assert c.get('/api/lab', headers=AUTH).json()['enlaces'][1]['desconectado'] is True
        assert c.post('/api/red/detener', headers=AUTH).json()['enlaces_caidos'] == []
    assert not [i for i in os.listdir('/sys/class/net') if i.startswith(('td1', 'td2', 'td3', 'tdsw'))]
