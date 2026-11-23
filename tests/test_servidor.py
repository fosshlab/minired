import os
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from minired.runtime.controlador import Controlador
from minired.servidor.app import crear_app
from minired.servidor.seguridad import Config

from utiles import DATOS, RedFalsa, lab_3pc

TOKEN = 'secreto-de-prueba'
BASE = 'http://127.0.0.1:8787'
ORIGEN = 'http://127.0.0.1:8787'
AUTH = {'Authorization': 'Bearer ' + TOKEN}
WS_PROTO = ['minired', 'token.' + TOKEN]


@pytest.fixture
def cliente(tmp_path):
    ctl = Controlador(lambda plan: RedFalsa(plan, os.path.join(DATOS, 'lan_3pc_ping')),
                      directorio_capturas=str(tmp_path))
    app = crear_app(ctl, Config(puerto=8787, token=TOKEN))
    with TestClient(app, base_url=BASE) as c:
        yield c


def lab_json():
    return lab_3pc().model_dump(mode='json')


# --- seguridad ---------------------------------------------------------------

def test_api_exige_token(cliente):
    assert cliente.get('/api/estado').status_code == 401
    assert cliente.get('/api/estado', headers={'Authorization': 'Bearer otro'}).status_code == 401
    assert cliente.get('/api/estado', headers=AUTH).status_code == 200


def test_api_rechaza_origen_ajeno(cliente):
    r = cliente.post('/api/red/iniciar', headers={**AUTH, 'Origin': 'http://malo.example'})
    assert r.status_code == 403


def test_host_ajeno_rechazado(cliente):
    # DNS rebinding: un dominio que resuelve a 127.0.0.1 manda otro Host
    r = cliente.get('/api/estado', headers={**AUTH, 'Host': 'malo.example:8787'})
    assert r.status_code == 403


def test_ws_exige_origen_y_token(cliente):
    for headers, proto in [({'origin': 'http://malo.example'}, WS_PROTO),
                           ({}, WS_PROTO),
                           ({'origin': ORIGEN}, ['minired', 'token.otro']),
                           ({'origin': ORIGEN}, ['minired'])]:
        with pytest.raises(WebSocketDisconnect) as e:
            with cliente.websocket_connect('ws://127.0.0.1:8787/ws/eventos', headers=headers, subprotocols=proto) as ws:
                ws.receive_json()
        assert e.value.code == 4403
    with cliente.websocket_connect('ws://127.0.0.1:8787/ws/eventos', headers={'origin': ORIGEN}, subprotocols=WS_PROTO) as ws:
        assert ws.receive_json()['estado'] == 'diseño'


def test_cabeceras_de_seguridad(cliente):
    r = cliente.get('/api/estado', headers=AUTH)
    assert "frame-ancestors 'none'" in r.headers['content-security-policy']
    assert r.headers['x-content-type-options'] == 'nosniff'
    assert 'access-control-allow-origin' not in r.headers


@pytest.mark.parametrize('cambio', [
    lambda d: d['nodos'][1].update(nombre='pc1;reboot'),
    lambda d: d['nodos'][1]['interfaces'][0].update(ip='10.0.0.1/24; id'),
    lambda d: d['nodos'][1].update(gateway='$(id)'),
    lambda d: d['nodos'][1].update(cmd='id'),
])
def test_lab_con_inyeccion_rechazado(cliente, cambio):
    datos = lab_json()
    cambio(datos)
    r = cliente.put('/api/lab', json=datos, headers=AUTH)
    assert r.status_code == 422
    assert r.json()['errores']


def test_validar_en_espanol(cliente):
    datos = lab_json()
    datos['nodos'][1]['interfaces'][0]['ip'] = '10.0.0.0/24'
    r = cliente.post('/api/lab/validar', json=datos, headers=AUTH).json()
    assert r['ok'] is False
    assert any('dirección de red' in e for e in r['errores'])
    datos['nodos'][1]['nombre'] = 'PC1'
    r = cliente.post('/api/lab/validar', json=datos, headers=AUTH).json()
    assert any(e.startswith('PC1 nombre: formato inválido') for e in r['errores'])


def test_rutas_con_ids_invalidos(cliente):
    assert cliente.post('/api/nodos/x;y/ping', json={'destino': '10.0.0.2'}, headers=AUTH).status_code == 422
    assert cliente.get('/api/captura/observaciones/../../etc/capas', headers=AUTH).status_code == 404


# --- ciclo de vida y captura (con capturas reales reproducidas) -------------

def test_ciclo_completo_con_captura(cliente):
    assert cliente.post('/api/red/iniciar', headers=AUTH).status_code == 409   # lab vacío
    assert cliente.put('/api/lab', json=lab_json(), headers=AUTH).json() == {'ok': True}
    with cliente.websocket_connect('ws://127.0.0.1:8787/ws/eventos', headers={'origin': ORIGEN}, subprotocols=WS_PROTO) as ws:
        assert ws.receive_json()['estado'] == 'diseño'
        r = cliente.post('/api/red/iniciar', headers=AUTH)
        assert r.status_code == 200 and r.json()['estado'] == 'activa'
        assert r.json()['enlaces']['e2'] == {'a': 'xa2-eth0', 'b': 'xs1-eth2'}
        assert cliente.put('/api/lab', json=lab_json(), headers=AUTH).status_code == 409
        estados = [ws.receive_json()['estado'], ws.receive_json()['estado']]
        assert estados == ['iniciando', 'activa']

        assert cliente.post('/api/captura/iniciar', headers=AUTH).status_code == 200
        items = []
        limite = time.monotonic() + 5
        while len(items) < 9 and time.monotonic() < limite:
            msg = ws.receive_json()
            if msg['tipo'] == 'observaciones':
                items += msg['items']
        assert len(items) == 9
    assert {o['confianza'] for o in items} == {'alta'}
    paquetes = {}
    for o in items:
        paquetes.setdefault(o['paquete'], []).append(o)
    arp = next(v for v in paquetes.values() if v[0]['resumen']['protocolo'] == 'arp')
    assert sorted(o['enlace'] for o in arp) == ['e1', 'e2', 'e3']
    eco = next(v for v in paquetes.values() if v[0]['resumen'].get('icmp', {}).get('tipo') == 8)
    assert [(o['enlace'], o['hacia']) for o in eco] == [('e1', 'b'), ('e2', 'a')]

    r = cliente.post('/api/captura/detener', headers=AUTH).json()
    assert r['activa'] is False
    assert {c['caidos_kernel'] for c in r['capturadores']} == {0}

    lista = cliente.get('/api/captura/observaciones?desde=3', headers=AUTH).json()
    assert [o['id'] for o in lista['items']] == [o['id'] for o in items[3:]]
    assert [int(o['ts_ns']) for o in items] == sorted(int(o['ts_ns']) for o in items)

    pcap = cliente.get('/api/captura/pcap', headers=AUTH)
    assert pcap.status_code == 200 and pcap.content[:4] == b'\x0a\x0d\x0d\x0a'
    assert pcap.content.count(b'minired o') == 9

    assert cliente.post('/api/red/detener', headers=AUTH).json()['estado'] == 'diseño'
    assert cliente.get('/api/captura/observaciones', headers=AUTH).status_code == 404


def test_terminal_pty(cliente):
    cliente.put('/api/lab', json=lab_json(), headers=AUTH)
    cliente.post('/api/red/iniciar', headers=AUTH)
    with pytest.raises(WebSocketDisconnect) as e:
        with cliente.websocket_connect('ws://127.0.0.1:8787/ws/terminal/sw', headers={'origin': ORIGEN},
                                       subprotocols=WS_PROTO) as ws:
            ws.receive_bytes()
    assert e.value.code == 4404
    with cliente.websocket_connect('ws://127.0.0.1:8787/ws/terminal/pc1', headers={'origin': ORIGEN},
                                   subprotocols=WS_PROTO) as ws:
        ws.send_text('{"tipo": "resize", "filas": 30, "columnas": 100}')
        ws.send_bytes(b'echo $((6*7)); stty size\n')
        salida = b''
        limite = time.monotonic() + 5
        while (b'42' not in salida or b'30 100' not in salida) and time.monotonic() < limite:
            salida += ws.receive_bytes()
        assert b'42' in salida and b'30 100' in salida
    ctl = cliente.app.state.controlador
    assert ctl.terminales == set()


def test_ws_eventos_libera_al_desconectar(cliente):
    ctl = cliente.app.state.controlador
    with cliente.websocket_connect('ws://127.0.0.1:8787/ws/eventos', headers={'origin': ORIGEN},
                                   subprotocols=WS_PROTO) as ws:
        ws.receive_json()
        assert len(ctl.bus.colas) == 1
    limite = time.monotonic() + 3
    while ctl.bus.colas and time.monotonic() < limite:
        time.sleep(0.05)
    assert ctl.bus.colas == set()
