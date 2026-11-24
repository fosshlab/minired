"""Graba capturas reales de los escenarios de la etapa 3 para las pruebas sin root (VM, con root).

    cd <repo> && sudo ~/.venvs/minired/bin/python tests/grabar_capturas.py [escenario ...]

Por escenario deja en tests/datos/<escenario>/: un .pcap por interfaz (lo que tcpdump -Q in vio
al llegar a ese extremo), estado.json (instantánea de rutas, direcciones, ARP y tabla MAC al iniciar
y al detener la captura) y lab.json. Sin calentar ARP: así quedan grabadas las consultas ARP.
"""

import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from escenarios import lab_nat_acl, lab_ospf, lab_servicios, lab_vlan  # noqa: E402
from utiles import lab_3pc  # noqa: E402
from minired.runtime.controlador import Controlador  # noqa: E402
from minired.runtime.edunet import RedMininet  # noqa: E402
from minired.servidor.app import crear_app  # noqa: E402
from minired.servidor.seguridad import Config  # noqa: E402

TOKEN = 'grabar'
AUTH = {'Authorization': 'Bearer ' + TOKEN}
DATOS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'datos')


def esperar(fn, segundos):
    limite = time.monotonic() + segundos
    while time.monotonic() < limite:
        if fn():
            return True
        time.sleep(0.5)
    return False


def ping(c, nodo, destino):
    return c.post('/api/nodos/%s/ping' % nodo, json={'destino': destino}, headers=AUTH).json()


def sh(ctl, nodo, *argv):
    p = ctl.red.popen(nodo, list(argv), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.communicate(timeout=15)[0].decode(errors='replace')


ESCENARIOS = {
    'lan_3pc': (lambda: lab_3pc(('xb1', 'xb2', 'xb3'), 'xbs'), None,
                lambda c, ctl: [ping(c, 'pc1', '10.0.0.2')], 1.5),
    # nombre: (lab, preparar(c, ctl), tráfico(c, ctl), espera tras el tráfico)
    'vlan_intervlan': (lab_vlan, None,
                       lambda c, ctl: [ping(c, 'v1', '10.20.0.1'), ping(c, 'v1', '10.10.0.2'),
                                       ping(c, 'v4', '10.10.0.1')], 1.5),
    'nat_acl': (lab_nat_acl, None,
                lambda c, ctl: [ping(c, 'n1', '203.0.113.10'), ping(c, 'n2', '203.0.113.10')], 1.5),
    'ospf': (lab_ospf,
             lambda c, ctl: esperar(lambda: ping(c, 'f1', '10.62.0.1')['codigo'] == 0, 60),
             lambda c, ctl: [ping(c, 'f1', '10.62.0.1')], 11),            # 11 s: entran hellos
    'dhcp_dns_http': (lab_servicios,
                      lambda c, ctl: esperar(lambda: 'inet ' in sh(ctl, 'ca', 'ip', '-4', 'addr', 'show', 'dc1-eth0'), 20),
                      lambda c, ctl: [c.post('/api/nodos/ca/dhcp', headers=AUTH).json(),
                                      sh(ctl, 'ca', 'curl', '-s', '-m', '5', 'http://web.lab/')], 1.5),
}


def grabar(nombre):
    fabrica, preparar, trafico, espera = ESCENARIOS[nombre]
    lab = fabrica()
    destino = os.path.join(DATOS, nombre)
    ctl = Controlador(RedMininet)
    app = crear_app(ctl, Config(puerto=8787, token=TOKEN))
    with TestClient(app, base_url='http://127.0.0.1:8787') as c:
        assert c.put('/api/lab', json=lab.model_dump(mode='json'), headers=AUTH).status_code == 200
        r = c.post('/api/red/iniciar', headers=AUTH)
        assert r.status_code == 200, r.text
        try:
            if preparar is not None:
                assert preparar(c, ctl), 'no se pudo preparar %s' % nombre
            assert c.post('/api/captura/iniciar', headers=AUTH).status_code == 200
            resultado = trafico(c, ctl)
            time.sleep(espera)
            c.post('/api/captura/detener', headers=AUTH)
            sesion = ctl.captura
            shutil.rmtree(destino, ignore_errors=True)
            os.makedirs(destino)
            for archivo in os.listdir(sesion.directorio):
                if archivo.endswith('.pcap'):
                    shutil.copy(os.path.join(sesion.directorio, archivo), destino)
            with open(os.path.join(destino, 'estado.json'), 'w') as f:
                json.dump(sesion.estado_red, f, indent=1, sort_keys=True)
            with open(os.path.join(destino, 'lab.json'), 'w') as f:
                json.dump(lab.model_dump(mode='json'), f, indent=1)
            print(nombre, len(sesion.observaciones), 'observaciones;', json.dumps(resultado)[:300])
        finally:
            c.post('/api/red/detener', headers=AUTH)


if __name__ == '__main__':
    for nombre in sys.argv[1:] or ESCENARIOS:
        grabar(nombre)
