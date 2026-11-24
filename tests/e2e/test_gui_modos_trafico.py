"""e2e: modo Simple (vista OSI estilo Packet Tracer) y Avanzado (estilo Wireshark) en los 5 escenarios,
y el enlace "desconectado" del diseño. Mismo servidor y variables que test_gui_enlaces_seleccion.py.

Los laboratorios son los de tests/escenarios.py (las mismas topologías que el menú Ejemplos, con
nombres propios para no chocar con otra red de la VM). Capturas en $MINIRED_E2E_CAPTURAS si se indica.
"""

import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_gui_enlaces_seleccion import (URL, cargar_lab, encuadrar, expect, nodo, pagina,  # noqa: E402,F401
                                        sync_api)

pytestmark = pytest.mark.skipif(not URL, reason='falta MINIRED_E2E_URL (servidor minired gui en marcha)')

from escenarios import lab_nat_acl, lab_ospf, lab_servicios, lab_vlan  # noqa: E402
from utiles import lab_3pc  # noqa: E402

CAPTURAS = os.environ.get('MINIRED_E2E_CAPTURAS')


@pytest.fixture(autouse=True)
def red_detenida_al_terminar(pagina, request, tmp_path):
    """Cada prueba deja la red detenida aunque falle (si no, las siguientes no pueden iniciar)
    y, si falló, guarda la pantalla para ver qué pasó."""
    yield
    pag = pagina
    if CAPTURAS and getattr(request.node, 'fallo', False):
        pag.screenshot(path=os.path.join(CAPTURAS, 'fallo_%s.png' % request.node.name))
    if 'activa' in (pag.locator('.estado').text_content() or ''):
        detener(pag)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    resultado = yield
    if resultado.get_result().when == 'call' and resultado.get_result().failed:
        item.fallo = True


def con_posiciones(lab):
    """Ubica los equipos en una grilla (los escenarios de prueba no traen posiciones)."""
    datos = lab.model_dump(mode='json')
    switches = [n for n in datos['nodos'] if n['tipo'] == 'switch']
    routers = [n for n in datos['nodos'] if n['tipo'] == 'router']
    resto = [n for n in datos['nodos'] if n['tipo'] not in ('switch', 'router')]
    for fila, grupo in enumerate((routers, switches, resto)):
        for i, n in enumerate(grupo):
            n['x'], n['y'] = 60 + i * 190, 40 + fila * 170
    return datos


def cargar(pag, tmp_path, lab):
    ruta = tmp_path / 'lab.json'
    ruta.write_text(json.dumps(con_posiciones(lab) if not isinstance(lab, dict) else lab))
    pag.locator('input[type=file]').set_input_files(str(ruta))
    expect(pag.locator('.react-flow__node')).to_have_count(len(json.loads(ruta.read_text())['nodos']))
    encuadrar(pag)


def iniciar(pag):
    pag.get_by_role('button', name='▶ Iniciar red').click()
    expect(pag.locator('.estado')).to_contain_text('activa', timeout=40000)


def detener(pag):
    boton = pag.locator('header button', has_text='Simulación')
    if 'capturando' in (boton.text_content() or ''):
        boton.click()
        expect(boton).not_to_contain_text('capturando', timeout=15000)
    pag.get_by_role('button', name='■ Detener red').click()
    expect(pag.locator('.estado')).to_contain_text('diseño', timeout=40000)


def ping(pag, origen, destino):
    nodo(pag, origen).click()
    pag.get_by_placeholder('IP destino').fill(destino)
    pag.get_by_role('button', name='ping -c 1').click()
    expect(pag.get_by_role('button', name='ping -c 1')).to_be_enabled(timeout=20000)
    return pag.locator('pre.salida').first.text_content()


def simulacion(pag):
    boton = pag.locator('header button', has_text='Simulación')
    boton.click()
    expect(boton).to_contain_text('capturando', timeout=15000)
    if pag.get_by_role('radio', name='Simple').get_attribute('aria-checked') != 'true':
        pag.get_by_role('radio', name='Simple').click()


def fila(pag, etiqueta, dispositivo):
    """Fila de la lista simple con esa etiqueta pedagógica, en ese dispositivo ("En dispositivo")."""
    filas = pag.locator('.lista-eventos.simple tbody tr').filter(has_text=etiqueta).filter(
        has=pag.locator('td:nth-child(4)', has_text=re.compile('^%s$' % dispositivo)))
    expect(filas.first).to_be_visible(timeout=15000)
    return filas.first


def ver_osi(pag, fila_, *esperados, captura=None):
    fila_.click()
    panel = pag.locator('.panel-osi')
    expect(panel.locator('.tabla-osi')).to_be_visible(timeout=10000)
    for texto in esperados:
        expect(panel.locator('.decisiones')).to_contain_text(texto, timeout=10000)
    if CAPTURAS and captura:
        pag.screenshot(path=os.path.join(CAPTURAS, captura))
    return panel


def avanzado_con_filtro(pag, filtro, esperado, captura=None):
    pag.get_by_role('radio', name='Avanzado').click()
    expect(pag.locator('.lista-eventos thead')).to_contain_text('Protocolo')
    pag.get_by_label('Filtro estilo Wireshark').fill(filtro)
    filas = pag.locator('.lista-eventos tbody tr')
    expect(filas.first).to_be_visible()
    assert filas.count() >= 1
    for i in range(filas.count()):
        assert re.search(esperado, filas.nth(i).text_content()), filas.nth(i).text_content()
    if CAPTURAS and captura:
        pag.screenshot(path=os.path.join(CAPTURAS, captura))
    pag.get_by_label('Filtro estilo Wireshark').fill('')
    pag.get_by_role('radio', name='Simple').click()


def test_3pc_arp_inundado_y_eco(pagina, tmp_path):
    pag = pagina
    cargar(pag, tmp_path, lab_3pc(('q1', 'q2', 'q3'), 'qsw'))
    iniciar(pag)
    simulacion(pag)
    assert ' 0% packet loss' in ping(pag, 'q1', '10.0.0.2')
    expect(pag.locator('.lista-eventos thead')).to_contain_text('Último dispositivo')
    panel = ver_osi(pag, fila(pag, 'ARP: ¿quién tiene 10.0.0.2? (pregunta q1)', 'qsw'),
                    'La MAC destino es broadcast: la inunda', 'Aprende la MAC de origen',
                    captura='20_simple_osi_switch_arp.png')
    expect(panel.locator('.resultado')).to_have_text('Inunda')
    expect(panel.locator('.salidas button')).to_have_count(2)                   # dos puertos de salida
    panel.get_by_role('button', name=re.compile('Dónde nace: q1')).click()
    expect(panel.locator('.decisiones')).to_contain_text('pregunta por ARP con un broadcast')
    panel.get_by_role('button', name='Volver a qsw').click()
    ver_osi(pag, fila(pag, 'Eco ICMP q1 → q2', 'q2'), 'responde con una respuesta de eco')
    panel.get_by_role('tab', name='Detalle de la PDU').click()
    expect(panel.locator('.campos-pdu').first).to_contain_text('IPv4')
    avanzado_con_filtro(pag, 'icmp', 'ICMP', captura='26_avanzado_filtro_wireshark.png')
    detener(pag)


def test_vlan_intervlan(pagina, tmp_path):
    pag = pagina
    cargar(pag, tmp_path, lab_vlan())
    iniciar(pag)
    ping(pag, 'v1', '10.20.0.1')                                                  # calienta ARP
    simulacion(pag)
    assert ' 0% packet loss' in ping(pag, 'v1', '10.20.0.1')
    ver_osi(pag, fila(pag, 'Eco ICMP v1 → v3', 'vr'), 'subinterfaz vr-eth0.10', 'Baja el TTL: 64 → 63',
            'vr-eth0.20 (subinterfaz: etiqueta 802.1Q VLAN 20)', captura='21_simple_osi_router_on_a_stick.png')
    ver_osi(pag, fila(pag, 'Eco ICMP v1 → v3', 'vsa'), 'puerto de acceso de la VLAN 10')
    avanzado_con_filtro(pag, 'vlan.id == 20', 'ICMP')
    detener(pag)


def test_ospf(pagina, tmp_path):
    pag = pagina
    cargar(pag, tmp_path, lab_ospf())
    iniciar(pag)
    for _ in range(30):
        if ' 0% packet loss' in ping(pag, 'f1', '10.62.0.1'):
            break
        pag.wait_for_timeout(2000)
    simulacion(pag)
    assert ' 0% packet loss' in ping(pag, 'f1', '10.62.0.1')
    ver_osi(pag, fila(pag, 'Eco ICMP f1 → f2', 'fr1'), 'aprendida por OSPF', 'Baja el TTL: 64 → 63',
            captura='22_simple_osi_ospf.png')
    detener(pag)


def test_dhcp_dns_http(pagina, tmp_path):
    pag = pagina
    cargar(pag, tmp_path, lab_servicios())
    iniciar(pag)
    simulacion(pag)
    nodo(pag, 'dc1').click()
    pag.get_by_role('button', name='Pedir IP por DHCP de nuevo').click()
    expect(pag.locator('pre.salida').first).to_contain_text('recibió', timeout=30000)
    ver_osi(pag, fila(pag, 'DHCP Discover: dc1 busca un servidor', 'dsa'), 'inunda')
    ver_osi(pag, fila(pag, 'DHCP Discover: dc1 busca un servidor', 'da1'), 'dnsmasq (servidor DHCP) recibe el DISCOVER',
            captura='23_simple_osi_dhcp_servidor.png')
    ver_osi(pag, fila(pag, 'DHCP Discover: dc1 busca un servidor', 'dc2'), 'No es servidor DHCP')
    avanzado_con_filtro(pag, 'dhcp && udp.port == 67', 'DHCP')
    detener(pag)


def test_nat_y_acl(pagina, tmp_path):
    pag = pagina
    cargar(pag, tmp_path, lab_nat_acl())
    iniciar(pag)
    ping(pag, 'n1', '203.0.113.10')
    simulacion(pag)
    assert ' 0% packet loss' in ping(pag, 'n1', '203.0.113.10')
    assert '100% packet loss' in ping(pag, 'n2', '203.0.113.10')
    ver_osi(pag, fila(pag, 'Eco ICMP n1 → nsrv', 'nr'), 'NAT (PAT) traduce la IP de origen 10.40.0.1 → 203.0.113.1',
            captura='24_simple_osi_nat.png')
    panel = ver_osi(pag, fila(pag, 'Eco ICMP n2 → nsrv', 'nr'), 'regla 1 (denegar icmp desde 10.40.0.2/32)',
                    'No se observó la salida', captura='25_simple_osi_acl.png')
    expect(panel.locator('.resultado')).to_have_text('Descarta')
    # Del modo simple al avanzado sin perder el paquete elegido: capas completas de tshark.
    panel.get_by_role('button', name=re.compile('Ver capas completas')).click()
    expect(pag.locator('.panel-capas')).to_contain_text('Internet Protocol Version 4', timeout=10000)
    pag.get_by_role('radio', name='Simple').click()
    detener(pag)


def test_enlace_desconectado_del_diseno(pagina, tmp_path):
    pag = pagina
    datos = con_posiciones(lab_3pc(('q1', 'q2', 'q3'), 'qsw'))
    datos['enlaces'][1]['desconectado'] = True                                    # e2: q2 sin cable
    cargar(pag, tmp_path, datos)
    arista = pag.locator('[data-testid="rf__edge-e2"]')
    expect(arista.locator('.arista')).to_have_class(re.compile(r'\bcaida\b'))     # ya en el diseño
    arista.locator('.arista-zona').click(force=True)
    expect(pag.get_by_label('Arranca desconectado (cable suelto)')).to_be_checked()
    if CAPTURAS:
        pag.screenshot(path=os.path.join(CAPTURAS, '27_enlace_desconectado_diseno.png'))
    iniciar(pag)
    expect(arista.locator('.arista')).to_have_class(re.compile(r'\bcaida\b'))
    simulacion(pag)                                  # la captura arranca aunque el enlace esté caído
    assert '100% packet loss' in ping(pag, 'q1', '10.0.0.2')
    arista.locator('.arista-zona').click(force=True)
    expect(pag.locator('.lateral')).to_contain_text('Estado: caído')
    pag.get_by_role('button', name='Subir enlace').click()
    expect(arista.locator('.arista')).not_to_have_class(re.compile(r'\bcaida\b'))
    assert ' 0% packet loss' in ping(pag, 'q1', '10.0.0.2')
    fila(pag, 'Eco ICMP q1 → q2', 'q2')              # y el enlace que se subió se capturó
    detener(pag)
    # Subirlo en vivo no cambió el diseño: sigue desconectado.
    expect(arista.locator('.arista')).to_have_class(re.compile(r'\bcaida\b'))
    arista.locator('.arista-zona').click(force=True)
    expect(pag.get_by_label('Arranca desconectado (cable suelto)')).to_be_checked()
