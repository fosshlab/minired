"""Prueba de punta a punta en el navegador: selección por rectángulo y bajar/subir enlace.

Corre contra un `minired gui` real (en la VM, con root). Se saltea si no se indica la URL.

    # en la VM (puerto propio para no molestar a otro servidor):
    sudo ~/.venvs/minired/bin/python -m minired gui --puerto 8797 --token-archivo /tmp/tok
    # en el equipo con el navegador (túnel ssh -L 8797:127.0.0.1:8797 …):
    MINIRED_E2E_URL='http://127.0.0.1:8797/#token=…' python -m pytest tests/e2e -v

Requiere `pip install playwright` y un Chromium (MINIRED_E2E_CHROME= ruta, opcional).
Usa nombres propios (q1, q2, q3, qsw) y deja la red detenida al terminar.
"""

import json
import os
import re

import pytest

URL = os.environ.get('MINIRED_E2E_URL')
pytestmark = pytest.mark.skipif(not URL, reason='falta MINIRED_E2E_URL (servidor minired gui en marcha)')

sync_api = pytest.importorskip('playwright.sync_api')
expect = sync_api.expect

# q1 queda sin conectar para probar que arrastrar desde el punto verde sigue conectando.
LAB = {'version': 1, 'nodos': [
    {'id': 'qsw', 'tipo': 'switch', 'nombre': 'qsw', 'x': 420, 'y': 80, 'interfaces': []},
    {'id': 'q1', 'tipo': 'pc', 'nombre': 'q1', 'x': 120, 'y': 300, 'interfaces': [{'puerto': 0, 'ip': '10.77.0.1/24'}]},
    {'id': 'q2', 'tipo': 'pc', 'nombre': 'q2', 'x': 420, 'y': 300, 'interfaces': [{'puerto': 0, 'ip': '10.77.0.2/24'}]},
    {'id': 'q3', 'tipo': 'pc', 'nombre': 'q3', 'x': 680, 'y': 300, 'interfaces': [{'puerto': 0, 'ip': '10.77.0.3/24'}]},
], 'enlaces': [
    {'id': 'e2', 'a': {'nodo': 'q2', 'puerto': 0}, 'b': {'nodo': 'qsw', 'puerto': 2}},
    {'id': 'e3', 'a': {'nodo': 'q3', 'puerto': 0}, 'b': {'nodo': 'qsw', 'puerto': 3}},
]}


@pytest.fixture(scope='module')
def pagina():
    with sync_api.sync_playwright() as p:
        chrome = os.environ.get('MINIRED_E2E_CHROME')
        nav = p.chromium.launch(headless=True, **({'executable_path': chrome} if chrome else {}))
        pag = nav.new_page(viewport={'width': 1440, 'height': 1200})
        errores = []
        pag.on('pageerror', lambda e: errores.append(str(e)))
        pag.goto(URL)
        expect(pag.locator('.estado')).to_contain_text('diseño', timeout=10000)
        yield pag
        if 'activa' in (pag.locator('.estado').text_content() or ''):
            pag.get_by_role('button', name='■ Detener red').click()
            expect(pag.locator('.estado')).to_contain_text('diseño', timeout=40000)
        assert errores == [], errores
        nav.close()


def cargar_lab(pag, tmp_path):
    ruta = tmp_path / 'lab.json'
    ruta.write_text(json.dumps(LAB))
    pag.locator('input[type=file]').set_input_files(str(ruta))
    expect(pag.locator('.react-flow__node')).to_have_count(4)
    encuadrar(pag)


def encuadrar(pag):
    """Control "encuadrar" de React Flow; espera a que la vista deje de moverse antes de medir."""
    pag.get_by_role('button', name='Fit View').click()
    previo = None
    for _ in range(60):
        actual = pag.locator('.react-flow__viewport').get_attribute('style')
        if actual == previo:
            return
        previo = actual
        pag.wait_for_timeout(100)


def nodo(pag, nombre):
    return pag.locator('.react-flow__node').filter(
        has=pag.locator('.nodo-nombre', has_text=re.compile('^%s$' % nombre)))


def caja(loc):
    b = loc.bounding_box()
    return b['x'], b['y'], b['width'], b['height']


def posicion(loc):
    """Posición del nodo en el lienzo (la que guarda el laboratorio), del transform de React Flow."""
    m = re.search(r'translate\(([-\d.]+)px, ([-\d.]+)px\)', loc.get_attribute('style'))
    return float(m.group(1)), float(m.group(2))


def seleccionados(pag):
    return sorted(t.strip() for t in pag.locator('.nodo.seleccionado .nodo-nombre').all_text_contents())


def esperar_seleccion(pag, esperados, segundos=3):
    """La selección se dibuja en el cuadro siguiente al clic: se reintenta un momento."""
    for _ in range(int(segundos * 20)):
        if seleccionados(pag) == esperados:
            return
        pag.wait_for_timeout(50)
    assert seleccionados(pag) == esperados


def arrastrar(pag, desde, hasta, boton='left'):
    pag.mouse.move(*desde)
    pag.mouse.down(button=boton)
    pag.mouse.move(*hasta, steps=12)
    pag.mouse.up(button=boton)


def test_seleccion_por_rectangulo_mover_y_borrar(pagina, tmp_path):
    pag = pagina
    cargar_lab(pag, tmp_path)
    lienzo = caja(pag.locator('.react-flow__pane'))
    x2, y2, w2, h2 = caja(nodo(pag, 'q2'))
    x3, y3, w3, h3 = caja(nodo(pag, 'q3'))

    # Rectángulo desde el fondo que toca q2 y q3 (no q1 ni el switch).
    # (desde abajo: ahí no pasa ningún enlace, que suben hacia el switch)
    # Todo dentro del lienzo: si el rectángulo sale por un borde, React Flow desplaza la vista.
    assert x3 + w3 + 15 < lienzo[0] + lienzo[2] and y2 + h2 + 25 < lienzo[1] + lienzo[3], 'la red no entra'
    arrastrar(pag, (x2 - 15, y2 + h2 + 25), (x3 + w3 + 15, y3 - 10))
    esperar_seleccion(pag, ['q2', 'q3'])
    expect(pag.locator('.lateral')).to_contain_text('2 equipos')

    # Shift+clic suma y Ctrl+clic quita.
    nodo(pag, 'q1').click(modifiers=['Shift'])
    esperar_seleccion(pag, ['q1', 'q2', 'q3'])
    nodo(pag, 'q1').click(modifiers=['Control'])
    esperar_seleccion(pag, ['q2', 'q3'])

    # Mover en bloque: arrastrar q2 mueve también q3, lo mismo.
    antes2, antes3 = posicion(nodo(pag, 'q2')), posicion(nodo(pag, 'q3'))
    arrastrar(pag, (x2 + w2 / 2, y2 + 14), (x2 + w2 / 2 + 60, y2 + 14 + 40))
    despues2, despues3 = posicion(nodo(pag, 'q2')), posicion(nodo(pag, 'q3'))
    d2 = (despues2[0] - antes2[0], despues2[1] - antes2[1])
    d3 = (despues3[0] - antes3[0], despues3[1] - antes3[1])
    assert d2[0] > 40 and d2[1] > 25, d2                      # se movió (menos el umbral de arrastre)
    assert abs(d2[0] - d3[0]) < 1 and abs(d2[1] - d3[1]) < 1, (d2, d3)   # en bloque
    esperar_seleccion(pag, ['q2', 'q3'])

    # El paneo con el botón derecho mueve la vista y no selecciona.
    vista = pag.locator('.react-flow__viewport').get_attribute('style')
    # (lejos de los controles de zoom de abajo a la izquierda, que no panean)
    fondo = (lienzo[0] + 250, lienzo[1] + lienzo[3] - 20)
    arrastrar(pag, fondo, (fondo[0] + 100, fondo[1] - 30), boton='right')
    assert pag.locator('.react-flow__viewport').get_attribute('style') != vista
    vista = pag.locator('.react-flow__viewport').get_attribute('style')
    pag.mouse.move(*fondo)                                # barra espaciadora + arrastrar
    pag.keyboard.down('Space')
    arrastrar(pag, fondo, (fondo[0] + 80, fondo[1] - 20))
    pag.keyboard.up('Space')
    assert pag.locator('.react-flow__viewport').get_attribute('style') != vista
    esperar_seleccion(pag, ['q2', 'q3'])

    # Arrastrar desde el punto verde sigue conectando (no dibuja un rectángulo).
    encuadrar(pag)
    asa = caja(nodo(pag, 'q1').locator('.asa'))
    sx, sy, sw, sh = caja(nodo(pag, 'qsw'))
    arrastrar(pag, (asa[0] + asa[2] / 2, asa[1] + asa[3] / 2), (sx + sw / 2, sy + sh / 2))
    expect(pag.locator('.arista-linea')).to_have_count(3)

    # Borrar en bloque pide confirmación: cancelar no borra, aceptar sí.
    arrastrar(pag, (lienzo[0] + 20, lienzo[1] + 20), (lienzo[0] + lienzo[2] - 20, lienzo[1] + lienzo[3] - 60))
    esperar_seleccion(pag, ['q1', 'q2', 'q3', 'qsw'])
    nodo(pag, 'qsw').click(modifiers=['Shift'])          # quitar el switch
    nodo(pag, 'q1').click(modifiers=['Shift'])           # y q1: quedan q2 y q3
    mensajes = []
    pag.once('dialog', lambda d: (mensajes.append(d.message), d.dismiss()))
    pag.get_by_role('button', name=re.compile('Eliminar selección')).click()
    expect(pag.locator('.react-flow__node')).to_have_count(4)
    assert mensajes == ['¿Eliminar 2 equipos (q2, q3) y 2 enlaces? No se puede deshacer.']
    pag.once('dialog', lambda d: d.accept())
    pag.keyboard.press('Delete')
    expect(pag.locator('.react-flow__node')).to_have_count(2)
    expect(pag.locator('.arista-linea')).to_have_count(1)


def test_bajar_y_subir_enlace_se_ve_y_corta_el_trafico(pagina, tmp_path):
    pag = pagina
    cargar_lab(pag, tmp_path)
    pag.get_by_role('button', name='▶ Iniciar red').click()
    expect(pag.locator('.estado')).to_contain_text('activa', timeout=40000)

    def ping():
        nodo(pag, 'q2').click()
        pag.get_by_placeholder('IP destino').fill('10.77.0.3')
        pag.get_by_role('button', name='ping -c 1').click()
        expect(pag.get_by_role('button', name='ping -c 1')).to_be_enabled(timeout=20000)
        return pag.locator('pre.salida').first.text_content()

    arista = pag.locator('[data-testid="rf__edge-e3"]')
    assert ' 0% packet loss' in ping()
    arista.locator('.arista-zona').click(force=True)
    expect(pag.locator('.lateral')).to_contain_text('Estado: arriba')
    expect(pag.get_by_role('button', name='Subir enlace')).to_have_count(0)
    pag.get_by_role('button', name='Bajar enlace').click()
    expect(arista.locator('.arista')).to_have_class(re.compile(r'\bcaida\b'))
    expect(arista.locator('.puerto-caido')).to_have_count(2)
    expect(pag.locator('.lateral')).to_contain_text('Estado: caído')
    expect(pag.get_by_role('button', name='Bajar enlace')).to_have_count(0)
    assert '100% packet loss' in ping()

    # Se mantiene al recargar la página (lo informa el servidor).
    pag.reload()
    expect(pag.locator('.estado')).to_contain_text('activa', timeout=10000)
    expect(arista.locator('.arista')).to_have_class(re.compile(r'\bcaida\b'), timeout=10000)

    arista.locator('.arista-zona').click(force=True)
    pag.get_by_role('button', name='Subir enlace').click()
    expect(arista.locator('.arista')).not_to_have_class(re.compile(r'\bcaida\b'))
    expect(pag.locator('.lateral')).to_contain_text('Estado: arriba')
    assert ' 0% packet loss' in ping()

    # Al detener la red se resetea.
    arista.locator('.arista-zona').click(force=True)
    pag.get_by_role('button', name='Bajar enlace').click()
    expect(arista.locator('.arista')).to_have_class(re.compile(r'\bcaida\b'))
    pag.get_by_role('button', name='■ Detener red').click()
    expect(pag.locator('.estado')).to_contain_text('diseño', timeout=40000)
    expect(arista.locator('.arista')).not_to_have_class(re.compile(r'\bcaida\b'))
