"""Detalle por capa de un paquete elegido, con tshark bajo demanda (PDML).

Se le pasa a tshark solo ese paquete (un PCAP de un registro por stdin), sin
privilegios de root, con tiempo límite. El resultado se guarda en caché.
"""

import io
import os
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET

# Protocolos de PDML que no son capas del paquete
OMITIR = {'geninfo', 'fake-field-wrapper'}


class ErrorDisector(Exception):
    pass


def pcap_de_un_paquete(ts_ns, largo_original, datos):
    f = io.BytesIO()
    f.write(struct.pack('<IHHiIII', 0xA1B23C4D, 2, 4, 0, 0, 262144, 1))
    f.write(struct.pack('<IIII', ts_ns // 1_000_000_000, ts_ns % 1_000_000_000, len(datos),
                        largo_original))
    f.write(datos)
    return f.getvalue()


def _sin_privilegios():
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)


def disecar(ts_ns, largo_original, datos, tshark=None, timeout=15):
    tshark = tshark or shutil.which('tshark')
    if not tshark:
        raise ErrorDisector('tshark no está instalado')
    try:
        p = subprocess.run([tshark, '-n', '-r', '-', '-T', 'pdml'],
                           input=pcap_de_un_paquete(ts_ns, largo_original, datos),
                           capture_output=True, timeout=timeout, preexec_fn=_sin_privilegios,
                           cwd='/', env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    except subprocess.TimeoutExpired:
        raise ErrorDisector('tshark tardó demasiado') from None
    if p.returncode != 0:
        raise ErrorDisector('tshark falló: %s' % p.stderr.decode(errors='replace').strip()[:300])
    return pdml_a_capas(p.stdout)


def _campo(el):
    c = {
        'nombre': el.get('name', ''),
        'titulo': el.get('showname') or el.get('show') or el.get('name', ''),
        'valor': el.get('show', ''),
    }
    if el.get('pos') is not None and el.get('size') is not None:
        c['pos'] = int(el.get('pos'))
        c['largo'] = int(el.get('size'))
    hijos = [_campo(h) for h in el if h.tag in ('field', 'proto') and not h.get('hide') == 'yes']
    if hijos:
        c['campos'] = hijos
    return c


def pdml_a_capas(pdml):
    try:
        raiz = ET.fromstring(pdml)
    except ET.ParseError as exc:
        raise ErrorDisector('salida PDML inválida: %s' % exc) from None
    paquete = raiz.find('packet')
    if paquete is None:
        raise ErrorDisector('tshark no devolvió el paquete')
    return [_campo(p) for p in paquete.findall('proto') if p.get('name') not in OMITIR]
