"""Campos del decodificador propio contra lo que muestra tshark 4.2.2 en la VM para las mismas capturas:

xs1-eth1.pcap #1: arp.opcode=1 10.0.0.1 -> 10.0.0.2, eth 00:00:00:00:00:01 -> ff:ff:ff:ff:ff:ff
xa2-eth0.pcap #2: ip.ttl=64 ip.id=0x70fc icmp.type=8 icmp.ident=5359 icmp.seq=1
"""
import io
import os
import struct

from minired.captura.decodificar import clave_ipv4_reenviada, decodificar
from minired.captura.pcap import LectorIncremental, escribir_pcapng, leer_archivo

D = os.path.join(os.path.dirname(__file__), 'datos', 'lan_3pc_ping')


def test_arp_request():
    r = decodificar(leer_archivo(os.path.join(D, 'xs1-eth1.pcap'))[0].datos)
    assert r['capas'] == ['eth', 'arp']
    assert r['eth'] == {'dst': 'ff:ff:ff:ff:ff:ff', 'src': '00:00:00:00:00:01', 'tipo': '0x0806'}
    assert r['arp']['op'] == 1 and r['arp']['spa'] == '10.0.0.1' and r['arp']['tpa'] == '10.0.0.2'
    assert r['info'] == '¿Quién tiene 10.0.0.2? Avisar a 10.0.0.1'


def test_arp_reply():
    r = decodificar(leer_archivo(os.path.join(D, 'xa1-eth0.pcap'))[0].datos)
    assert r['arp']['op'] == 2 and r['arp']['sha'] == '00:00:00:00:00:02'
    assert r['info'] == '10.0.0.2 está en 00:00:00:00:00:02'


def test_icmp_echo_request():
    regs = leer_archivo(os.path.join(D, 'xa2-eth0.pcap'))
    assert [x.n for x in regs] == [1, 2]
    r = decodificar(regs[1].datos)
    assert r['capas'] == ['eth', 'ip', 'icmp']
    assert r['ip']['ttl'] == 64 and r['ip']['id'] == 0x70fc and r['ip']['proto'] == 1
    assert r['icmp'] == {'tipo': 8, 'codigo': 0, 'ident': 5359, 'seq': 1}
    assert r['protocolo'] == 'icmp'
    assert regs[1].largo_original == 98


def test_timestamps_en_nanosegundos():
    reg = leer_archivo(os.path.join(D, 'xs1-eth1.pcap'))[0]
    assert reg.ts_ns == 1795445199926187489      # tshark -t e: 1795445199.926187489


def test_lector_incremental_por_trozos():
    datos = open(os.path.join(D, 'xa2-eth0.pcap'), 'rb').read()
    lector = LectorIncremental()
    regs = []
    for i in range(0, len(datos), 7):
        regs += lector.alimentar(datos[i:i + 7])
    assert [r.n for r in regs] == [1, 2]
    assert regs[1].datos == leer_archivo(os.path.join(D, 'xa2-eth0.pcap'))[1].datos


def test_truncado_y_desconocido():
    assert decodificar(b'\x00' * 5)['capas'] == []
    r = decodificar(b'\xff' * 12 + b'\x88\xcc' + b'\x00' * 30)
    assert r['capas'] == ['eth'] and '0x88cc' in r['info']


def test_clave_reenvio_ignora_ttl_y_mac():
    d = leer_archivo(os.path.join(D, 'xa2-eth0.pcap'))[1].datos
    clave, ttl = clave_ipv4_reenviada(d)
    reenviado = bytearray(d)
    reenviado[0:12] = b'\xaa' * 12           # MAC nuevas
    reenviado[14 + 8] = 63                    # TTL - 1
    reenviado[14 + 10:14 + 12] = b'\x12\x34'  # checksum nuevo
    clave2, ttl2 = clave_ipv4_reenviada(bytes(reenviado) + b'\0' * 4)  # con relleno distinto
    assert clave == clave2 and (ttl, ttl2) == (64, 63)
    assert clave_ipv4_reenviada(leer_archivo(os.path.join(D, 'xa1-eth0.pcap'))[0].datos) is None


def test_pcapng_bloques():
    f = io.BytesIO()
    escribir_pcapng(f, [('xs1-eth1', 'e1 · entrada')], [(0, 1795445199926187489, 42, b'\x01' * 42, 'o1 p1')])
    b = f.getvalue()
    assert struct.unpack('<I', b[:4])[0] == 0x0A0D0D0A
    assert b'xs1-eth1' in b and b'o1 p1' in b
    assert len(b) % 4 == 0
