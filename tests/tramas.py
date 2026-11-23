"""Constructores de tramas sintéticas (bytes reales de cabecera) para probar sin capturas."""

import struct


def _suma(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ip(a):
    return bytes(int(x) for x in a.split('.'))


def mac(m):
    return bytes.fromhex(m.replace(':', ''))


def eth(dst, src, tipo, carga, vlan=None, rellenar=True):
    cab = mac(dst) + mac(src)
    if vlan is not None:
        cab += struct.pack('!HH', 0x8100, vlan)
    trama = cab + struct.pack('!H', tipo) + carga
    if rellenar and len(trama) < 60:
        trama += b'\0' * (60 - len(trama))
    return trama


def ipv4(src, dst, proto, carga, ttl=64, ident=0x1234):
    cab = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(carga), ident, 0x4000, ttl, proto, 0,
                      _ip(src), _ip(dst))
    cab = cab[:10] + struct.pack('!H', _suma(cab)) + cab[12:]
    return cab + carga


def icmp_eco(ident=7, seq=1, tipo=8, datos=b'minired-datos-de-ping'):
    sin = struct.pack('!BBHHH', tipo, 0, 0, ident, seq) + datos
    return sin[:2] + struct.pack('!H', _suma(sin)) + sin[4:]


def udp(sport, dport, datos):
    return struct.pack('!HHHH', sport, dport, 8 + len(datos), 0) + datos


def tcp(sport, dport, datos=b'', banderas=0x18, seq=1000):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 5 << 4, banderas, 64240, 0, 0) + datos


def dhcp(tipo, xid=0xABCDEF01, chaddr='02:00:00:00:05:00', yiaddr='0.0.0.0', pedida=None):
    b = bytearray(240)
    b[0] = 1 if tipo in (1, 3) else 2
    b[1], b[2] = 1, 6
    b[4:8] = struct.pack('!I', xid)
    b[16:20] = _ip(yiaddr)
    b[28:34] = mac(chaddr)
    b[236:240] = b'\x63\x82\x53\x63'
    opciones = bytes([53, 1, tipo])
    if pedida:
        opciones += bytes([50, 4]) + _ip(pedida)
    return bytes(b) + opciones + b'\xff'


def dns(ident, nombre, respuesta_ip=None):
    q = b''.join(bytes([len(p)]) + p.encode() for p in nombre.split('.')) + b'\0' + struct.pack('!HH', 1, 1)
    if respuesta_ip is None:
        return struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + q
    an = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + _ip(respuesta_ip)
    return struct.pack('!HHHHHH', ident, 0x8180, 1, 1, 0, 0) + q + an
