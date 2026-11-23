"""Decodificador mínimo (stdlib) para animar: Ethernet, 802.1Q, ARP, IPv4, IPv6, ICMP, UDP, TCP.

Solo extrae lo necesario para el resumen y la correlación. El detalle completo
por capa lo da tshark bajo demanda (disector.py).
"""

import struct

ETH_ARP = 0x0806
ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = 0x8100

ICMP_TIPOS = {0: 'Echo reply', 3: 'Destino inalcanzable', 5: 'Redirect', 8: 'Echo request',
              11: 'TTL excedido'}
TCP_BANDERAS = 'FSRPAUEC'


def mac(b):
    return ':'.join('%02x' % x for x in b)


def ipv4(b):
    return '%d.%d.%d.%d' % tuple(b)


def decodificar(datos):
    """Devuelve un dict con 'capas', campos por capa, 'protocolo' (el más alto) e 'info'."""
    r = {'capas': [], 'protocolo': 'desconocido', 'info': ''}
    if len(datos) < 14:
        r['info'] = 'trama truncada (%d bytes)' % len(datos)
        return r
    dst, src, tipo = datos[0:6], datos[6:12], struct.unpack('!H', datos[12:14])[0]
    r['capas'].append('eth')
    r['eth'] = {'dst': mac(dst), 'src': mac(src), 'tipo': '0x%04x' % tipo}
    r['protocolo'] = 'eth'
    off = 14
    if tipo == ETH_VLAN and len(datos) >= 18:
        tci, tipo = struct.unpack('!HH', datos[14:18])
        r['capas'].append('vlan')
        r['vlan'] = {'id': tci & 0x0FFF, 'pcp': tci >> 13}
        r['protocolo'] = 'vlan'
        off = 18
    cuerpo = datos[off:]
    if tipo == ETH_ARP:
        _arp(cuerpo, r)
    elif tipo == ETH_IPV4:
        _ipv4(cuerpo, r)
    elif tipo == ETH_IPV6:
        _ipv6(cuerpo, r)
    else:
        r['info'] = 'Ethertype 0x%04x' % tipo
    return r


def _arp(b, r):
    if len(b) < 28:
        r['info'] = 'ARP truncado'
        return
    op = struct.unpack('!H', b[6:8])[0]
    a = {'op': op, 'sha': mac(b[8:14]), 'spa': ipv4(b[14:18]), 'tha': mac(b[18:24]), 'tpa': ipv4(b[24:28])}
    r['capas'].append('arp')
    r['arp'] = a
    r['protocolo'] = 'arp'
    if op == 1:
        r['info'] = '¿Quién tiene %s? Avisar a %s' % (a['tpa'], a['spa'])
    elif op == 2:
        r['info'] = '%s está en %s' % (a['spa'], a['sha'])
    else:
        r['info'] = 'ARP operación %d' % op


def _ipv4(b, r):
    if len(b) < 20 or b[0] >> 4 != 4:
        r['info'] = 'IPv4 truncado o inválido'
        return
    ihl = (b[0] & 0x0F) * 4
    largo_total, ident, frag = struct.unpack('!HHH', b[2:8])
    ttl, proto = b[8], b[9]
    ip = {'src': ipv4(b[12:16]), 'dst': ipv4(b[16:20]), 'ttl': ttl, 'proto': proto,
          'id': ident, 'largo': largo_total}
    r['capas'].append('ip')
    r['ip'] = ip
    r['protocolo'] = 'ipv4'
    r['info'] = '%s → %s' % (ip['src'], ip['dst'])
    if frag & 0x1FFF:
        r['info'] += ' (fragmento)'
        return
    _transporte(proto, b[ihl:], r)


def _ipv6(b, r):
    if len(b) < 40:
        r['info'] = 'IPv6 truncado'
        return
    import ipaddress
    src = str(ipaddress.IPv6Address(bytes(b[8:24])))
    dst = str(ipaddress.IPv6Address(bytes(b[24:40])))
    r['capas'].append('ipv6')
    r['ipv6'] = {'src': src, 'dst': dst, 'siguiente': b[6], 'hop_limit': b[7]}
    r['protocolo'] = 'ipv6'
    r['info'] = '%s → %s' % (src, dst)
    if b[6] == 58:
        r['capas'].append('icmpv6')
        r['protocolo'] = 'icmpv6'
        if len(b) > 40:
            r['icmpv6'] = {'tipo': b[40]}
            r['info'] += ' ICMPv6 tipo %d' % b[40]


def _transporte(proto, b, r):
    if proto == 1 and len(b) >= 8:
        tipo, codigo = b[0], b[1]
        icmp = {'tipo': tipo, 'codigo': codigo}
        if tipo in (0, 8):
            icmp['ident'], icmp['seq'] = struct.unpack('!HH', b[4:8])
        r['capas'].append('icmp')
        r['icmp'] = icmp
        r['protocolo'] = 'icmp'
        texto = ICMP_TIPOS.get(tipo, 'ICMP tipo %d' % tipo)
        if 'seq' in icmp:
            texto += ' id=%d seq=%d' % (icmp['ident'], icmp['seq'])
        r['info'] = '%s %s, TTL %d' % (r['info'], texto, r['ip']['ttl'])
    elif proto == 17 and len(b) >= 8:
        sport, dport = struct.unpack('!HH', b[0:4])
        r['capas'].append('udp')
        r['udp'] = {'sport': sport, 'dport': dport}
        r['protocolo'] = 'udp'
        r['info'] += ' UDP %d → %d' % (sport, dport)
    elif proto == 6 and len(b) >= 14:
        sport, dport = struct.unpack('!HH', b[0:4])
        banderas = ''.join(c for i, c in enumerate(TCP_BANDERAS) if b[13] & (1 << i))
        r['capas'].append('tcp')
        r['tcp'] = {'sport': sport, 'dport': dport, 'banderas': banderas}
        r['protocolo'] = 'tcp'
        r['info'] += ' TCP %d → %d [%s]' % (sport, dport, banderas)


def clave_ipv4_reenviada(datos):
    """Clave de un paquete IPv4 que ignora lo que cambia un router al reenviarlo.

    Quita la cabecera Ethernet (MAC nuevas), y pone en cero TTL y checksum de IP.
    Devuelve (clave, ttl) o None si no es IPv4.
    """
    off = 14
    if len(datos) >= 18 and datos[12:14] == b'\x81\x00':
        off = 18
    if len(datos) < off + 20 or struct.unpack('!H', datos[off - 2:off])[0] != ETH_IPV4:
        return None
    ip = bytearray(datos[off:])
    largo_total = struct.unpack('!H', ip[2:4])[0]
    if 20 <= largo_total <= len(ip):
        del ip[largo_total:]          # sin el relleno Ethernet, que puede cambiar en cada salto
    ttl = ip[8]
    ip[8] = 0
    ip[10:12] = b'\0\0'
    return bytes(ip), ttl
