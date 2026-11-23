"""Decodificador mínimo (stdlib) para animar: Ethernet, 802.1Q, ARP, IPv4, IPv6, ICMP, UDP, TCP,
OSPF, DHCP, DNS y HTTP.

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
DHCP_TIPOS = {1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release',
              8: 'Inform'}
OSPF_TIPOS = {1: 'Hello', 2: 'DB Description', 3: 'LS Request', 4: 'LS Update', 5: 'LS Ack'}
DNS_TIPOS = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
DNS_RCODE = {0: 'ok', 1: 'error de formato', 2: 'falla del servidor', 3: 'no existe', 5: 'rechazada'}
HTTP_METODOS = (b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ', b'HTTP/1.')


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
        if {sport, dport} & {67, 68}:
            _dhcp(b[8:], r)
        elif 53 in (sport, dport):
            _dns(b[8:], r)
    elif proto == 6 and len(b) >= 14:
        sport, dport = struct.unpack('!HH', b[0:4])
        banderas = ''.join(c for i, c in enumerate(TCP_BANDERAS) if b[13] & (1 << i))
        r['capas'].append('tcp')
        r['tcp'] = {'sport': sport, 'dport': dport, 'banderas': banderas}
        r['protocolo'] = 'tcp'
        r['info'] += ' TCP %d → %d [%s]' % (sport, dport, banderas)
        carga = b[(b[12] >> 4) * 4:]
        if 80 in (sport, dport) and carga.startswith(HTTP_METODOS):
            linea = bytes(carga[:carga.find(b'\r\n')] if b'\r\n' in carga else carga[:80])
            r['capas'].append('http')
            r['http'] = {'linea': linea.decode('latin-1')[:120]}
            r['protocolo'] = 'http'
            r['info'] = '%s → %s HTTP %s' % (r['ip']['src'], r['ip']['dst'], r['http']['linea'])
    elif proto == 89 and len(b) >= 2:
        tipo = b[1]
        r['capas'].append('ospf')
        r['ospf'] = {'tipo': tipo}
        r['protocolo'] = 'ospf'
        r['info'] += ' OSPF %s' % OSPF_TIPOS.get(tipo, 'tipo %d' % tipo)


def _dhcp(b, r):
    if len(b) < 240 or b[236:240] != b'\x63\x82\x53\x63':
        return
    d = {'op': b[0], 'xid': '0x%08x' % struct.unpack('!I', b[4:8])[0], 'yiaddr': ipv4(b[16:20]),
         'chaddr': mac(b[28:34])}
    i = 240
    while i < len(b) and b[i] != 255:
        if b[i] == 0:
            i += 1
            continue
        if i + 1 >= len(b):
            break
        codigo, largo = b[i], b[i + 1]
        valor = b[i + 2:i + 2 + largo]
        if codigo == 53 and largo >= 1:
            d['tipo'] = valor[0]
        elif codigo == 50 and largo == 4:
            d['pedida'] = ipv4(valor)
        i += 2 + largo
    r['capas'].append('dhcp')
    r['dhcp'] = d
    r['protocolo'] = 'dhcp'
    nombre = DHCP_TIPOS.get(d.get('tipo'), 'BOOTP')
    texto = 'DHCP %s xid %s' % (nombre, d['xid'])
    if d.get('tipo') in (2, 5):
        texto += ': ofrece %s a %s' % (d['yiaddr'], d['chaddr']) if d['tipo'] == 2 else \
            ': confirma %s para %s' % (d['yiaddr'], d['chaddr'])
    elif 'pedida' in d:
        texto += ': pide %s' % d['pedida']
    r['info'] = texto


def _dns_nombre(b, i, saltos=0):
    partes = []
    while i < len(b) and saltos < 16:
        largo = b[i]
        if largo == 0:
            return '.'.join(partes), i + 1
        if largo & 0xC0 == 0xC0:
            if i + 1 >= len(b):
                break
            nombre, _ = _dns_nombre(b, ((largo & 0x3F) << 8) | b[i + 1], saltos + 1)
            return '.'.join(partes + ([nombre] if nombre else [])), i + 2
        partes.append(bytes(b[i + 1:i + 1 + largo]).decode('ascii', 'replace'))
        i += 1 + largo
    return '.'.join(partes), len(b)


def _dns(b, r):
    if len(b) < 12:
        return
    ident, banderas, qd, an = struct.unpack('!HHHH', b[0:8])
    respuesta = bool(banderas & 0x8000)
    d = {'id': ident, 'respuesta': respuesta, 'rcode': banderas & 0xF}
    try:
        i = 12
        if qd:
            d['nombre'], i = _dns_nombre(b, 12)
            d['qtipo'] = DNS_TIPOS.get(struct.unpack('!H', b[i:i + 2])[0], '?')
            i += 4
        respuestas = []
        for _ in range(min(an, 8)):
            _, i = _dns_nombre(b, i)
            tipo, _, _, largo = struct.unpack('!HHIH', b[i:i + 10])
            i += 10
            if tipo == 1 and largo == 4:
                respuestas.append(ipv4(b[i:i + 4]))
            i += largo
        d['respuestas'] = respuestas
    except (struct.error, IndexError):
        pass
    r['capas'].append('dns')
    r['dns'] = d
    r['protocolo'] = 'dns'
    if respuesta:
        r['info'] = 'DNS respuesta %s %s → %s' % (d.get('qtipo', ''), d.get('nombre', ''),
                                                   ', '.join(d.get('respuestas', [])) or
                                                   DNS_RCODE.get(d['rcode'], 'rcode %d' % d['rcode']))
    else:
        r['info'] = 'DNS consulta %s %s' % (d.get('qtipo', ''), d.get('nombre', ''))


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


def _cuerpo_l2(datos):
    """(ethertype, desplazamiento de la carga) salteando una etiqueta 802.1Q."""
    if len(datos) >= 18 and datos[12:14] == b'\x81\x00':
        return struct.unpack('!H', datos[16:18])[0], 18
    return struct.unpack('!H', datos[12:14])[0], 14


def clave_conmutada(datos):
    """Clave de una trama que ignora lo que cambia un switch: la etiqueta 802.1Q (acceso ↔ troncal)
    y el relleno hasta 60 bytes. MAC, ethertype interior y carga quedan iguales."""
    if len(datos) < 14:
        return bytes(datos)
    tipo, off = _cuerpo_l2(datos)
    carga = datos[off:]
    if tipo == ETH_IPV4 and len(carga) >= 20:
        largo = struct.unpack('!H', carga[2:4])[0]
        if 20 <= largo <= len(carga):
            carga = carga[:largo]
    elif tipo == ETH_ARP and len(carga) >= 28:
        carga = carga[:28]
    return bytes(datos[:12]) + struct.pack('!H', tipo) + bytes(carga)


def clave_nat(datos):
    """Clave de un IPv4 que atravesó un NAT: ignora direcciones, puertos, identificador ICMP,
    TTL y sumas de verificación. Devuelve (clave, ttl, src, dst) o None."""
    if len(datos) < 34:
        return None
    tipo, off = _cuerpo_l2(datos)
    if tipo != ETH_IPV4:
        return None
    ip = bytes(datos[off:])
    largo = struct.unpack('!H', ip[2:4])[0]
    if not 20 <= largo <= len(ip):
        return None
    ip = ip[:largo]
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    l4 = bytearray(ip[ihl:])
    if proto == 1 and len(l4) >= 8:
        l4[2:6] = b'\0\0\0\0'          # checksum e identificador
    elif proto == 17 and len(l4) >= 8:
        l4[0:4] = b'\0\0\0\0'
        l4[6:8] = b'\0\0'
    elif proto == 6 and len(l4) >= 18:
        l4[0:4] = b'\0\0\0\0'
        l4[16:18] = b'\0\0'
    else:
        return None
    clave = (proto, ip[4:6], largo, bytes(l4))
    return clave, ip[8], ip[12:16], ip[16:20]
