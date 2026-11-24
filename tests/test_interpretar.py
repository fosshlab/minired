"""Vista OSI estilo Packet Tracer sobre capturas REALES grabadas en la VM (tests/grabar_capturas.py)."""

import pytest

from minired.captura.interpretar import CONFIGURACION, ESTADO, INFERIDO, OBSERVADO, Interprete

from utiles import escenario_grabado


def preparar(nombre):
    plan, obs, estado = escenario_grabado(nombre)
    return Interprete(plan, obs, estado), obs


def buscar(obs, nodo, contiene, emisor=None):
    for o in obs:
        if o.nodo == nodo and contiene in o.resumen['info'] and (emisor is None or o.emisor == emisor):
            return o
    raise AssertionError('no hay observación en %s con %r' % (nodo, contiene))


def textos(v):
    return [(d['fuente'], d['texto']) for d in v['decisiones']]


def tiene(v, fuente, fragmento):
    assert any(f == fuente and fragmento in t for f, t in textos(v)), (fragmento, textos(v))


def test_switch_inunda_el_arp_y_reenvia_el_eco_solo_a_su_destino():
    it, obs = preparar('lan_3pc')
    arp = buscar(obs, 'sw', '¿Quién tiene 10.0.0.2?')
    v = it.visita(arp.id)
    assert v['resultado'] == 'inundado' and v['nombre'] == 'xbs' and v['desde_nombre'] == 'xb1'
    tiene(v, INFERIDO, 'Aprende la MAC de origen: 02:00:00:00:02:00 está detrás del puerto xbs-eth1')
    tiene(v, INFERIDO, 'La MAC destino es broadcast: la inunda')
    tiene(v, OBSERVADO, 'Se observó salir por: ')
    assert sorted(s['hacia_nombre'] for s in v['salidas']) == ['xb2', 'xb3']
    assert [c['capa'] for c in v['entrada']] == [2, 2, 1]                # ARP y Ethernet en la capa 2
    assert v['origen']['nombre'] == 'xb1'
    tiene(v['origen'], OBSERVADO, 'Necesita la MAC de 10.0.0.2: pregunta por ARP')

    eco = buscar(obs, 'sw', 'Echo request')
    v = it.visita(eco.id)
    assert v['resultado'] == 'reenviado' and [s['hacia_nombre'] for s in v['salidas']] == ['xb2']
    tiene(v, INFERIDO, 'está en su tabla MAC, asociada a xbs-eth2: la reenvía solo por ese puerto')
    assert [c['capa'] for c in v['entrada']] == [3, 2, 1]
    tiene(v['origen'], INFERIDO, '10.0.0.2 está en su misma red (10.0.0.0/24)')

    # La PC que no es destino ignora la solicitud ARP; la destino responde (paquete observado).
    tiene(it.visita(buscar(obs, 'pc3', '¿Quién tiene').id), OBSERVADO, 'que no es su IP: ignora')
    v = it.visita(buscar(obs, 'pc2', '¿Quién tiene').id)
    assert v['resultado'] == 'respondido'
    tiene(v, OBSERVADO, 'Preguntan por su IP 10.0.0.2')
    v = it.visita(buscar(obs, 'pc2', 'Echo request').id)
    assert v['resultado'] == 'respondido'
    tiene(v, OBSERVADO, 'responde con una respuesta de eco (paquete')


def test_troncal_y_router_on_a_stick():
    it, obs = preparar('vlan_intervlan')
    ida = buscar(obs, 'sa', '10.10.0.1 → 10.20.0.1 Echo request', emisor='v1')
    v = it.visita(ida.id)
    tiene(v, CONFIGURACION, 'puerto de acceso de la VLAN 10')
    tiene(v, CONFIGURACION, 'Sale por vsa-eth4, que es troncal: agrega la etiqueta 802.1Q de la VLAN 10')
    en_router = buscar(obs, 'r', '10.10.0.1 → 10.20.0.1 Echo request')
    v = it.visita(en_router.id)
    assert v['resultado'] == 'reenviado'
    tiene(v, OBSERVADO, 'subinterfaz vr-eth0.10')
    tiene(v, ESTADO, 'coincide 10.20.0.0/24, entrega directa, por vr-eth0.20')
    tiene(v, OBSERVADO, 'Baja el TTL: 64 → 63')
    tiene(v, OBSERVADO, 'vr-eth0.20 (subinterfaz: etiqueta 802.1Q VLAN 20)')
    vuelta = buscar(obs, 'sa', 'Echo request', emisor='r')
    v = it.visita(vuelta.id)
    tiene(v, OBSERVADO, 'troncal con etiqueta 802.1Q de la VLAN 20')
    tiene(v, CONFIGURACION, 'puerto de acceso de la VLAN 20: quita la etiqueta')
    # v4 (VLAN 20) pregunta por 10.10.0.1: el ARP nunca llega a v1 ni a v2.
    arp_v4 = [o for o in obs if o.resumen.get('arp', {}).get('spa') == '10.10.0.4']
    assert arp_v4 and not any(o.nodo in ('v1', 'v2') for o in arp_v4)
    tiene(it.visita(next(o for o in arp_v4 if o.nodo == 'r').id), OBSERVADO, 'que no es su IP')


def test_nat_y_acl():
    it, obs = preparar('nat_acl')
    v = it.visita(buscar(obs, 'r', '10.40.0.1 → 203.0.113.10 Echo request').id)
    assert v['resultado'] == 'traducido'
    tiene(v, CONFIGURACION, 'permite el paquete por la regla 2 (permitir ip)')
    tiene(v, OBSERVADO, 'NAT (PAT) traduce la IP de origen 10.40.0.1 → 203.0.113.1')
    tiene(v, OBSERVADO, 'No conocía la MAC de 203.0.113.10: preguntó por ARP')
    v = it.visita(buscar(obs, 'r', '203.0.113.10 → 203.0.113.1 Echo reply').id)
    assert v['resultado'] == 'traducido'
    tiene(v, OBSERVADO, 'respuesta a una conexión traducida por NAT')
    tiene(v, OBSERVADO, 'NAT deshace la traducción: la IP destino 203.0.113.1 → 10.40.0.1')
    tiene(v, ESTADO, 'Busca 10.40.0.1 en la tabla de rutas')
    v = it.visita(buscar(obs, 'r', '10.40.0.2 → 203.0.113.10 Echo request').id)
    assert v['resultado'] == 'descartado' and v['salidas'] == []
    tiene(v, CONFIGURACION, 'coincide con la regla 1 (denegar icmp desde 10.40.0.2/32): descarta')
    tiene(v, OBSERVADO, 'No se observó la salida')


def test_ospf_dos_routers_y_hellos():
    it, obs = preparar('ospf')
    v = it.visita(buscar(obs, 'r1', '10.61.0.1 → 10.62.0.1 Echo request').id)
    tiene(v, ESTADO, 'coincide 10.62.0.0/24 vía 10.60.0.2, por fr1-eth1 (aprendida por OSPF')
    tiene(v, OBSERVADO, 'Baja el TTL: 64 → 63')
    hello = next(o for o in obs if o.resumen['protocolo'] == 'ospf')
    v = it.visita(hello.id)
    assert v['resultado'] == 'entregado'
    tiene(v, CONFIGURACION, 'lo procesa ospfd (FRR) y no se reenvía')
    tiene(v['origen'], CONFIGURACION, 'Hello cada 10 s')


def test_dhcp_dora_dns_y_http():
    it, obs = preparar('dhcp_dns_http')
    discover = [o for o in obs if o.resumen.get('dhcp', {}).get('tipo') == 1]
    v = it.visita(next(o for o in discover if o.nodo == 'sa').id)
    assert v['resultado'] == 'inundado'
    tiene(v['origen'], OBSERVADO, 'todavía no tiene IP: envía DISCOVER desde 0.0.0.0 a 255.255.255.255')
    v = it.visita(next(o for o in discover if o.nodo == 'srva').id)
    assert v['resultado'] == 'respondido'
    tiene(v, OBSERVADO, 'dnsmasq (servidor DHCP) recibe el DISCOVER y contesta con OFFER')
    v = it.visita(next(o for o in discover if o.nodo == 'ca2').id)
    assert v['resultado'] == 'descartado'
    tiene(v, CONFIGURACION, 'No es servidor DHCP')
    ack = next(o for o in obs if o.resumen.get('dhcp', {}).get('tipo') == 5 and o.nodo == 'ca')
    tiene(it.visita(ack.id), INFERIDO, 'configura 10.30.0.')
    consulta = next(o for o in obs if o.resumen['protocolo'] == 'dns' and o.nodo == 'srva')
    v = it.visita(consulta.id)
    assert v['entrada'][0] == {'capa': 7, 'nombre': 'DNS', 'texto': 'consulta A web.lab'}
    tiene(v, OBSERVADO, 'dnsmasq busca web.lab en sus registros y responde')
    http = next(o for o in obs if o.resumen['protocolo'] == 'http' and o.nodo == 'srva')
    tiene(it.visita(http.id), OBSERVADO, 'El servidor HTTP recibe "GET / HTTP/1.1"')


@pytest.mark.parametrize('nombre', ['lan_3pc', 'vlan_intervlan', 'nat_acl', 'ospf', 'dhcp_dns_http'])
def test_toda_observacion_tiene_vista_osi(nombre):
    it, obs = preparar(nombre)
    for o in obs:
        v = it.visita(o.id)
        assert v['entrada'][-1]['capa'] == 1 and v['decisiones'], o.id
        assert all(d['fuente'] in (OBSERVADO, CONFIGURACION, ESTADO, INFERIDO) for d in v['decisiones'])
        # Nunca se inventa un paquete: toda salida es una observación real.
        assert all(s['obs'] in it.por_id for s in v['salidas'])
