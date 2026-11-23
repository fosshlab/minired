import pytest
from pydantic import ValidationError

from minired.modelo.a_mininet import planificar
from minired.modelo.topologia import Lab

from utiles import lab_3pc


def lab(nodos, enlaces=()):
    return Lab.model_validate({'version': 1, 'nodos': nodos, 'enlaces': list(enlaces)})


def pc(id_, nombre, ip=None, gw=None):
    d = {'id': id_, 'tipo': 'pc', 'nombre': nombre}
    if ip:
        d['interfaces'] = [{'puerto': 0, 'ip': ip}]
    if gw:
        d['gateway'] = gw
    return d


def sw(id_, nombre):
    return {'id': id_, 'tipo': 'switch', 'nombre': nombre}


def en(id_, a, pa, b, pb):
    return {'id': id_, 'a': {'nodo': a, 'puerto': pa}, 'b': {'nodo': b, 'puerto': pb}}


def test_lab_valido_y_plan():
    plan = planificar(lab_3pc(('pc1', 'pc2', 'pc3'), 's1'))
    assert plan.enlaces['e2'][0].intf == 'pc2-eth0'
    assert plan.enlaces['e2'][1].intf == 's1-eth2'
    assert plan.por_intf['s1-eth3'].enlace == 'e3'
    assert plan.extremo_opuesto('e1', 'b').intf == 'pc1-eth0'
    assert plan.dpids == {'sw': '0000000000000001'}
    assert plan.enlaces['e1'][0].ip == '10.0.0.1/24'


@pytest.mark.parametrize('nombre', ['pc1;reboot', 'PC1', '1pc', 'pc-1', 'nombremuylargo', '', 'pc 1',
                                    '$(id)'])
def test_nombres_invalidos(nombre):
    with pytest.raises(ValidationError):
        lab([pc('n1', nombre)])


@pytest.mark.parametrize('ip', ['10.0.0.1/24;id', '10.0.0.1', '10.0.0.0/24', '10.0.0.255/24',
                                '300.0.0.1/24', '127.0.0.1/8', 'fe80::1/64', '10.0.0.1/24 '])
def test_ip_invalidas(ip):
    with pytest.raises(ValidationError):
        lab([pc('n1', 'pc1', ip)])


def test_gateway():
    lab([pc('n1', 'pc1', '10.0.0.1/24', '10.0.0.254')])
    for gw in ['10.0.1.254', '10.0.0.1', '10.0.0.254; id']:
        with pytest.raises(ValidationError):
            lab([pc('n1', 'pc1', '10.0.0.1/24', gw)])
    with pytest.raises(ValidationError):
        lab([pc('n1', 'pc1', None, '10.0.0.254')])


def test_nombres_e_ids_repetidos():
    with pytest.raises(ValidationError, match='nombre repetido'):
        lab([pc('n1', 'pc1'), pc('n2', 'pc1')])
    with pytest.raises(ValidationError, match='id de nodo repetido'):
        lab([pc('n1', 'pc1'), pc('n1', 'pc2')])


def test_puertos():
    with pytest.raises(ValidationError, match='no tiene el puerto'):
        lab([pc('n1', 'pc1'), sw('s', 's1')], [en('e1', 'n1', 1, 's', 1)])
    with pytest.raises(ValidationError, match='no tiene el puerto'):
        lab([pc('n1', 'pc1'), sw('s', 's1')], [en('e1', 'n1', 0, 's', 0)])
    with pytest.raises(ValidationError, match='dos veces'):
        lab([pc('n1', 'pc1'), pc('n2', 'pc2'), sw('s', 's1')],
            [en('e1', 'n1', 0, 's', 1), en('e2', 'n2', 0, 's', 1)])
    with pytest.raises(ValidationError, match='inexistente'):
        lab([pc('n1', 'pc1')], [en('e1', 'n1', 0, 'zz', 1)])
    with pytest.raises(ValidationError, match='consigo mismo'):
        lab([sw('s', 's1')], [en('e1', 's', 1, 's', 2)])


def test_bucle_de_switches():
    sws = [sw('a', 'sa'), sw('b', 'sb'), sw('c', 'sc')]
    lab(sws, [en('e1', 'a', 1, 'b', 1), en('e2', 'b', 2, 'c', 1)])
    with pytest.raises(ValidationError, match='bucle'):
        lab(sws, [en('e1', 'a', 1, 'b', 1), en('e2', 'b', 2, 'c', 1), en('e3', 'c', 2, 'a', 2)])


def test_router_redes_superpuestas_y_switch_sin_ip():
    r = {'id': 'r', 'tipo': 'router', 'nombre': 'r1',
         'interfaces': [{'puerto': 0, 'ip': '10.0.0.1/24'}, {'puerto': 1, 'ip': '10.0.0.2/16'}]}
    with pytest.raises(ValidationError, match='superpuestas'):
        lab([r])
    s = {'id': 's', 'tipo': 'switch', 'nombre': 's1', 'interfaces': [{'puerto': 1, 'ip': '10.0.0.1/24'}]}
    with pytest.raises(ValidationError, match='switch'):
        lab([s])


def test_campos_extra_rechazados():
    with pytest.raises(ValidationError):
        Lab.model_validate({'version': 1, 'nodos': [dict(pc('n1', 'pc1'), cmd='id')]})


# --- etapa 3 -----------------------------------------------------------------

from escenarios import lab_nat_acl, lab_ospf, lab_servicios, lab_vlan  # noqa: E402
from minired.modelo.topologia import ips_nodo  # noqa: E402


@pytest.mark.parametrize('fabrica', [lab_vlan, lab_ospf, lab_servicios, lab_nat_acl])
def test_escenarios_etapa3_validos(fabrica):
    lab_ = fabrica()
    assert planificar(lab_).enlaces


def test_subinterfaces_en_ips_del_router():
    r = lab_vlan().nodo('r')
    assert [(n, str(ip)) for n, ip in ips_nodo(r)] == [
        ('vr-eth0.10', '10.10.0.254/24'), ('vr-eth0.20', '10.20.0.254/24')]


def _errores(nodos, enlaces=()):
    with pytest.raises(ValidationError) as e:
        lab(nodos, enlaces)
    return str(e.value)


def router(id_, nombre, interfaces, **extra):
    return {'id': id_, 'tipo': 'router', 'nombre': nombre, 'interfaces': interfaces, **extra}


@pytest.mark.parametrize('nodos,esperado', [
    ([dict(pc('a', 'pc1', '10.0.0.1/24'), interfaces=[{'puerto': 0, 'ip': '10.0.0.1/24', 'vlan': 10}])],
     'se configuran en puertos de switch'),
    ([dict(sw('s', 's1'), interfaces=[{'puerto': 1, 'vlan': 10, 'troncal': [10]}])], 'no las dos cosas'),
    ([dict(sw('s', 's1'), interfaces=[{'puerto': 1, 'troncal': [10, 10]}])], 'VLAN repetida'),
    ([dict(sw('s', 's1'), interfaces=[{'puerto': 1, 'troncal': [5000]}])], 'de 1 a 4094'),
    ([dict(sw('s', 's1'), interfaces=[{'puerto': 1, 'troncal': []}])], 'al menos una VLAN'),
    ([router('r', 'r1', [{'puerto': 0, 'ip': '10.0.0.1/24'}], ospf=True)], 'OSPF necesita FRR'),
    ([router('r', 'r1', [{'puerto': 0, 'ip': '10.0.0.1/24'}],
             rutas=[{'destino': '10.9.0.0/16', 'via': '10.1.0.1'}])], 'ninguna red conectada'),
    ([router('r', 'r1', [{'puerto': 0, 'ip': '10.0.0.1/24'}],
             rutas=[{'destino': '10.9.0.1/16', 'via': '10.0.0.2'}])], 'not a valid IPv4 network'),
    ([router('r', 'router12', [{'puerto': 0, 'subinterfaces': [{'vlan': 4000, 'ip': '10.0.0.1/24'}]}])],
     'supera 15 caracteres'),
    ([router('r', 'r1', [{'puerto': 0, 'subinterfaces': [{'vlan': 10, 'ip': '10.0.0.1/24'},
                                                          {'vlan': 20, 'ip': '10.0.0.2/25'}]}])],
     'redes superpuestas'),
    ([router('r', 'r1', [{'puerto': 0, 'ip': '10.0.0.1/24', 'nat': 'interior'}])],
     'una interfaz interior y una exterior'),
    ([router('r', 'r1', [{'puerto': 0, 'ip': '10.0.0.1/24', 'acl_entrada': [
        {'accion': 'denegar', 'protocolo': 'icmp', 'puerto': 80}]}])], 'solo vale para tcp o udp'),
    ([dict(pc('a', 'pc1', '10.0.0.1/24'), dhcp=True)], 'dejalos vacíos'),
    ([dict(pc('a', 'pc1', '10.0.0.1/24'), servicios={'http': True})], 'van en un servidor'),
    ([{'id': 's', 'tipo': 'servidor', 'nombre': 'srv', 'servicios': {'http': True}}], 'IP fija'),
    ([{'id': 's', 'tipo': 'servidor', 'nombre': 'srv', 'interfaces': [{'puerto': 0, 'ip': '10.0.0.1/24'}],
       'servicios': {'dhcp': {'desde': '10.0.1.10', 'hasta': '10.0.1.20'}}}], 'en la red del servidor'),
    ([{'id': 's', 'tipo': 'servidor', 'nombre': 'srv', 'interfaces': [{'puerto': 0, 'ip': '10.0.0.15/24'}],
       'servicios': {'dhcp': {'desde': '10.0.0.10', 'hasta': '10.0.0.20'}}}], 'dentro del rango'),
    ([{'id': 's', 'tipo': 'servidor', 'nombre': 'srv', 'interfaces': [{'puerto': 0, 'ip': '10.0.0.1/24'}],
       'servicios': {'dns': [{'nombre': 'Web;rm', 'ip': '10.0.0.1'}]}}], 'should match pattern'),
])
def test_errores_etapa3(nodos, esperado):
    assert esperado in _errores(nodos)
