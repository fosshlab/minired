"""Configuración generada para FRR, nftables, dnsmasq y udhcpc (sin root)."""

from escenarios import lab_nat_acl, lab_ospf, lab_servicios, lab_vlan

from minired.runtime import servicios as sv


def test_frr_ospf_punto_a_punto_y_pasivas():
    lab = lab_ospf()
    conf = sv.frr_conf(lab.nodo('r1'), lab)
    assert 'hostname fr1' in conf
    assert 'interface fr1-eth1\n ip address 10.60.0.1/30\n ip ospf network point-to-point\n!' in conf
    assert 'interface fr1-eth0\n ip address 10.61.0.254/24\n!' in conf
    assert ' network 10.61.0.0/24 area 0' in conf and ' network 10.60.0.0/30 area 0' in conf
    assert ' passive-interface fr1-eth0' in conf and 'passive-interface fr1-eth1' not in conf
    assert ' ospf router-id 10.60.0.1' in conf
    assert sv.daemons_frr(lab.nodo('r1')) == ['zebra', 'staticd', 'ospfd']


def test_frr_rutas_estaticas_y_subinterfaces():
    lab = lab_vlan()
    r = lab.nodo('r').model_copy(update={'frr': True, 'rutas': lab_nat_acl().nodo('r').rutas[:0]})
    conf = sv.frr_conf(r, lab)
    assert 'interface vr-eth0.10\n ip address 10.10.0.254/24' in conf
    assert 'router ospf' not in conf and sv.daemons_frr(r) == ['zebra', 'staticd']
    nat = lab_nat_acl()
    r2 = nat.nodo('r').model_copy(update={'frr': True})
    assert 'ip route 198.51.100.0/24 203.0.113.10' in sv.frr_conf(r2, nat)


def test_nft_acl_con_deny_implicito_y_nat():
    texto = sv.nft_ruleset(lab_nat_acl().nodo('r'))
    assert 'chain acl_entrada_eth0 {' in texto
    assert 'ip saddr 10.40.0.2/32 ip protocol icmp counter drop comment "regla 1"' in texto
    assert 'counter accept comment "regla 2"' in texto
    assert 'counter drop comment "deny any implícito"' in texto
    assert texto.count('iifname { "nr-eth0" } jump acl_entrada_eth0') == 2      # forward e input
    assert 'iifname { "nr-eth0" } oifname { "nr-eth1" } counter masquerade' in texto
    assert sv.necesita_nft(lab_nat_acl().nodo('r'))
    assert not sv.necesita_nft(lab_vlan().nodo('r'))


def test_nft_regla_con_puerto():
    from minired.modelo.topologia import ReglaACL
    regla = ReglaACL(accion='permitir', protocolo='tcp', destino='203.0.113.10/32', puerto=80)
    assert sv._regla(regla, 3) == ('ip daddr 203.0.113.10/32 ip protocol tcp tcp dport 80 counter accept '
                                   'comment "regla 3"')


def test_dnsmasq_dhcp_dns_y_sin_dns():
    lab = lab_servicios()
    a = sv.argv_dnsmasq(lab.nodo('srva'), 'da1-eth0', '/x')
    assert '--dhcp-range=10.30.0.100,10.30.0.150,255.255.255.0,1h' in a
    assert '--dhcp-option=3,10.30.0.254' in a and '--dhcp-option=6,10.30.0.1' in a
    assert '--host-record=web.lab,10.30.0.1' in a and '--port=0' not in a
    assert '--interface=da1-eth0' in a and '--bind-interfaces' in a and '--no-resolv' in a
    b = sv.argv_dnsmasq(lab.nodo('srvb'), 'db1-eth0', '/y')
    assert '--port=0' in b and '--dhcp-option=3' in b and '--dhcp-option=6' in b
    assert sv.necesita_dnsmasq(lab.nodo('srva')) and sv.necesita_dnsmasq(lab.nodo('srvb'))
    assert not sv.necesita_dnsmasq(lab_nat_acl().nodo('web'))


def test_guion_udhcpc_no_toca_el_resolv_del_sistema():
    assert '/etc/resolv.conf' not in sv.UDHCPC_SCRIPT.split('\n', 3)[3]
    assert '"$MINIRED_RESOLV"' in sv.UDHCPC_SCRIPT
    assert sv.argv_udhcpc('dc1-eth0', '/d')[:4] == ['busybox', 'udhcpc', '-i', 'dc1-eth0']
