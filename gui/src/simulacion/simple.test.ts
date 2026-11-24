import { describe, expect, it } from 'vitest';
import type { Lab, Observacion, Resumen } from '../api/tipos';
import { ejemplo3Pc } from '../estado/ejemplos';
import { compilarFiltro, ErrorFiltro } from './filtroWireshark';
import { esRuido, etiquetaSimple, macDe, nombresDe } from './simple';

let n = 0;
function obs(resumen: Partial<Resumen>, extra: Partial<Observacion> = {}): Observacion {
  n += 1;
  return {
    id: `o${n}`, seq: n, ts_ns: '1', t_us: n, enlace: 'e1', hacia: 'b', nodo: 'n1', emisor: 'n2', intf: 's1-eth1',
    largo: 60, pcap: { archivo: 'a', n }, paquete: `p${n}`, padre: null, confianza: 'alta', profundidad: 0,
    resumen: { capas: [], protocolo: '', info: 'info cruda', ...resumen } as Resumen, ...extra,
  };
}

// Valores tomados de las capturas reales de tests/datos (lan_3pc, dhcp_dns_http, ospf).
const BC = 'ff:ff:ff:ff:ff:ff';
const arpPregunta = obs({ capas: ['eth', 'arp'], eth: { src: '02:00:00:00:02:00', dst: BC, tipo: '0x0806' },
  arp: { op: 1, sha: '02:00:00:00:02:00', spa: '10.0.0.1', tha: '00:00:00:00:00:00', tpa: '10.0.0.2' } });
const arpRespuesta = obs({ capas: ['eth', 'arp'], eth: { src: '02:00:00:00:03:00', dst: '02:00:00:00:02:00', tipo: '0x0806' },
  arp: { op: 2, sha: '02:00:00:00:03:00', spa: '10.0.0.2', tha: '02:00:00:00:02:00', tpa: '10.0.0.1' } });
const arpVerificacion = obs({ capas: ['eth', 'arp'], eth: { src: '02:00:00:00:03:00', dst: '02:00:00:00:02:00', tipo: '0x0806' },
  arp: { op: 1, sha: '02:00:00:00:03:00', spa: '10.0.0.2', tha: '00:00:00:00:00:00', tpa: '10.0.0.1' } });
const eco = obs({ capas: ['eth', 'ip', 'icmp'], eth: { src: '02:00:00:00:02:00', dst: '02:00:00:00:03:00', tipo: '0x0800' },
  ip: { src: '10.0.0.1', dst: '10.0.0.2', ttl: 64, proto: 1, id: 1 }, icmp: { tipo: 8, codigo: 0, ident: 1, seq: 1 } }, { largo: 98 });
const hello = obs({ capas: ['eth', 'ip', 'ospf'], ip: { src: '10.60.0.1', dst: '224.0.0.5', ttl: 1, proto: 89, id: 2 }, ospf: { tipo: 1 } });
const conVlan = obs({ capas: ['eth', 'vlan', 'ip', 'icmp'], vlan: { id: 20, pcp: 0 },
  ip: { src: '10.10.0.1', dst: '10.20.0.1', ttl: 63, proto: 1, id: 3 }, icmp: { tipo: 8, codigo: 0 } });
const http = obs({ capas: ['eth', 'ip', 'tcp', 'http'], ip: { src: '10.30.0.107', dst: '10.30.0.1', ttl: 64, proto: 6, id: 4 },
  tcp: { sport: 41000, dport: 80, banderas: 'PA' }, http: { linea: 'GET / HTTP/1.1' } });

describe('modo simple', () => {
  const nombres = nombresDe(ejemplo3Pc);

  it('MAC deterministas iguales a las del backend', () => {
    expect(macDe(2, 0)).toBe('02:00:00:00:02:00');
    expect(nombres.porMac.get('02:00:00:00:02:00')).toBe('pc1');     // n2 = pc1, segundo nodo
    expect(nombres.porIp.get('10.0.0.3')).toBe('pc3');
  });

  it('etiquetas pedagógicas con nombres de equipos', () => {
    expect(etiquetaSimple(arpPregunta, nombres)).toBe('ARP: ¿quién tiene 10.0.0.2? (pregunta pc1)');
    expect(etiquetaSimple(arpRespuesta, nombres)).toBe('ARP: 10.0.0.2 está en pc2');
    expect(etiquetaSimple(eco, nombres)).toBe('Eco ICMP pc1 → pc2');
    expect(etiquetaSimple(http, nombres)).toBe('HTTP GET /');
  });

  it('DHCP: el nombre del cliente sale de su MAC, y la IP entregada se aprende del ACK', () => {
    const lab: Lab = { version: 1, nodos: [
      { id: 's', tipo: 'switch', nombre: 'dsa', x: 0, y: 0, interfaces: [] },
      { id: 'c', tipo: 'pc', nombre: 'dc1', x: 0, y: 0, interfaces: [], dhcp: true },
      { id: 'v', tipo: 'servidor', nombre: 'da1', x: 0, y: 0, interfaces: [{ puerto: 0, ip: '10.30.0.1/24' }] },
    ], enlaces: [{ id: 'e1', a: { nodo: 'c', puerto: 0 }, b: { nodo: 's', puerto: 1 } },
      { id: 'e2', a: { nodo: 'v', puerto: 0 }, b: { nodo: 's', puerto: 2 } }] };
    const discover = obs({ capas: ['eth', 'ip', 'udp', 'dhcp'], ip: { src: '0.0.0.0', dst: '255.255.255.255', ttl: 64, proto: 17, id: 0 },
      dhcp: { tipo: 1, xid: '0x1', yiaddr: '0.0.0.0', chaddr: '02:00:00:00:02:00' } });
    const ack = obs({ capas: ['eth', 'ip', 'udp', 'dhcp'], ip: { src: '10.30.0.1', dst: '10.30.0.107', ttl: 64, proto: 17, id: 0 },
      dhcp: { tipo: 5, xid: '0x1', yiaddr: '10.30.0.107', chaddr: '02:00:00:00:02:00' } });
    const nom = nombresDe(lab, [discover, ack]);
    expect(etiquetaSimple(discover, nom)).toBe('DHCP Discover: dc1 busca un servidor');
    expect(etiquetaSimple(ack, nom)).toBe('DHCP ACK: da1 confirma la IP 10.30.0.107');
    expect(nom.porIp.get('10.30.0.107')).toBe('dc1');
  });

  it('el tráfico de fondo se reconoce (Hello OSPF, verificación ARP unicast)', () => {
    expect(esRuido(hello)).toBe('Hello de OSPF (cada 10 s)');
    expect(esRuido(arpVerificacion)).toBe('verificación ARP de Linux');
    expect(esRuido(arpPregunta)).toBeNull();
    expect(esRuido(eco)).toBeNull();
  });
});

describe('filtro estilo Wireshark (modo avanzado)', () => {
  const todas = [arpPregunta, arpRespuesta, eco, hello, conVlan, http];
  const ids = (f: string) => todas.filter(compilarFiltro(f)).map((o) => o.id);

  it('protocolos, campos y lógica', () => {
    expect(ids('')).toHaveLength(6);
    expect(ids('arp')).toEqual([arpPregunta.id, arpRespuesta.id]);
    expect(ids('icmp && !vlan')).toEqual([eco.id]);
    expect(ids('ip.addr == 10.0.0.2')).toEqual([eco.id]);
    expect(ids('ip.src == 10.10.0.1 or ospf')).toEqual([hello.id, conVlan.id]);
    expect(ids('vlan.id == 20')).toEqual([conVlan.id]);
    expect(ids('tcp.port == 80')).toEqual([http.id]);
    expect(ids('(arp || http) and not eth.dst == ff:ff:ff:ff:ff:ff')).toEqual([arpRespuesta.id, http.id]);
    expect(ids('frame.len > 90')).toEqual([eco.id]);
    expect(ids('ip.addr != 10.0.0.1')).toEqual([hello.id, conVlan.id, http.id]);
  });

  it('errores claros en español', () => {
    expect(() => compilarFiltro('ip.adr == 1')).toThrow(ErrorFiltro);
    expect(() => compilarFiltro('ip.adr == 1')).toThrow('campo desconocido: ip.adr');
    expect(() => compilarFiltro('(arp')).toThrow('falta cerrar un paréntesis');
    expect(() => compilarFiltro('icmp &&')).toThrow('termina antes de tiempo');
    expect(() => compilarFiltro('frame.len > muchos')).not.toThrow();
    expect(() => todas.filter(compilarFiltro('frame.len > muchos'))).toThrow('no es un número');
  });
});
