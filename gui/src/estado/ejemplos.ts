import type { Lab } from '../api/tipos';

// Laboratorios de ejemplo. Los de la etapa 3 son los mismos que validan las pruebas con root
// (tests/escenarios.py), con posiciones para el dibujo.

export const ejemplo3Pc: Lab = {
  version: 1,
  nodos: [
    { id: 'n1', tipo: 'switch', nombre: 's1', x: 300, y: 120, interfaces: [] },
    { id: 'n2', tipo: 'pc', nombre: 'pc1', x: 80, y: 300, interfaces: [{ puerto: 0, ip: '10.0.0.1/24' }] },
    { id: 'n3', tipo: 'pc', nombre: 'pc2', x: 300, y: 330, interfaces: [{ puerto: 0, ip: '10.0.0.2/24' }] },
    { id: 'n4', tipo: 'pc', nombre: 'pc3', x: 520, y: 300, interfaces: [{ puerto: 0, ip: '10.0.0.3/24' }] },
  ],
  enlaces: [
    { id: 'e1', a: { nodo: 'n2', puerto: 0 }, b: { nodo: 'n1', puerto: 1 } },
    { id: 'e2', a: { nodo: 'n3', puerto: 0 }, b: { nodo: 'n1', puerto: 2 } },
    { id: 'e3', a: { nodo: 'n4', puerto: 0 }, b: { nodo: 'n1', puerto: 3 } },
  ],
};

const en = (id: string, a: string, pa: number, b: string, pb: number) =>
  ({ id, a: { nodo: a, puerto: pa }, b: { nodo: b, puerto: pb } });

const vlan: Lab = {
  version: 1,
  nodos: [
    { id: 'sa', tipo: 'switch', nombre: 'vsa', x: 220, y: 210, interfaces: [
      { puerto: 1, vlan: 10 }, { puerto: 2, vlan: 20 }, { puerto: 3, troncal: [10, 20] }, { puerto: 4, troncal: [10, 20] }] },
    { id: 'sb', tipo: 'switch', nombre: 'vsb', x: 520, y: 200, interfaces: [
      { puerto: 1, vlan: 10 }, { puerto: 2, vlan: 20 }, { puerto: 3, troncal: [10, 20] }] },
    { id: 'r', tipo: 'router', nombre: 'vr', x: 220, y: 60, interfaces: [
      { puerto: 0, subinterfaces: [{ vlan: 10, ip: '10.10.0.254/24' }, { vlan: 20, ip: '10.20.0.254/24' }] }] },
    { id: 'v1', tipo: 'pc', nombre: 'v1', x: 100, y: 360, interfaces: [{ puerto: 0, ip: '10.10.0.1/24' }], gateway: '10.10.0.254' },
    { id: 'v3', tipo: 'pc', nombre: 'v3', x: 300, y: 360, interfaces: [{ puerto: 0, ip: '10.20.0.1/24' }], gateway: '10.20.0.254' },
    { id: 'v2', tipo: 'pc', nombre: 'v2', x: 440, y: 360, interfaces: [{ puerto: 0, ip: '10.10.0.2/24' }], gateway: '10.10.0.254' },
    { id: 'v4', tipo: 'pc', nombre: 'v4', x: 640, y: 360, interfaces: [{ puerto: 0, ip: '10.10.0.4/24' }] },
  ],
  enlaces: [en('e1', 'v1', 0, 'sa', 1), en('e2', 'v3', 0, 'sa', 2), en('e3', 'sa', 3, 'sb', 3),
    en('e4', 'r', 0, 'sa', 4), en('e5', 'v2', 0, 'sb', 1), en('e6', 'v4', 0, 'sb', 2)],
};

const ospf: Lab = {
  version: 1,
  nodos: [
    { id: 'f1', tipo: 'pc', nombre: 'f1', x: 40, y: 220, interfaces: [{ puerto: 0, ip: '10.61.0.1/24' }], gateway: '10.61.0.254' },
    { id: 'r1', tipo: 'router', nombre: 'fr1', x: 230, y: 120, frr: true, ospf: true, interfaces: [
      { puerto: 0, ip: '10.61.0.254/24' }, { puerto: 1, ip: '10.60.0.1/30' }] },
    { id: 'r2', tipo: 'router', nombre: 'fr2', x: 470, y: 120, frr: true, ospf: true, interfaces: [
      { puerto: 0, ip: '10.62.0.254/24' }, { puerto: 1, ip: '10.60.0.2/30' }] },
    { id: 'f2', tipo: 'pc', nombre: 'f2', x: 660, y: 220, interfaces: [{ puerto: 0, ip: '10.62.0.1/24' }], gateway: '10.62.0.254' },
  ],
  enlaces: [en('e1', 'f1', 0, 'r1', 0), en('e2', 'r1', 1, 'r2', 1), en('e3', 'r2', 0, 'f2', 0)],
};

const servicios: Lab = {
  version: 1,
  nodos: [
    { id: 'sa', tipo: 'switch', nombre: 'dsa', x: 260, y: 160, interfaces: [] },
    { id: 'srva', tipo: 'servidor', nombre: 'da1', x: 260, y: 40, dns: '10.30.0.1',
      interfaces: [{ puerto: 0, ip: '10.30.0.1/24' }],
      servicios: { dhcp: { desde: '10.30.0.100', hasta: '10.30.0.150', gateway: '10.30.0.254', dns: '10.30.0.1' },
        dns: [{ nombre: 'web.lab', ip: '10.30.0.1' }], http: true } },
    { id: 'ca', tipo: 'pc', nombre: 'dc1', x: 120, y: 320, interfaces: [], dhcp: true },
    { id: 'ca2', tipo: 'pc', nombre: 'dc2', x: 400, y: 320, interfaces: [], dhcp: true },
    { id: 'sb', tipo: 'switch', nombre: 'dsb', x: 620, y: 160, interfaces: [] },
    { id: 'srvb', tipo: 'servidor', nombre: 'db1', x: 620, y: 40, interfaces: [{ puerto: 0, ip: '10.31.0.1/24' }],
      servicios: { dhcp: { desde: '10.31.0.200', hasta: '10.31.0.210' } } },
    { id: 'cb', tipo: 'pc', nombre: 'dc3', x: 620, y: 320, interfaces: [], dhcp: true },
  ],
  enlaces: [en('e1', 'srva', 0, 'sa', 1), en('e2', 'ca', 0, 'sa', 2), en('e3', 'ca2', 0, 'sa', 3),
    en('e4', 'srvb', 0, 'sb', 1), en('e5', 'cb', 0, 'sb', 2)],
};

const natAcl: Lab = {
  version: 1,
  nodos: [
    { id: 'n1', tipo: 'pc', nombre: 'n1', x: 40, y: 330, interfaces: [{ puerto: 0, ip: '10.40.0.1/24' }], gateway: '10.40.0.254' },
    { id: 'n2', tipo: 'pc', nombre: 'n2', x: 260, y: 330, interfaces: [{ puerto: 0, ip: '10.40.0.2/24' }], gateway: '10.40.0.254' },
    { id: 'sw', tipo: 'switch', nombre: 'ns', x: 150, y: 180, interfaces: [] },
    { id: 'r', tipo: 'router', nombre: 'nr', x: 380, y: 180,
      rutas: [{ destino: '198.51.100.0/24', via: '203.0.113.10' }],
      interfaces: [
        { puerto: 0, ip: '10.40.0.254/24', nat: 'interior', acl_entrada: [
          { accion: 'denegar', protocolo: 'icmp', origen: '10.40.0.2/32' },
          { accion: 'permitir', protocolo: 'ip' }] },
        { puerto: 1, ip: '203.0.113.1/24', nat: 'exterior' }] },
    { id: 'web', tipo: 'servidor', nombre: 'nsrv', x: 620, y: 180, interfaces: [{ puerto: 0, ip: '203.0.113.10/24' }],
      servicios: { http: true } },
  ],
  enlaces: [en('e1', 'n1', 0, 'sw', 1), en('e2', 'n2', 0, 'sw', 2), en('e3', 'r', 0, 'sw', 3), en('e4', 'r', 1, 'web', 0)],
};

export const EJEMPLOS: { titulo: string; lab: Lab }[] = [
  { titulo: '3 PC + switch (ARP e ICMP)', lab: ejemplo3Pc },
  { titulo: 'VLAN, troncal e inter-VLAN', lab: vlan },
  { titulo: 'Dos routers FRR con OSPF', lab: ospf },
  { titulo: 'DHCP, DNS y HTTP', lab: servicios },
  { titulo: 'NAT y ACL', lab: natAcl },
];
