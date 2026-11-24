import type { Observacion } from '../api/tipos';

// Un paso de la reproducción: los cruces de enlace de un mismo paquete lógico a la misma
// profundidad. Si un switch inunda, el paso tiene varias observaciones (ramas en paralelo).
// Una observación sin correlacionar es un paso propio: se dibuja sola, sin camino inventado.
export interface Paso {
  clave: string;
  paquete: string;
  profundidad: number;
  ts: bigint;
  obs: Observacion[];
}

export type Filtro = 'todos' | 'arp' | 'icmp' | 'ip' | 'dhcp' | 'dns' | 'http' | 'ospf' | 'otros';

export function pasaFiltro(o: Observacion, filtro: Filtro) {
  const capas = o.resumen.capas;
  switch (filtro) {
    case 'todos': return true;
    case 'arp': return capas.includes('arp');
    case 'icmp': return capas.includes('icmp');
    case 'ip': return capas.includes('ip');
    case 'dhcp': case 'dns': case 'http': case 'ospf': return capas.includes(filtro);
    case 'otros': return !capas.includes('arp') && !capas.includes('ip');
  }
}

export function construirPasos(observaciones: Observacion[], filtro: Filtro | ((o: Observacion) => boolean) = 'todos'): Paso[] {
  const visible = typeof filtro === 'function' ? filtro : (o: Observacion) => pasaFiltro(o, filtro);
  const grupos = new Map<string, Paso>();
  for (const o of observaciones) {
    if (!visible(o)) continue;
    const clave = `${o.paquete}/${o.profundidad}`;
    const ts = BigInt(o.ts_ns);
    let paso = grupos.get(clave);
    if (!paso) {
      paso = { clave, paquete: o.paquete, profundidad: o.profundidad, ts, obs: [] };
      grupos.set(clave, paso);
    }
    paso.obs.push(o);
    if (ts < paso.ts) paso.ts = ts;
  }
  return [...grupos.values()].sort((x, y) => (x.ts < y.ts ? -1 : x.ts > y.ts ? 1 : 0));
}

export function indicePasoDe(pasos: Paso[], obsId: string) {
  return pasos.findIndex((p) => p.obs.some((o) => o.id === obsId));
}

// Color por protocolo (también se usa en la lista de eventos).
export function colorProtocolo(o: Observacion) {
  const c = o.resumen.capas;
  if (c.includes('arp')) return '#d97706';
  if (c.includes('dhcp')) return '#be185d';
  if (c.includes('dns')) return '#0f766e';
  if (c.includes('http')) return '#15803d';
  if (c.includes('ospf')) return '#9333ea';
  if (c.includes('icmp')) return '#2563eb';
  if (c.includes('tcp')) return '#059669';
  if (c.includes('udp')) return '#7c3aed';
  if (c.includes('ip')) return '#0891b2';
  return '#6b7280';
}

export function etiquetaProtocolo(o: Observacion) {
  const c = o.resumen.capas;
  if (c.includes('arp')) return 'ARP';
  if (c.includes('dhcp')) return 'DHCP';
  if (c.includes('dns')) return 'DNS';
  if (c.includes('http')) return 'HTTP';
  if (c.includes('ospf')) return 'OSPF';
  if (c.includes('icmp')) return 'ICMP';
  if (c.includes('tcp')) return 'TCP';
  if (c.includes('udp')) return 'UDP';
  if (c.includes('ip')) return 'IPv4';
  if (c.includes('ipv6')) return 'IPv6';
  return 'ETH';
}
