import type { Lab, Observacion } from '../api/tipos';

// Modo SIMPLE: el mismo tráfico real, presentado como en Packet Tracer (sin inventar paquetes).
// - Cada observación es un salto: con tcpdump -Q in, cada frame aparece una sola vez,
//   en el extremo que lo recibe ("último dispositivo" → "en dispositivo").
// - El tráfico de fondo se oculta por defecto (se puede mostrar).
// - Las etiquetas hablan en términos del curso y con nombres de equipos.

export type Vista = 'simple' | 'avanzado';

// MAC deterministas del backend (minired/modelo/a_mininet.py, mac_de): 02:00:00:00:<nodo>:<puerto>.
export function macDe(indiceNodo: number, puerto: number) {
  const h = (n: number) => n.toString(16).padStart(2, '0');
  return `02:00:00:00:${h(indiceNodo)}:${h(puerto)}`;
}

export interface Nombres {
  porIp: Map<string, string>;
  porMac: Map<string, string>;
}

// IP y MAC → nombre de equipo, del laboratorio y de lo que entregó el DHCP en la captura.
export function nombresDe(lab: Lab, observaciones: Observacion[] = []): Nombres {
  const porIp = new Map<string, string>();
  const porMac = new Map<string, string>();
  lab.nodos.forEach((n, i) => {
    for (const intf of n.interfaces) {
      if (intf.ip) porIp.set(intf.ip.split('/')[0], n.nombre);
      for (const s of intf.subinterfaces ?? []) porIp.set(s.ip.split('/')[0], n.nombre);
    }
    for (const e of lab.enlaces) {
      for (const ext of [e.a, e.b]) if (ext.nodo === n.id) porMac.set(macDe(i + 1, ext.puerto), n.nombre);
    }
  });
  for (const o of observaciones) {
    const d = o.resumen.dhcp;
    if (d && d.tipo === 5 && d.yiaddr !== '0.0.0.0' && porMac.has(d.chaddr)) porIp.set(d.yiaddr, porMac.get(d.chaddr)!);
  }
  return { porIp, porMac };
}

// Tráfico de fondo: lo genera la red sola y distrae del ejercicio.
export function esRuido(o: Observacion): string | null {
  const r = o.resumen;
  if (r.ospf?.tipo === 1) return 'Hello de OSPF (cada 10 s)';
  if (r.arp && r.arp.op === 1 && r.eth && r.eth.dst !== 'ff:ff:ff:ff:ff:ff') return 'verificación ARP de Linux';
  if (r.capas.includes('ipv6')) return 'IPv6';
  return null;
}

const DHCP = ['', 'Discover', 'Offer', 'Request', 'Decline', 'ACK', 'NAK', 'Release', 'Inform'];
const DHCP_QUE: Record<number, string> = {
  1: 'busca un servidor', 2: 'ofrece una IP', 3: 'pide la IP ofrecida', 5: 'confirma la IP',
};

export function etiquetaSimple(o: Observacion, nombres: Nombres): string {
  const r = o.resumen;
  const n = (ip: string) => nombres.porIp.get(ip) ?? ip;
  if (r.arp) {
    return r.arp.op === 1 ? `ARP: ¿quién tiene ${r.arp.tpa}? (pregunta ${n(r.arp.spa)})`
      : `ARP: ${r.arp.spa} está en ${nombres.porMac.get(r.arp.sha) ?? r.arp.sha}`;
  }
  if (r.dhcp) {
    const t = r.dhcp.tipo ?? 0;
    const quien = t === 1 || t === 3 ? (nombres.porMac.get(r.dhcp.chaddr) ?? 'el cliente') : (r.ip ? n(r.ip.src) : 'el servidor');
    const ip = t === 2 || t === 5 ? ` ${r.dhcp.yiaddr}` : '';
    return `DHCP ${DHCP[t] ?? 'BOOTP'}: ${quien} ${DHCP_QUE[t] ?? ''}${ip}`.trim();
  }
  if (r.dns) return r.dns.respuesta ? `DNS: respuesta para ${r.dns.nombre ?? '?'}` : `DNS: ¿${r.dns.nombre ?? '?'}?`;
  if (r.http) return `HTTP ${r.http.linea.split(' ').slice(0, 2).join(' ')}`;
  if (r.ospf) return `OSPF ${['', 'Hello', 'Descripción de BD', 'Pedido de LS', 'Actualización de LS', 'Acuse de LS'][r.ospf.tipo] ?? ''} de ${n(r.ip!.src)}`.trim();
  if (r.icmp && r.ip) {
    const de = n(r.ip.src);
    const a = n(r.ip.dst);
    if (r.icmp.tipo === 8) return `Eco ICMP ${de} → ${a}`;
    if (r.icmp.tipo === 0) return `Respuesta de eco ${de} → ${a}`;
    if (r.icmp.tipo === 3) return `ICMP: destino inalcanzable (avisa ${de})`;
    if (r.icmp.tipo === 11) return `ICMP: TTL excedido (avisa ${de})`;
    return `ICMP tipo ${r.icmp.tipo} ${de} → ${a}`;
  }
  if (r.tcp && r.ip) {
    const b = r.tcp.banderas;
    const que = b === 'S' ? 'abre conexión (SYN)' : b.includes('S') ? 'acepta (SYN-ACK)' : b.includes('F') ? 'cierra (FIN)' : 'datos/ACK';
    return `TCP ${n(r.ip.src)} → ${n(r.ip.dst)}: ${que}`;
  }
  if (r.udp && r.ip) return `UDP ${n(r.ip.src)} → ${n(r.ip.dst)} puerto ${r.udp.dport}`;
  return r.info;
}
