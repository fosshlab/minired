import { describe, expect, it } from 'vitest';
import type { Observacion } from '../api/tipos';
import { construirPasos, indicePasoDe } from './reproductor';

let n = 0;
function obs(paquete: string, profundidad: number, ts: number, capas: string[], extra: Partial<Observacion> = {}): Observacion {
  n += 1;
  return {
    id: `o${n}`, seq: n, ts_ns: String(1795445199000000000n + BigInt(ts)), t_us: ts, enlace: 'e1', hacia: 'b',
    nodo: 'x', emisor: 'y', intf: 'i', largo: 42, pcap: { archivo: 'a', n: 1 },
    resumen: { capas, protocolo: capas[capas.length - 1], info: '' }, paquete, padre: null,
    confianza: 'alta', profundidad, ...extra,
  };
}

describe('construirPasos', () => {
  // Captura real (lan_3pc_ping): ARP inundado a 2 puertos, respuesta, eco y respuesta.
  const arp0 = obs('p1', 0, 100, ['eth', 'arp']);
  const arp1a = obs('p1', 1, 180, ['eth', 'arp'], { enlace: 'e2' });
  const arp1b = obs('p1', 1, 170, ['eth', 'arp'], { enlace: 'e3' });
  const rep0 = obs('p2', 0, 200, ['eth', 'arp']);
  const rep1 = obs('p2', 1, 250, ['eth', 'arp']);
  const eco0 = obs('p3', 0, 260, ['eth', 'ip', 'icmp']);
  const eco1 = obs('p3', 1, 300, ['eth', 'ip', 'icmp']);
  const suelta = obs('p9', 0, 280, ['eth', 'ip', 'icmp'], { confianza: 'sin_correlacionar' });
  const todas = [arp0, arp1b, arp1a, rep0, rep1, eco0, suelta, eco1];

  it('agrupa las ramas de una inundación en un mismo paso', () => {
    const pasos = construirPasos(todas);
    expect(pasos.map((p) => p.clave)).toEqual(['p1/0', 'p1/1', 'p2/0', 'p2/1', 'p3/0', 'p9/0', 'p3/1']);
    expect(pasos[1].obs.map((o) => o.enlace).sort()).toEqual(['e2', 'e3']);
  });

  it('deja sola a la observación sin correlacionar', () => {
    const pasos = construirPasos(todas);
    expect(pasos[5].obs).toEqual([suelta]);
  });

  it('filtra por protocolo', () => {
    expect(construirPasos(todas, 'icmp').map((p) => p.clave)).toEqual(['p3/0', 'p9/0', 'p3/1']);
    expect(construirPasos(todas, 'arp')).toHaveLength(4);
  });

  it('encuentra el paso de una observación', () => {
    const pasos = construirPasos(todas);
    expect(indicePasoDe(pasos, arp1a.id)).toBe(1);
    expect(indicePasoDe(pasos, 'o999')).toBe(-1);
  });
});
