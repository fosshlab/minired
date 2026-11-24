import { useEffect, useMemo, useRef } from 'react';
import { useLab } from '../estado/labStore';
import { predicado, useSimulacion } from '../estado/simulacionStore';
import { colorProtocolo, etiquetaProtocolo } from './reproductor';
import { esRuido, etiquetaSimple, nombresDe } from './simple';

const CONFIANZA = {
  alta: 'alta', media: 'media (reenviado por router)', baja: 'baja (traducido por NAT)', sin_correlacionar: 'suelta',
} as const;

export function ListaEventos() {
  const { observaciones, pasos, cursor, seleccion, filtro, vista, fondo, filtroWs, elegir } = useSimulacion();
  const nodos = useLab((s) => s.nodos);
  const enlaces = useLab((s) => s.enlaces);
  const nombres = useMemo(() => nombresDe({ version: 1, nodos, enlaces }, observaciones), [nodos, enlaces, observaciones]);
  const captura = useLab((s) => s.captura);
  const nombre = (id: string) => nodos.find((n) => n.id === id)?.nombre ?? id;
  const enPaso = useMemo(() => new Set(cursor >= 0 && pasos[cursor] ? pasos[cursor].obs.map((o) => o.id) : []), [pasos, cursor]);
  const visibles = useMemo(() => observaciones.filter(predicado({ vista, fondo, filtro, filtroWs })),
    [observaciones, vista, fondo, filtro, filtroWs]);
  const ocultas = vista === 'simple' && !fondo ? observaciones.filter((o) => esRuido(o)).length : 0;
  const contenedor = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const fila = contenedor.current?.querySelector('tr.en-paso');
    fila?.scrollIntoView({ block: 'nearest' });
  }, [cursor]);

  if (!observaciones.length) {
    return (
      <div className="lista-vacia">
        {captura?.activa
          ? 'Capturando en todos los extremos de cada enlace. Generá tráfico (por ejemplo ping -c 1 desde una terminal).'
          : 'Activá Simulación con la red en marcha para capturar el tráfico real.'}
      </div>
    );
  }
  const clase = (id: string) => `${enPaso.has(id) ? 'en-paso' : ''}${seleccion === id ? ' elegida' : ''}`;
  const chip = (o: (typeof visibles)[number]) => (
    <span className="chip" style={{ background: colorProtocolo(o) }}>{etiquetaProtocolo(o)}</span>
  );

  if (vista === 'simple') {
    // Como la lista de eventos de Packet Tracer: último dispositivo, en dispositivo y tipo.
    return (
      <div className="lista-eventos simple" ref={contenedor}>
        <table>
          <thead>
            <tr><th>#</th><th>Tiempo</th><th>Último dispositivo</th><th>En dispositivo</th><th>Tipo</th><th>Qué pasa</th></tr>
          </thead>
          <tbody>
            {visibles.map((o, i) => (
              <tr key={o.id} className={clase(o.id)} onClick={() => elegir(o.id)}>
                <td>{i + 1}</td>
                <td className="num">{(o.t_us / 1000).toFixed(1)} ms</td>
                <td>{nombre(o.emisor)}</td>
                <td><b>{nombre(o.nodo)}</b></td>
                <td>{chip(o)}</td>
                <td>{o.confianza === 'sin_correlacionar' ? '? ' : ''}{etiquetaSimple(o, nombres)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {ocultas > 0 && <p className="tenue nota-fondo">{ocultas} de tráfico de fondo ocultas (Hello de OSPF, verificaciones ARP). Marcá "Tráfico de fondo" para verlas.</p>}
      </div>
    );
  }

  // Avanzado: como la lista de Wireshark, más el cruce y la correlación de minired.
  return (
    <div className="lista-eventos" ref={contenedor}>
      <table>
        <thead>
          <tr><th>No.</th><th>Tiempo</th><th>Origen</th><th>Destino</th><th>Protocolo</th><th>Largo</th><th>Info</th>
            <th>Cruce</th><th>Paquete</th><th>Correlación</th></tr>
        </thead>
        <tbody>
          {visibles.map((o) => {
            const r = o.resumen;
            const origen = r.ip?.src ?? r.arp?.sha ?? r.eth?.src ?? '';
            const destino = r.ip?.dst ?? (r.arp ? (r.eth?.dst === 'ff:ff:ff:ff:ff:ff' ? 'Broadcast' : r.eth?.dst) : r.eth?.dst) ?? '';
            return (
              <tr key={o.id} className={clase(o.id)} onClick={() => elegir(o.id)}>
                <td>{o.seq}</td>
                <td className="num">{(o.t_us / 1e6).toFixed(6)}</td>
                <td>{origen}</td>
                <td>{destino}</td>
                <td>{chip(o)}{r.vlan ? <span className="tenue"> v{r.vlan.id}</span> : null}</td>
                <td className="num">{o.largo}</td>
                <td>{r.info}</td>
                <td><b>{nombre(o.emisor)}</b> → <b>{nombre(o.nodo)}</b> <span className="tenue">({o.intf})</span></td>
                <td>{o.paquete}{o.profundidad ? ` · salto ${o.profundidad}` : ''}</td>
                <td className={`conf-${o.confianza}`}>{CONFIANZA[o.confianza]}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
