import { useEffect, useMemo, useRef } from 'react';
import { useLab } from '../estado/labStore';
import { useSimulacion } from '../estado/simulacionStore';
import { colorProtocolo, etiquetaProtocolo, pasaFiltro } from './reproductor';

const CONFIANZA = { alta: 'alta', media: 'media (reenviado por router)', sin_correlacionar: 'suelta' } as const;

export function ListaEventos() {
  const { observaciones, pasos, cursor, seleccion, filtro, elegir } = useSimulacion();
  const nodos = useLab((s) => s.nodos);
  const captura = useLab((s) => s.captura);
  const nombre = (id: string) => nodos.find((n) => n.id === id)?.nombre ?? id;
  const enPaso = useMemo(() => new Set(cursor >= 0 && pasos[cursor] ? pasos[cursor].obs.map((o) => o.id) : []), [pasos, cursor]);
  const visibles = observaciones.filter((o) => pasaFiltro(o, filtro));
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
  return (
    <div className="lista-eventos" ref={contenedor}>
      <table>
        <thead>
          <tr><th>#</th><th>Tiempo</th><th>Cruce</th><th>Prot.</th><th>Info</th><th>Paquete</th><th>Correlación</th></tr>
        </thead>
        <tbody>
          {visibles.map((o, i) => (
            <tr key={o.id} className={`${enPaso.has(o.id) ? 'en-paso' : ''}${seleccion === o.id ? ' elegida' : ''}`}
              onClick={() => elegir(o.id)}>
              <td>{i + 1}</td>
              <td className="num">{(o.t_us / 1000).toFixed(3)} ms</td>
              <td><b>{nombre(o.emisor)}</b> → <b>{nombre(o.nodo)}</b> <span className="tenue">({o.intf})</span></td>
              <td><span className="chip" style={{ background: colorProtocolo(o) }}>{etiquetaProtocolo(o)}</span></td>
              <td>{o.resumen.info}</td>
              <td>{o.paquete}{o.profundidad ? ` · salto ${o.profundidad}` : ''}</td>
              <td className={`conf-${o.confianza}`}>{CONFIANZA[o.confianza]}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
