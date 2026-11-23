import { useEffect, useMemo, useState } from 'react';
import { api, ErrorApi } from '../api/cliente';
import type { Campo, DetalleCapas } from '../api/tipos';
import { useLab } from '../estado/labStore';
import { useSimulacion } from '../estado/simulacionStore';
import { EXPLICACIONES } from './explicaciones';

const ABIERTAS_INICIO = new Set(['eth', 'arp', 'ip', 'icmp', 'udp', 'tcp']);

export function PanelCapas() {
  const seleccion = useSimulacion((s) => s.seleccion);
  const obs = useSimulacion((s) => s.observaciones.find((o) => o.id === s.seleccion));
  const elegir = useSimulacion((s) => s.elegir);
  const nodos = useLab((s) => s.nodos);
  const [detalle, setDetalle] = useState<DetalleCapas | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [resaltado, setResaltado] = useState<[number, number] | null>(null);

  useEffect(() => {
    if (!seleccion) return;
    let vigente = true;
    setDetalle(null);
    setError(null);
    api.get<DetalleCapas>(`/api/captura/observaciones/${seleccion}/capas`)
      .then((d) => vigente && setDetalle(d))
      .catch((e) => vigente && setError(e instanceof ErrorApi ? e.message : String(e)));
    return () => { vigente = false; };
  }, [seleccion]);

  if (!seleccion || !obs) return null;
  const nombre = (id: string) => nodos.find((n) => n.id === id)?.nombre ?? id;
  return (
    <div className="panel-capas">
      <div className="capas-cabecera">
        <h3>Paquete {obs.paquete} · {obs.id}</h3>
        <button className="cerrar" onClick={() => elegir(null)} aria-label="Cerrar detalle">✕</button>
      </div>
      <p className="tenue">
        Capturado al llegar a <code>{obs.intf}</code> ({nombre(obs.nodo)}), enviado por {nombre(obs.emisor)} por el enlace {obs.enlace}.
        Frame {obs.pcap.n} de <code>{obs.pcap.archivo}</code>.
      </p>
      {obs.confianza === 'sin_correlacionar' && (
        <p className="aviso">Observación suelta: no se encontró por dónde entró este frame al equipo que lo envió. Se muestra sola, sin inventar un camino.</p>
      )}
      {obs.confianza === 'media' && (
        <p className="tenue">Correlacionado a través de un router: mismo paquete IP con TTL una unidad menor y MAC nuevas.</p>
      )}
      {error && <p className="aviso">{error}</p>}
      {!detalle && !error && <p className="tenue">Decodificando con tshark…</p>}
      {detalle && (
        <>
          <div className="capas">
            {detalle.capas.map((c) => <CapaTshark key={c.nombre} campo={c} nivel={0} resaltar={setResaltado} />)}
          </div>
          <Hex hex={detalle.hex} resaltado={resaltado} />
        </>
      )}
    </div>
  );
}

function CapaTshark({ campo, nivel, resaltar }: { campo: Campo; nivel: number; resaltar: (r: [number, number] | null) => void }) {
  const explicacion = EXPLICACIONES[campo.nombre];
  const rango = campo.pos !== undefined && campo.largo ? [campo.pos, campo.largo] as [number, number] : null;
  const entrar = () => resaltar(rango);
  if (campo.campos?.length) {
    return (
      <details open={nivel === 0 ? ABIERTAS_INICIO.has(campo.nombre) : false} className={`capa nivel-${nivel}`}>
        <summary onMouseEnter={entrar} onMouseLeave={() => resaltar(null)}>{campo.titulo}</summary>
        {nivel === 0 && explicacion && <p className="explicacion">{explicacion}</p>}
        {campo.campos.map((h, i) => <CapaTshark key={`${h.nombre}-${i}`} campo={h} nivel={nivel + 1} resaltar={resaltar} />)}
      </details>
    );
  }
  return (
    <div className="campo" onMouseEnter={entrar} onMouseLeave={() => resaltar(null)}>
      <span>{campo.titulo}</span>
      {explicacion && <span className="explicacion">{explicacion}</span>}
    </div>
  );
}

function Hex({ hex, resaltado }: { hex: string; resaltado: [number, number] | null }) {
  const bytes = useMemo(() => hex.match(/../g) ?? [], [hex]);
  const filas = [];
  for (let i = 0; i < bytes.length; i += 16) filas.push(i);
  const marcado = (i: number) => resaltado !== null && i >= resaltado[0] && i < resaltado[0] + resaltado[1];
  return (
    <div className="hex" aria-label="Bytes del frame">
      {filas.map((ini) => (
        <div key={ini} className="hex-fila">
          <span className="hex-off">{ini.toString(16).padStart(4, '0')}</span>
          <span className="hex-bytes">
            {bytes.slice(ini, ini + 16).map((b, j) => <span key={j} className={marcado(ini + j) ? 'marcado' : ''}>{b}</span>)}
          </span>
          <span className="hex-ascii">
            {bytes.slice(ini, ini + 16).map((b, j) => {
              const c = parseInt(b, 16);
              return <span key={j} className={marcado(ini + j) ? 'marcado' : ''}>{c >= 32 && c < 127 ? String.fromCharCode(c) : '.'}</span>;
            })}
          </span>
        </div>
      ))}
    </div>
  );
}
