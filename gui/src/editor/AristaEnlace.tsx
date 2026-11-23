import { useInternalNode, type Edge, type EdgeProps, type InternalNode } from '@xyflow/react';
import type { Enlace } from '../api/tipos';
import { useLab, nombreIntf } from '../estado/labStore';
import { useSimulacion } from '../estado/simulacionStore';
import { colorProtocolo, etiquetaProtocolo } from '../simulacion/reproductor';

export type AristaFlujo = Edge<{ enlace: Enlace; caido?: boolean }, 'enlace'>;

function centro(n: InternalNode) {
  const w = n.measured.width ?? 0;
  const h = n.measured.height ?? 0;
  return { x: n.internals.positionAbsolute.x + w / 2, y: n.internals.positionAbsolute.y + h / 2, w, h };
}

// Punto donde la recta entre centros sale del rectángulo del nodo.
function borde(c: { x: number; y: number; w: number; h: number }, hacia: { x: number; y: number }) {
  const dx = hacia.x - c.x;
  const dy = hacia.y - c.y;
  if (!dx && !dy) return { x: c.x, y: c.y };
  const esc = Math.min(dx ? (c.w / 2 + 4) / Math.abs(dx) : Infinity, dy ? (c.h / 2 + 4) / Math.abs(dy) : Infinity);
  return { x: c.x + dx * esc, y: c.y + dy * esc };
}

const suavizar = (t: number) => (t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2);

export function AristaEnlace({ id, source, target, data, selected }: EdgeProps<AristaFlujo>) {
  const ns = useInternalNode(source);
  const nt = useInternalNode(target);
  const nodos = useLab((s) => s.nodos);
  const simActivo = useSimulacion((s) => s.activo);
  const paso = useSimulacion((s) => (s.cursor >= 0 ? s.pasos[s.cursor] : null));
  const enPaso = simActivo && paso ? paso.obs.filter((o) => o.enlace === id) : [];
  const t = useSimulacion((s) => (enPaso.length ? s.t : 0));
  const seleccion = useSimulacion((s) => s.seleccion);
  const elegir = useSimulacion((s) => s.elegir);
  if (!ns || !nt || !data) return null;

  const ca = centro(ns);
  const cb = centro(nt);
  const pa = borde(ca, cb);
  const pb = borde(cb, ca);
  const largo = Math.hypot(pb.x - pa.x, pb.y - pa.y) || 1;
  const ux = (pb.x - pa.x) / largo;
  const uy = (pb.y - pa.y) / largo;
  const { enlace } = data;
  const na = nodos.find((n) => n.id === enlace.a.nodo);
  const nb = nodos.find((n) => n.id === enlace.b.nodo);
  const activo = enPaso.length > 0;

  return (
    <g className={`arista${selected ? ' seleccionada' : ''}${activo ? ' activa' : ''}${data.caido ? ' caida' : ''}`}>
      <path d={`M${pa.x},${pa.y} L${pb.x},${pb.y}`} className="arista-zona" />
      <path id={`arista-${id}`} d={`M${pa.x},${pa.y} L${pb.x},${pb.y}`} className="arista-linea" />
      {largo > 90 && (
        <>
          <text x={pa.x + ux * 26} y={pa.y + uy * 26 - 6} className="arista-puerto" textAnchor="middle">
            {nombreIntf(na, enlace.a.puerto).replace(/^.*-/, '')}
          </text>
          <text x={pb.x - ux * 26} y={pb.y - uy * 26 - 6} className="arista-puerto" textAnchor="middle">
            {nombreIntf(nb, enlace.b.puerto).replace(/^.*-/, '')}
          </text>
        </>
      )}
      {enPaso.map((o) => {
        // hacia 'b': lo envió el extremo a y viaja de a hacia b.
        const [desde, hasta] = o.hacia === 'b' ? [pa, pb] : [pb, pa];
        const k = suavizar(t);
        const x = desde.x + (hasta.x - desde.x) * k;
        const y = desde.y + (hasta.y - desde.y) * k;
        const suelta = o.confianza === 'sin_correlacionar';
        const color = colorProtocolo(o);
        return (
          <g key={o.id} transform={`translate(${x - 21},${y - 12})`} className="sobre"
            onClick={(e) => { e.stopPropagation(); elegir(o.id); }}>
            <title>{`${o.resumen.info}${suelta ? ' (observación suelta: sin origen correlacionado)' : ''}`}</title>
            <rect width="42" height="24" rx="4" fill={suelta ? '#fff' : color} stroke={seleccion === o.id ? '#111' : color}
              strokeWidth={seleccion === o.id ? 3 : 2} strokeDasharray={suelta ? '4 3' : undefined} />
            <text x="21" y="16" textAnchor="middle" className="sobre-texto" fill={suelta ? color : '#fff'}>
              {suelta ? '?' : ''}{etiquetaProtocolo(o)}
            </text>
          </g>
        );
      })}
    </g>
  );
}
