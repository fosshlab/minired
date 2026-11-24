import type { TipoNodo } from '../api/tipos';
import { useLab } from '../estado/labStore';
import { Icono, NOMBRE_TIPO } from './iconos';

const TIPOS: TipoNodo[] = ['pc', 'switch', 'router', 'servidor'];

export function Paleta() {
  const estado = useLab((s) => s.estadoRed);
  const agregarNodo = useLab((s) => s.agregarNodo);
  const nodos = useLab((s) => s.nodos);
  const diseno = estado === 'diseño' || estado === 'error';
  return (
    <aside className="paleta" aria-label="Equipos">
      <div className="paleta-titulo">Equipos</div>
      {TIPOS.map((tipo) => (
        <button key={tipo} className="paleta-item" draggable={diseno} disabled={!diseno}
          title={diseno ? 'Arrastrá al lienzo o hacé clic' : 'Detené la red para editar'}
          onDragStart={(e) => { e.dataTransfer.setData('application/minired-nodo', tipo); e.dataTransfer.effectAllowed = 'copy'; }}
          onClick={() => agregarNodo(tipo, 120 + (nodos.length % 5) * 90, 80 + Math.floor(nodos.length / 5) * 110)}>
          <Icono tipo={tipo} tam={34} />
          <span>{NOMBRE_TIPO[tipo]}</span>
        </button>
      ))}
      <p className="paleta-ayuda">
        {diseno ? 'Para conectar, arrastrá desde el punto verde de un equipo hasta otro.' : 'Red en marcha: el diseño está bloqueado.'}
      </p>
      <p className="paleta-ayuda">
        Fondo + arrastrar: elegir varios (Shift/Ctrl+clic suma o quita).
        Mover la vista: botón derecho o espacio + arrastrar.
      </p>
    </aside>
  );
}
