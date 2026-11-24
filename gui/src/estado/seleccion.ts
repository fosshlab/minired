import type { Enlace, Nodo } from '../api/tipos';

// Selección múltiple del lienzo (rectángulo, Shift/Ctrl+clic). Lógica pura: se prueba con vitest.

export type Seleccion = { tipo: 'nodo' | 'enlace'; id: string } | null;

export interface Marcados {
  nodos: string[];
  enlaces: string[];
}

export const NINGUNO: Marcados = { nodos: [], enlaces: [] };

export interface CambioSeleccion {
  id: string;
  selected: boolean;
}

// Aplica los cambios "select" que emite React Flow (clic, Shift/Ctrl+clic o rectángulo).
export function aplicarCambios(m: Marcados, clave: keyof Marcados, cambios: CambioSeleccion[]): Marcados {
  if (!cambios.length) return m;
  const ids = new Set(m[clave]);
  for (const c of cambios) {
    if (c.selected) ids.add(c.id);
    else ids.delete(c.id);
  }
  return { ...m, [clave]: [...ids] };
}

// Al desmarcar un equipo (Shift/Ctrl+clic) se desmarcan también sus enlaces: si no, un enlace
// marcado por el rectángulo se borraría junto con el resto aunque su equipo ya no esté elegido.
export function soltarEnlacesDe(m: Marcados, quitados: string[], enlaces: Enlace[]): Marcados {
  if (!quitados.length) return m;
  const q = new Set(quitados);
  const tocan = new Set(enlaces.filter((e) => q.has(e.a.nodo) || q.has(e.b.nodo)).map((e) => e.id));
  const restantes = m.enlaces.filter((id) => !tocan.has(id));
  return restantes.length === m.enlaces.length ? m : { ...m, enlaces: restantes };
}

// El panel de propiedades muestra un elemento solo si hay exactamente uno seleccionado.
export function unica(m: Marcados): Seleccion {
  if (m.nodos.length + m.enlaces.length !== 1) return null;
  return m.nodos.length ? { tipo: 'nodo', id: m.nodos[0] } : { tipo: 'enlace', id: m.enlaces[0] };
}

export function desdeSeleccion(s: Seleccion): Marcados {
  if (!s) return NINGUNO;
  return s.tipo === 'nodo' ? { nodos: [s.id], enlaces: [] } : { nodos: [], enlaces: [s.id] };
}

// Enlaces que se borran con la selección: los marcados y todos los que tocan un equipo marcado.
export function enlacesAfectados(m: Marcados, enlaces: Enlace[]): string[] {
  const nodos = new Set(m.nodos);
  const marcados = new Set(m.enlaces);
  return enlaces.filter((e) => marcados.has(e.id) || nodos.has(e.a.nodo) || nodos.has(e.b.nodo)).map((e) => e.id);
}

export function quitarMarcados(lab: { nodos: Nodo[]; enlaces: Enlace[] }, m: Marcados) {
  const nodos = new Set(m.nodos);
  const enlaces = new Set(enlacesAfectados(m, lab.enlaces));
  return {
    nodos: lab.nodos.filter((n) => !nodos.has(n.id)),
    enlaces: lab.enlaces.filter((e) => !enlaces.has(e.id)),
  };
}

// Texto de la confirmación antes de borrar en bloque.
export function textoConfirmacion(m: Marcados, lab: { nodos: Nodo[]; enlaces: Enlace[] }) {
  const nombres = lab.nodos.filter((n) => m.nodos.includes(n.id)).map((n) => n.nombre);
  const nEnlaces = enlacesAfectados(m, lab.enlaces).length;
  const partes = [];
  if (nombres.length) partes.push(`${nombres.length} equipo${nombres.length > 1 ? 's' : ''} (${nombres.join(', ')})`);
  if (nEnlaces) partes.push(`${nEnlaces} enlace${nEnlaces > 1 ? 's' : ''}`);
  return `¿Eliminar ${partes.join(' y ')}? No se puede deshacer.`;
}
