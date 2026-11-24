import { create } from 'zustand';
import type { Enlace, EstadoCaptura, EstadoRed, Interfaz, Lab, Nodo, TipoNodo } from '../api/tipos';
import { ejemplo3Pc } from './ejemplos';
export { EJEMPLOS, ejemplo3Pc } from './ejemplos';

// Puertos por tipo (igual que PUERTOS en el backend). Nombre Linux: <nombre>-eth<puerto>.
export const PUERTOS: Record<TipoNodo, number[]> = {
  pc: [0],
  switch: Array.from({ length: 16 }, (_, i) => i + 1),
  router: Array.from({ length: 8 }, (_, i) => i),
  servidor: [0],
};

const PREFIJO: Record<TipoNodo, string> = { pc: 'pc', switch: 's', router: 'r', servidor: 'srv' };
const GUARDADO = 'minired.lab';

import { desdeSeleccion, NINGUNO, quitarMarcados, unica, type Marcados, type Seleccion } from './seleccion';
export type { Seleccion } from './seleccion';

// Selección única (panel de propiedades) y múltiple (lienzo) siempre coherentes.
const sel = (seleccion: Seleccion) => ({ seleccion, marcados: desdeSeleccion(seleccion) });

interface EstadoLab {
  nodos: Nodo[];
  enlaces: Enlace[];
  seleccion: Seleccion;
  marcados: Marcados;
  estadoRed: EstadoRed;
  enlacesCaidos: string[];      // bajados con "Bajar enlace" (los informa el servidor)
  cargas: number;               // sube con cada laboratorio cargado: el lienzo vuelve a encuadrar
  errorRed: string | null;
  captura: EstadoCaptura | null;
  conectado: boolean;
  mensaje: { texto: string; tipo: 'error' | 'info'; detalles?: string[] } | null;

  agregarNodo: (tipo: TipoNodo, x: number, y: number) => void;
  moverNodo: (id: string, x: number, y: number) => void;
  actualizarNodo: (id: string, cambio: Partial<Nodo>) => void;
  ponerIp: (id: string, puerto: number, ip: string) => void;
  editarInterfaz: (id: string, puerto: number, cambio: Partial<Interfaz>) => void;
  conectar: (origen: string, destino: string) => void;
  borrarSeleccion: () => void;
  seleccionar: (s: Seleccion) => void;
  marcar: (m: Marcados) => void;
  cargar: (lab: Lab) => void;
  lab: () => Lab;
  avisar: (texto: string, tipo?: 'error' | 'info', detalles?: string[]) => void;
}

function siguienteNombre(nodos: Nodo[], tipo: TipoNodo) {
  const usados = new Set(nodos.map((n) => n.nombre));
  for (let i = 1; ; i++) if (!usados.has(`${PREFIJO[tipo]}${i}`)) return `${PREFIJO[tipo]}${i}`;
}

function siguienteId(prefijo: string, ids: string[]) {
  const usados = new Set(ids);
  for (let i = 1; ; i++) if (!usados.has(`${prefijo}${i}`)) return `${prefijo}${i}`;
}

function siguienteIpPc(nodos: Nodo[]) {
  const usadas = new Set(nodos.flatMap((n) => n.interfaces.map((i) => i.ip?.split('/')[0])));
  for (let i = 1; i < 255; i++) if (!usadas.has(`10.0.0.${i}`)) return `10.0.0.${i}/24`;
  return null;
}

function limpiarInterfaz(i: Interfaz): Interfaz {
  const r: Interfaz = { puerto: i.puerto };
  if (i.ip) r.ip = i.ip;
  if (i.vlan != null) r.vlan = i.vlan;
  if (i.troncal != null) r.troncal = i.troncal;
  if (i.subinterfaces?.length) r.subinterfaces = i.subinterfaces;
  if (i.nat) r.nat = i.nat;
  if (i.acl_entrada?.length) r.acl_entrada = i.acl_entrada;
  return r;
}

export function puertoLibre(nodo: Nodo, enlaces: Enlace[]): number | null {
  const usados = new Set(
    enlaces.flatMap((e) => [e.a, e.b]).filter((x) => x.nodo === nodo.id).map((x) => x.puerto));
  return PUERTOS[nodo.tipo].find((p) => !usados.has(p)) ?? null;
}

export function nombreIntf(nodo: Nodo | undefined, puerto: number) {
  return nodo ? `${nodo.nombre}-eth${puerto}` : `?-eth${puerto}`;
}

export function interfazDe(nodo: Nodo | undefined, puerto: number): Interfaz {
  return nodo?.interfaces.find((i) => i.puerto === puerto) ?? { puerto };
}

function leerGuardado(): Lab | null {
  try {
    const t = localStorage.getItem(GUARDADO);
    return t ? (JSON.parse(t) as Lab) : null;
  } catch {
    return null;
  }
}

const inicial = leerGuardado() ?? ejemplo3Pc;

export const useLab = create<EstadoLab>((set, get) => ({
  nodos: inicial.nodos,
  enlaces: inicial.enlaces,
  seleccion: null,
  marcados: NINGUNO,
  estadoRed: 'diseño',
  enlacesCaidos: [],
  cargas: 0,
  errorRed: null,
  captura: null,
  conectado: false,
  mensaje: null,

  agregarNodo: (tipo, x, y) => set((s) => {
    const nodo: Nodo = {
      id: siguienteId('n', s.nodos.map((n) => n.id)), tipo, nombre: siguienteNombre(s.nodos, tipo),
      x, y, interfaces: [],
    };
    if (tipo === 'pc' || tipo === 'servidor') {
      const ip = siguienteIpPc(s.nodos);
      if (ip) nodo.interfaces = [{ puerto: 0, ip }];
    }
    return { nodos: [...s.nodos, nodo], ...sel({ tipo: 'nodo', id: nodo.id }) };
  }),

  moverNodo: (id, x, y) => set((s) => ({
    nodos: s.nodos.map((n) => (n.id === id ? { ...n, x, y } : n)),
  })),

  actualizarNodo: (id, cambio) => set((s) => ({
    nodos: s.nodos.map((n) => (n.id === id ? { ...n, ...cambio } : n)),
  })),

  ponerIp: (id, puerto, ip) => get().editarInterfaz(id, puerto, { ip: ip.trim() || null }),

  // Cambia una interfaz (la crea si hace falta) y quita las que quedan sin ningún dato.
  editarInterfaz: (id, puerto, cambio) => set((s) => ({
    nodos: s.nodos.map((n) => {
      if (n.id !== id) return n;
      const actual = n.interfaces.find((i) => i.puerto === puerto) ?? { puerto };
      const nueva = limpiarInterfaz({ ...actual, ...cambio });
      const resto = n.interfaces.filter((i) => i.puerto !== puerto);
      const interfaces = Object.keys(nueva).length > 1 ? [...resto, nueva] : resto;
      return { ...n, interfaces: interfaces.sort((a, b) => a.puerto - b.puerto) };
    }),
  })),

  conectar: (origen, destino) => {
    const s = get();
    const a = s.nodos.find((n) => n.id === origen);
    const b = s.nodos.find((n) => n.id === destino);
    if (!a || !b || a.id === b.id) return;
    if (s.enlaces.some((e) => (e.a.nodo === a.id && e.b.nodo === b.id) || (e.a.nodo === b.id && e.b.nodo === a.id))) {
      s.avisar(`${a.nombre} y ${b.nombre} ya están conectados`);
      return;
    }
    const pa = puertoLibre(a, s.enlaces);
    const pb = puertoLibre(b, s.enlaces);
    if (pa === null || pb === null) {
      s.avisar(`${(pa === null ? a : b).nombre} no tiene puertos libres`);
      return;
    }
    const enlace: Enlace = {
      id: siguienteId('e', s.enlaces.map((e) => e.id)),
      a: { nodo: a.id, puerto: pa },
      b: { nodo: b.id, puerto: pb },
    };
    set({ enlaces: [...s.enlaces, enlace], ...sel({ tipo: 'enlace', id: enlace.id }) });
  },

  // Borra lo marcado (uno o varios equipos y enlaces) y los enlaces de esos equipos.
  borrarSeleccion: () => set((s) => ({ ...quitarMarcados(s, s.marcados), ...sel(null) })),

  seleccionar: (seleccion) => set(sel(seleccion)),

  marcar: (marcados) => set({ marcados, seleccion: unica(marcados) }),

  cargar: (lab) => set((s) => ({ nodos: lab.nodos, enlaces: lab.enlaces, cargas: s.cargas + 1, ...sel(null) })),

  lab: () => ({ version: 1, nodos: get().nodos, enlaces: get().enlaces }),

  avisar: (texto, tipo = 'error', detalles) => set({ mensaje: { texto, tipo, detalles } }),
}));

// Autoguardado del diseño en este navegador (comodidad; el archivo JSON es el respaldo).
useLab.subscribe((s, previo) => {
  if (s.nodos === previo.nodos && s.enlaces === previo.enlaces) return;
  try {
    localStorage.setItem(GUARDADO, JSON.stringify({ version: 1, nodos: s.nodos, enlaces: s.enlaces }));
  } catch { /* sin almacenamiento */ }
});
