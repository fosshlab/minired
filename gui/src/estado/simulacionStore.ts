import { create } from 'zustand';
import type { Observacion } from '../api/tipos';
import { construirPasos, indicePasoDe, type Filtro, type Paso } from '../simulacion/reproductor';

export type Modo = 'pausa' | 'play' | 'paso';

interface EstadoSimulacion {
  activo: boolean;               // modo simulación encendido en la interfaz
  observaciones: Observacion[];  // confirmadas por el correlador, en orden de tiempo
  pasos: Paso[];
  filtro: Filtro;
  cursor: number;                // paso actual (-1: antes del primero)
  t: number;                     // avance de la animación del paso actual (0..1)
  modo: Modo;
  velocidad: number;             // 1 = 1 s por paso
  seleccion: string | null;      // id de observación elegida
  descartadasVista: number;
  aviso: string | null;

  setActivo: (v: boolean) => void;
  reiniciar: () => void;
  agregar: (items: Observacion[], descartadas?: number) => void;
  reemplazar: (items: Observacion[]) => void;
  setFiltro: (f: Filtro) => void;
  avanzar: (dt: number) => void;
  play: () => void;
  pausa: () => void;
  siguiente: () => void;
  anterior: () => void;
  irA: (indice: number) => void;
  elegir: (obsId: string | null) => void;
  setVelocidad: (v: number) => void;
  setAviso: (t: string | null) => void;
}

export const useSimulacion = create<EstadoSimulacion>((set, get) => ({
  activo: false,
  observaciones: [],
  pasos: [],
  filtro: 'todos',
  cursor: -1,
  t: 0,
  modo: 'play',
  velocidad: 1,
  seleccion: null,
  descartadasVista: 0,
  aviso: null,

  setActivo: (activo) => set({ activo }),

  reiniciar: () => set({ observaciones: [], pasos: [], cursor: -1, t: 0, seleccion: null, descartadasVista: 0 }),

  agregar: (items, descartadas) => set((s) => {
    const conocidos = new Set(s.observaciones.map((o) => o.id));
    const nuevas = items.filter((o) => !conocidos.has(o.id));
    if (!nuevas.length && descartadas === undefined) return {};
    const observaciones = [...s.observaciones, ...nuevas];
    return {
      observaciones,
      pasos: construirPasos(observaciones, s.filtro),
      descartadasVista: descartadas ?? s.descartadasVista,
    };
  }),

  reemplazar: (items) => set((s) => ({
    observaciones: items, pasos: construirPasos(items, s.filtro), cursor: -1, t: 0, seleccion: null,
  })),

  setFiltro: (filtro) => set((s) => ({ filtro, pasos: construirPasos(s.observaciones, filtro), cursor: -1, t: 0 })),

  // Llamado por requestAnimationFrame. Duración de un paso: 1 s / velocidad.
  avanzar: (dt) => {
    const s = get();
    if (s.modo === 'pausa') return;
    if (s.cursor < 0 || s.t >= 1) {
      if (s.modo === 'play' && s.cursor < s.pasos.length - 1) set({ cursor: s.cursor + 1, t: 0 });
      else if (s.modo === 'paso' && s.t >= 1) set({ modo: 'pausa' });
      return;
    }
    set({ t: Math.min(1, s.t + (dt / 1000) * s.velocidad) });
  },

  play: () => set((s) => (s.cursor >= s.pasos.length - 1 && s.t >= 1 && s.pasos.length
    ? { modo: 'play', cursor: 0, t: 0 } : { modo: 'play' })),
  pausa: () => set({ modo: 'pausa' }),
  siguiente: () => set((s) => (s.cursor < s.pasos.length - 1 ? { cursor: s.cursor + 1, t: 0, modo: 'paso' } : {})),
  anterior: () => set((s) => (s.cursor > 0 ? { cursor: s.cursor - 1, t: 0, modo: 'paso' } : { cursor: -1, t: 0, modo: 'pausa' })),
  irA: (indice) => set((s) => ({ cursor: Math.max(-1, Math.min(indice, s.pasos.length - 1)), t: 0, modo: 'paso' })),

  elegir: (obsId) => {
    const s = get();
    if (obsId === null) return set({ seleccion: null });
    const i = indicePasoDe(s.pasos, obsId);
    set({ seleccion: obsId, ...(i >= 0 && i !== s.cursor ? { cursor: i, t: 0, modo: 'paso' as Modo } : {}) });
  },

  setVelocidad: (velocidad) => set({ velocidad }),
  setAviso: (aviso) => set({ aviso }),
}));
