import { create } from 'zustand';

// Pestañas del panel inferior: la lista de eventos y una terminal por nodo abierto.
interface EstadoPanel {
  terminales: string[];
  pestana: string;        // 'eventos' o id de nodo
  abrirTerminal: (nodo: string) => void;
  cerrarTerminal: (nodo: string) => void;
  cerrarTodas: () => void;
  setPestana: (p: string) => void;
}

export const usePanel = create<EstadoPanel>((set) => ({
  terminales: [],
  pestana: 'eventos',
  abrirTerminal: (nodo) => set((s) => ({
    terminales: s.terminales.includes(nodo) ? s.terminales : [...s.terminales, nodo], pestana: nodo,
  })),
  cerrarTerminal: (nodo) => set((s) => ({
    terminales: s.terminales.filter((t) => t !== nodo), pestana: s.pestana === nodo ? 'eventos' : s.pestana,
  })),
  cerrarTodas: () => set({ terminales: [], pestana: 'eventos' }),
  setPestana: (pestana) => set({ pestana }),
}));
