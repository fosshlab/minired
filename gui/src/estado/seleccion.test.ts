import { describe, expect, it } from 'vitest';
import type { Enlace, Nodo } from '../api/tipos';
import { aplicarCambios, soltarEnlacesDe, desdeSeleccion, enlacesAfectados, NINGUNO, quitarMarcados, textoConfirmacion, unica } from './seleccion';

const nodo = (id: string): Nodo => ({ id, tipo: 'pc', nombre: id, x: 0, y: 0, interfaces: [] });
const enlace = (id: string, a: string, b: string): Enlace => ({ id, a: { nodo: a, puerto: 0 }, b: { nodo: b, puerto: 1 } });
const lab = {
  nodos: ['pc1', 'pc2', 'pc3', 's1'].map(nodo),
  enlaces: [enlace('e1', 'pc1', 's1'), enlace('e2', 'pc2', 's1'), enlace('e3', 'pc3', 's1')],
};

describe('selección múltiple', () => {
  it('suma y quita con los cambios de React Flow (rectángulo o Shift/Ctrl+clic)', () => {
    let m = aplicarCambios(NINGUNO, 'nodos', [{ id: 'pc1', selected: true }, { id: 'pc2', selected: true }]);
    expect(m.nodos).toEqual(['pc1', 'pc2']);
    m = aplicarCambios(m, 'nodos', [{ id: 'pc1', selected: false }]);
    expect(m.nodos).toEqual(['pc2']);
    m = aplicarCambios(m, 'enlaces', [{ id: 'e2', selected: true }]);
    expect(m).toEqual({ nodos: ['pc2'], enlaces: ['e2'] });
    expect(aplicarCambios(m, 'nodos', [])).toBe(m);
  });

  it('el panel muestra un elemento solo si hay uno', () => {
    expect(unica(NINGUNO)).toBeNull();
    expect(unica({ nodos: ['pc1'], enlaces: [] })).toEqual({ tipo: 'nodo', id: 'pc1' });
    expect(unica({ nodos: [], enlaces: ['e3'] })).toEqual({ tipo: 'enlace', id: 'e3' });
    expect(unica({ nodos: ['pc1'], enlaces: ['e1'] })).toBeNull();
    expect(desdeSeleccion({ tipo: 'enlace', id: 'e1' })).toEqual({ nodos: [], enlaces: ['e1'] });
  });

  it('borrar en bloque se lleva los enlaces de los equipos', () => {
    const m = { nodos: ['pc1', 'pc2'], enlaces: [] };
    expect(enlacesAfectados(m, lab.enlaces)).toEqual(['e1', 'e2']);
    const r = quitarMarcados(lab, m);
    expect(r.nodos.map((n) => n.id)).toEqual(['pc3', 's1']);
    expect(r.enlaces.map((e) => e.id)).toEqual(['e3']);
    expect(quitarMarcados(lab, { nodos: [], enlaces: ['e3'] }).nodos).toHaveLength(4);
    expect(textoConfirmacion(m, lab)).toBe('¿Eliminar 2 equipos (pc1, pc2) y 2 enlaces? No se puede deshacer.');
  });

  it('desmarcar un equipo desmarca sus enlaces', () => {
    const m = { nodos: ['pc2', 's1'], enlaces: ['e1', 'e2', 'e3'] };
    expect(soltarEnlacesDe(m, ['pc2'], lab.enlaces)).toEqual({ nodos: ['pc2', 's1'], enlaces: ['e1', 'e3'] });
    expect(soltarEnlacesDe(m, [], lab.enlaces)).toBe(m);
  });
});
