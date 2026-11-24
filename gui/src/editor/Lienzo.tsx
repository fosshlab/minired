import { useCallback, useEffect, useMemo, type DragEvent } from 'react';
import {
  Background, ConnectionMode, Controls, ReactFlow, SelectionMode, useNodesInitialized, useReactFlow,
  type Connection, type EdgeChange, type NodeChange,
} from '@xyflow/react';
import type { TipoNodo } from '../api/tipos';
import { useLab } from '../estado/labStore';
import { aplicarCambios, soltarEnlacesDe, type CambioSeleccion } from '../estado/seleccion';
import { useSimulacion } from '../estado/simulacionStore';
import { AristaEnlace, type AristaFlujo } from './AristaEnlace';
import { NodoRed, type NodoFlujo } from './NodoRed';
import { confirmarYBorrar } from './PanelPropiedades';

const tiposNodo = { red: NodoRed };
const tiposArista = { enlace: AristaEnlace };

export function Lienzo() {
  const { nodos, enlaces, marcados, enlacesCaidos, estadoRed, moverNodo, seleccionar, marcar, conectar, agregarNodo } = useLab();
  const paso = useSimulacion((s) => (s.activo && s.cursor >= 0 ? s.pasos[s.cursor] : null));
  const t = useSimulacion((s) => s.t);
  const { screenToFlowPosition, fitView } = useReactFlow();
  const cargas = useLab((s) => s.cargas);
  const medidos = useNodesInitialized();
  const diseno = estadoRed === 'diseño' || estadoRed === 'error';

  const receptores = useMemo(
    () => new Set(paso && t >= 1 ? paso.obs.map((o) => o.nodo) : []), [paso, t >= 1]); // eslint-disable-line

  const nodes: NodoFlujo[] = useMemo(() => nodos.map((n) => ({
    id: n.id, type: 'red', position: { x: n.x, y: n.y },
    selected: marcados.nodos.includes(n.id),
    data: { nodo: n, conectable: diseno, recibe: receptores.has(n.id) },
  })), [nodos, marcados, diseno, receptores]);

  const edges: AristaFlujo[] = useMemo(() => enlaces.map((e) => ({
    id: e.id, type: 'enlace', source: e.a.nodo, target: e.b.nodo, sourceHandle: 's', targetHandle: 't',
    selected: marcados.enlaces.includes(e.id),
    // Con la red en marcha manda el estado real (lo informa el servidor); en diseño, el cable suelto.
    data: { enlace: e, caido: diseno ? !!e.desconectado : enlacesCaidos.includes(e.id) },
  })), [enlaces, marcados, enlacesCaidos, diseno]);

  // Selección controlada: React Flow emite cambios "select" al hacer clic, Shift/Ctrl+clic o al
  // arrastrar el rectángulo; se aplican sobre los marcados del store.
  const alCambiarNodos = useCallback((cambios: NodeChange<NodoFlujo>[]) => {
    const sel: CambioSeleccion[] = [];
    for (const c of cambios) {
      if (c.type === 'position' && c.position) moverNodo(c.id, Math.round(c.position.x), Math.round(c.position.y));
      if (c.type === 'select') sel.push(c);
    }
    if (sel.length) {
      // Elegir un equipo muestra sus datos, no el detalle del último paquete elegido.
      if (sel.some((c) => c.selected)) useSimulacion.getState().elegir(null);
      const { marcados: m, enlaces: todos } = useLab.getState();
      const quitados = sel.filter((c) => !c.selected).map((c) => c.id);
      marcar(soltarEnlacesDe(aplicarCambios(m, 'nodos', sel), quitados, todos));
    }
  }, [moverNodo, marcar]);

  const alCambiarAristas = useCallback((cambios: EdgeChange<AristaFlujo>[]) => {
    const sel = cambios.filter((c): c is CambioSeleccion & EdgeChange<AristaFlujo> => c.type === 'select');
    if (sel.length) {
      if (sel.some((c) => c.selected)) useSimulacion.getState().elegir(null);
      marcar(aplicarCambios(useLab.getState().marcados, 'enlaces', sel));
    }
  }, [marcar]);

  const alConectar = useCallback((c: Connection) => {
    if (c.source && c.target) conectar(c.source, c.target);
  }, [conectar]);

  // Al cargar un ejemplo o un archivo, encuadrar cuando React Flow ya midió los nodos nuevos
  // (antes, la vista quedaba como estaba y la red podía quedar fuera de pantalla).
  useEffect(() => {
    if (cargas && medidos) fitView({ padding: 0.3, maxZoom: 1.2 });
  }, [cargas, medidos, fitView]);

  // Supr / Delete borra la selección (con confirmación), salvo mientras se escribe en un campo.
  useEffect(() => {
    const tecla = (e: KeyboardEvent) => {
      if (e.key !== 'Delete') return;
      const t = e.target as HTMLElement | null;
      if (t && (t.closest('input, textarea, select, .xterm') || t.isContentEditable)) return;
      confirmarYBorrar();
    };
    window.addEventListener('keydown', tecla);
    return () => window.removeEventListener('keydown', tecla);
  }, []);

  const alSoltar = (e: DragEvent) => {
    e.preventDefault();
    const tipo = e.dataTransfer.getData('application/minired-nodo') as TipoNodo;
    if (!tipo || !diseno) return;
    const p = screenToFlowPosition({ x: e.clientX, y: e.clientY });
    agregarNodo(tipo, Math.round(p.x - 32), Math.round(p.y - 30));
  };

  return (
    <div className="lienzo" onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; }} onDrop={alSoltar}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={tiposNodo}
        edgeTypes={tiposArista}
        onNodesChange={alCambiarNodos}
        onEdgesChange={alCambiarAristas}
        onConnect={alConectar}
        onPaneClick={() => seleccionar(null)}
        onPaneContextMenu={(e) => e.preventDefault()}
        // Como en Packet Tracer: arrastrar en el fondo dibuja un rectángulo de selección.
        // La vista se mueve con el botón del medio o el derecho, o con la barra espaciadora.
        selectionOnDrag
        selectionMode={SelectionMode.Partial}
        panOnDrag={[1, 2]}
        panActivationKeyCode="Space"
        multiSelectionKeyCode={['Shift', 'Control', 'Meta']}
        selectionKeyCode={null}
        connectionMode={ConnectionMode.Loose}
        connectionRadius={40}
        nodesConnectable={diseno}
        deleteKeyCode={null}
        fitView
        fitViewOptions={{ padding: 0.3, maxZoom: 1.2 }}
        minZoom={0.3}
        maxZoom={2.5}
        proOptions={{ hideAttribution: false }}
      >
        <Background gap={24} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
