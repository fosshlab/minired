import { useCallback, useMemo, type DragEvent } from 'react';
import {
  Background, ConnectionMode, Controls, ReactFlow, useReactFlow,
  type Connection, type NodeChange,
} from '@xyflow/react';
import type { TipoNodo } from '../api/tipos';
import { useLab } from '../estado/labStore';
import { useSimulacion } from '../estado/simulacionStore';
import { AristaEnlace, type AristaFlujo } from './AristaEnlace';
import { NodoRed, type NodoFlujo } from './NodoRed';

const tiposNodo = { red: NodoRed };
const tiposArista = { enlace: AristaEnlace };

export function Lienzo() {
  const { nodos, enlaces, seleccion, estadoRed, moverNodo, seleccionar, conectar, agregarNodo } = useLab();
  const paso = useSimulacion((s) => (s.activo && s.cursor >= 0 ? s.pasos[s.cursor] : null));
  const t = useSimulacion((s) => s.t);
  const { screenToFlowPosition } = useReactFlow();
  const diseno = estadoRed === 'diseño' || estadoRed === 'error';

  const receptores = useMemo(
    () => new Set(paso && t >= 1 ? paso.obs.map((o) => o.nodo) : []), [paso, t >= 1]); // eslint-disable-line

  const nodes: NodoFlujo[] = useMemo(() => nodos.map((n) => ({
    id: n.id, type: 'red', position: { x: n.x, y: n.y },
    selected: seleccion?.tipo === 'nodo' && seleccion.id === n.id,
    data: { nodo: n, conectable: diseno, recibe: receptores.has(n.id) },
  })), [nodos, seleccion, diseno, receptores]);

  const edges: AristaFlujo[] = useMemo(() => enlaces.map((e) => ({
    id: e.id, type: 'enlace', source: e.a.nodo, target: e.b.nodo, sourceHandle: 's', targetHandle: 't',
    selected: seleccion?.tipo === 'enlace' && seleccion.id === e.id,
    data: { enlace: e },
  })), [enlaces, seleccion]);

  const alCambiarNodos = useCallback((cambios: NodeChange<NodoFlujo>[]) => {
    for (const c of cambios) {
      if (c.type === 'position' && c.position) moverNodo(c.id, Math.round(c.position.x), Math.round(c.position.y));
      if (c.type === 'select' && c.selected) seleccionar({ tipo: 'nodo', id: c.id });
    }
  }, [moverNodo, seleccionar]);

  const alConectar = useCallback((c: Connection) => {
    if (c.source && c.target) conectar(c.source, c.target);
  }, [conectar]);

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
        onConnect={alConectar}
        onEdgeClick={(_, e) => seleccionar({ tipo: 'enlace', id: e.id })}
        onPaneClick={() => seleccionar(null)}
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
