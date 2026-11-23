import { useState } from 'react';
import { api, ErrorApi } from '../api/cliente';
import type { Nodo } from '../api/tipos';
import { nombreIntf, useLab } from '../estado/labStore';
import { usePanel } from '../estado/panelStore';
import { NOMBRE_TIPO } from './iconos';

export function PanelPropiedades() {
  const { seleccion, nodos, enlaces, estadoRed } = useLab();
  if (!seleccion) {
    return (
      <div className="panel-vacio">
        <p>Elegí un equipo o un enlace para ver sus datos.</p>
        <p className="tenue">Flujo: armá la red → <b>Iniciar red</b> → abrí terminales → activá <b>Simulación</b> y hacé un <code>ping -c 1</code>.</p>
      </div>
    );
  }
  if (seleccion.tipo === 'enlace') {
    const e = enlaces.find((x) => x.id === seleccion.id);
    if (!e) return null;
    return <PanelEnlace id={e.id} />;
  }
  const nodo = nodos.find((n) => n.id === seleccion.id);
  if (!nodo) return null;
  return estadoRed === 'diseño' || estadoRed === 'error' ? <EditarNodo nodo={nodo} /> : <NodoActivo nodo={nodo} />;
}

function puertosConectados(nodo: Nodo, enlaces: ReturnType<typeof useLab.getState>['enlaces']) {
  return enlaces.flatMap((e) => [e.a, e.b]).filter((x) => x.nodo === nodo.id).map((x) => x.puerto).sort((a, b) => a - b);
}

function EditarNodo({ nodo }: { nodo: Nodo }) {
  const { enlaces, actualizarNodo, ponerIp, borrarSeleccion } = useLab();
  const puertos = nodo.tipo === 'pc' ? [0] : puertosConectados(nodo, enlaces);
  return (
    <div className="propiedades">
      <h3>{NOMBRE_TIPO[nodo.tipo]} {nodo.nombre}</h3>
      <label>Nombre
        <input value={nodo.nombre} maxLength={8} spellCheck={false}
          onChange={(e) => actualizarNodo(nodo.id, { nombre: e.target.value.toLowerCase() })} />
      </label>
      <p className="tenue">Minúsculas y números, hasta 8, empezando por letra.</p>
      {nodo.tipo !== 'switch' && puertos.map((p) => (
        <label key={p}>IP de {nombreIntf(nodo, p)}
          <input placeholder="10.0.0.1/24" spellCheck={false}
            value={nodo.interfaces.find((i) => i.puerto === p)?.ip ?? ''}
            onChange={(e) => ponerIp(nodo.id, p, e.target.value)} />
        </label>
      ))}
      {nodo.tipo === 'router' && puertos.length === 0 && <p className="tenue">Conectá el router para configurar sus interfaces.</p>}
      {nodo.tipo === 'pc' && (
        <label>Gateway (opcional)
          <input placeholder="10.0.0.254" spellCheck={false} value={nodo.gateway ?? ''}
            onChange={(e) => actualizarNodo(nodo.id, { gateway: e.target.value.trim() || null })} />
        </label>
      )}
      {nodo.tipo === 'switch' && <p className="tenue">Switch Open vSwitch en modo bridge (aprende MAC, sin controlador ni STP).</p>}
      <button className="peligro" onClick={borrarSeleccion}>Eliminar {nodo.nombre}</button>
    </div>
  );
}

function NodoActivo({ nodo }: { nodo: Nodo }) {
  const abrirTerminal = usePanel((s) => s.abrirTerminal);
  const avisar = useLab((s) => s.avisar);
  const [destino, setDestino] = useState('');
  const [salida, setSalida] = useState<string | null>(null);
  const [ocupado, setOcupado] = useState(false);
  const hacerPing = async () => {
    setOcupado(true);
    try {
      const r = await api.post<{ codigo: number; salida: string }>(`/api/nodos/${nodo.id}/ping`, { destino: destino.trim(), cantidad: 1 });
      setSalida(r.salida);
    } catch (e) {
      avisar(e instanceof ErrorApi ? e.message : String(e));
    } finally {
      setOcupado(false);
    }
  };
  return (
    <div className="propiedades">
      <h3>{NOMBRE_TIPO[nodo.tipo]} {nodo.nombre}</h3>
      {nodo.interfaces.filter((i) => i.ip).map((i) => (
        <p key={i.puerto}><code>{nombreIntf(nodo, i.puerto)}</code> {i.ip}</p>
      ))}
      {nodo.gateway && <p>Gateway <code>{nodo.gateway}</code></p>}
      {nodo.tipo === 'switch' ? (
        <p className="tenue">El switch vive en el espacio de red del sistema: no tiene terminal propia.</p>
      ) : (
        <>
          <button className="primario" onClick={() => abrirTerminal(nodo.id)}>Abrir terminal de {nodo.nombre}</button>
          <form className="fila" onSubmit={(e) => { e.preventDefault(); hacerPing(); }}>
            <input placeholder="IP destino" value={destino} onChange={(e) => setDestino(e.target.value)} spellCheck={false} />
            <button disabled={ocupado || !destino.trim()}>ping -c 1</button>
          </form>
          {salida && <pre className="salida">{salida}</pre>}
        </>
      )}
    </div>
  );
}

function PanelEnlace({ id }: { id: string }) {
  const { enlaces, nodos, estadoRed, borrarSeleccion, avisar } = useLab();
  const e = enlaces.find((x) => x.id === id)!;
  const a = nodos.find((n) => n.id === e.a.nodo);
  const b = nodos.find((n) => n.id === e.b.nodo);
  const activa = estadoRed === 'activa';
  const cambiar = async (arriba: boolean) => {
    try {
      await api.post(`/api/enlaces/${id}/estado`, { arriba });
      avisar(`Enlace ${id} ${arriba ? 'levantado' : 'bajado'}`, 'info');
    } catch (err) {
      avisar(err instanceof ErrorApi ? err.message : String(err));
    }
  };
  return (
    <div className="propiedades">
      <h3>Enlace {id}</h3>
      <p><code>{nombreIntf(a, e.a.puerto)}</code> ↔ <code>{nombreIntf(b, e.b.puerto)}</code></p>
      <p className="tenue">Par veth. En simulación se captura lo que llega a cada extremo.</p>
      {activa ? (
        <div className="fila">
          <button onClick={() => cambiar(false)}>Bajar enlace</button>
          <button onClick={() => cambiar(true)}>Subir enlace</button>
        </div>
      ) : (
        estadoRed !== 'iniciando' && estadoRed !== 'deteniendo' && <button className="peligro" onClick={borrarSeleccion}>Eliminar enlace</button>
      )}
    </div>
  );
}
