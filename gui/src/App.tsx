import { useEffect, useRef } from 'react';
import { ReactFlowProvider } from '@xyflow/react';
import { api, ErrorApi, token } from './api/cliente';
import type { Evento, Lab, Observacion } from './api/tipos';
import { conectarEventos } from './api/ws';
import { ejemplo3Pc, useLab } from './estado/labStore';
import { usePanel } from './estado/panelStore';
import { useSimulacion } from './estado/simulacionStore';
import { Lienzo } from './editor/Lienzo';
import { Paleta } from './editor/Paleta';
import { PanelPropiedades } from './editor/PanelPropiedades';
import { BarraReproduccion, useBucleAnimacion } from './simulacion/BarraReproduccion';
import { ListaEventos } from './simulacion/ListaEventos';
import { PanelCapas } from './simulacion/PanelCapas';
import { TerminalNodo } from './terminal/TerminalNodo';

function procesarEvento(e: Evento) {
  const lab = useLab.getState();
  const sim = useSimulacion.getState();
  if (e.tipo === 'estado') {
    const antes = lab.estadoRed;
    useLab.setState({ estadoRed: e.estado, errorRed: e.error, captura: e.captura });
    if (e.estado !== 'activa' && antes === 'activa') usePanel.getState().cerrarTodas();
    if (e.estado === 'diseño' || e.estado === 'error') sim.setActivo(false);
    else if (e.captura?.activa) sim.setActivo(true);
  } else if (e.tipo === 'observaciones') {
    if (e.reinicio) sim.reemplazar(e.items);
    else sim.agregar(e.items, e.descartadas_vista);
  } else if (e.tipo === 'captura') {
    const { tipo: _t, reinicio, ...estado } = e;
    useLab.setState({ captura: estado });
    if (reinicio) sim.reiniciar();
  } else if (e.tipo === 'aviso') {
    // Se perdieron eventos en vivo: se recarga la lista completa (el PCAP no pierde nada).
    api.get<{ items: Observacion[] }>('/api/captura/observaciones')
      .then((r) => sim.reemplazar(r.items)).catch(() => {});
  }
}

export function App() {
  const { estadoRed, errorRed, captura, conectado, mensaje, avisar, lab, cargar } = useLab();
  const simActivo = useSimulacion((s) => s.activo);
  const { terminales, pestana, setPestana, cerrarTerminal } = usePanel();
  const nodos = useLab((s) => s.nodos);
  const seleccionObs = useSimulacion((s) => s.seleccion);
  const archivo = useRef<HTMLInputElement>(null);
  useBucleAnimacion();

  useEffect(() => conectarEventos(procesarEvento, (c) => useLab.setState({ conectado: c })), []);

  const manejar = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
    } catch (e) {
      if (e instanceof ErrorApi) avisar(e.message, 'error', e.errores);
      else avisar(String(e));
    }
  };

  const iniciar = () => manejar(async () => {
    useLab.setState({ mensaje: null });
    await api.put('/api/lab', lab());
    await api.post('/api/red/iniciar');
  });
  const detener = () => manejar(() => api.post('/api/red/detener'));
  const alternarSimulacion = () => manejar(async () => {
    if (!simActivo) {
      useSimulacion.getState().setActivo(true);
      useSimulacion.getState().play();
      if (!captura?.activa) await api.post('/api/captura/iniciar');
    } else {
      if (captura?.activa) await api.post('/api/captura/detener');
      useSimulacion.getState().setActivo(false);
    }
  });

  const guardarJson = () => {
    const blob = new Blob([JSON.stringify(lab(), null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'laboratorio.minired.json';
    a.click();
  };
  const abrirJson = async (f: File) => manejar(async () => {
    const datos = JSON.parse(await f.text()) as Lab;
    const r = await api.post<{ ok: boolean; errores: string[] }>('/api/lab/validar', datos);
    if (!r.ok) throw new ErrorApi('El archivo no es un laboratorio válido', 422, r.errores);
    cargar(datos);
  });

  const diseno = estadoRed === 'diseño' || estadoRed === 'error';
  const nombre = (id: string) => nodos.find((n) => n.id === id)?.nombre ?? id;

  if (!token) {
    return <div className="sin-token">Abrí la dirección completa que mostró <code>sudo minired gui</code> (incluye <code>#token=…</code>).</div>;
  }

  return (
    <div className="app">
      <header className="barra">
        <span className="marca">minired</span>
        <div className="grupo">
          <button disabled={!diseno} onClick={() => cargar({ version: 1, nodos: [], enlaces: [] })}>Nuevo</button>
          <button disabled={!diseno} onClick={() => cargar(ejemplo3Pc)}>Ejemplo: 3 PC + switch</button>
          <button disabled={!diseno} onClick={() => archivo.current?.click()}>Abrir…</button>
          <button onClick={guardarJson}>Guardar</button>
          <input ref={archivo} type="file" accept=".json,application/json" hidden
            onChange={(e) => { const f = e.target.files?.[0]; if (f) abrirJson(f); e.target.value = ''; }} />
        </div>
        <div className="grupo">
          <span className={`estado estado-${estadoRed}`}>Red: {estadoRed}</span>
          {diseno
            ? <button className="primario" onClick={iniciar}>▶ Iniciar red</button>
            : <button onClick={detener} disabled={estadoRed !== 'activa'}>■ Detener red</button>}
          <button className={simActivo ? 'sim-on' : ''} disabled={estadoRed !== 'activa'} onClick={alternarSimulacion}
            aria-pressed={simActivo} title="Captura el tráfico real en cada extremo de cada enlace y lo reproduce paso a paso">
            {simActivo ? (captura?.activa ? '● Simulación: capturando' : 'Simulación (captura detenida)') : 'Simulación'}
          </button>
          <button disabled={!captura} onClick={() => manejar(() => api.descargar('/api/captura/pcap', 'minired-captura.pcapng'))}>
            Descargar PCAP
          </button>
        </div>
        {!conectado && <span className="desconectado">sin conexión con el servidor…</span>}
      </header>

      {(mensaje || errorRed) && (
        <div className={`mensaje mensaje-${mensaje?.tipo ?? 'error'}`} role="alert">
          <span>{mensaje?.texto ?? errorRed}</span>
          {mensaje?.detalles?.length ? <ul>{mensaje.detalles.map((d) => <li key={d}>{d}</li>)}</ul> : null}
          <button className="cerrar" onClick={() => useLab.setState({ mensaje: null, errorRed: null })} aria-label="Cerrar">✕</button>
        </div>
      )}

      <main className="centro">
        <Paleta />
        <ReactFlowProvider><Lienzo /></ReactFlowProvider>
        <aside className="lateral">{seleccionObs ? <PanelCapas /> : <PanelPropiedades />}</aside>
      </main>

      <section className="inferior">
        <nav className="pestanas">
          <button className={pestana === 'eventos' ? 'activa' : ''} onClick={() => setPestana('eventos')}>
            Eventos {captura ? `(${captura.observaciones})` : ''}
          </button>
          {terminales.map((t) => (
            <span key={t} className={`pestana-term ${pestana === t ? 'activa' : ''}`}>
              <button onClick={() => setPestana(t)}>Terminal {nombre(t)}</button>
              <button className="cerrar" onClick={() => cerrarTerminal(t)} aria-label={`Cerrar terminal ${nombre(t)}`}>✕</button>
            </span>
          ))}
        </nav>
        <div className="contenido-inferior">
          <div style={{ display: pestana === 'eventos' ? 'flex' : 'none' }} className="eventos">
            {simActivo && <BarraReproduccion />}
            <ListaEventos />
          </div>
          {terminales.map((t) => <TerminalNodo key={t} nodo={t} visible={pestana === t} />)}
        </div>
      </section>
    </div>
  );
}
