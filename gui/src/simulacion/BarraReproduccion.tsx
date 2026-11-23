import { useEffect } from 'react';
import { useSimulacion } from '../estado/simulacionStore';
import type { Filtro } from './reproductor';

// Bucle de animación: avanza el paso actual con requestAnimationFrame.
export function useBucleAnimacion() {
  useEffect(() => {
    let previo = performance.now();
    let id = requestAnimationFrame(function cuadro(ahora) {
      const s = useSimulacion.getState();
      if (s.activo) s.avanzar(Math.min(100, ahora - previo));
      previo = ahora;
      id = requestAnimationFrame(cuadro);
    });
    return () => cancelAnimationFrame(id);
  }, []);
}

const VELOCIDADES = [0.25, 0.5, 1, 2, 4];

export function BarraReproduccion() {
  const { pasos, cursor, modo, velocidad, filtro, descartadasVista, play, pausa, siguiente, anterior, irA, setVelocidad, setFiltro } = useSimulacion();
  const total = pasos.length;
  return (
    <div className="barra-repro" role="toolbar" aria-label="Reproducción">
      <span className="etiqueta-repro" title="Los paquetes ya circularon de verdad: esto reproduce lo capturado">Reproducción de la captura</span>
      <button onClick={() => irA(-1)} title="Al principio" aria-label="Al principio">⏮</button>
      <button onClick={anterior} title="Paso anterior" aria-label="Paso anterior">◀</button>
      {modo === 'play'
        ? <button onClick={pausa} title="Pausa" aria-label="Pausa">⏸</button>
        : <button onClick={play} title="Reproducir" aria-label="Reproducir" disabled={!total}>▶</button>}
      <button onClick={siguiente} title="Paso siguiente" aria-label="Paso siguiente" disabled={cursor >= total - 1}>⏭</button>
      <input type="range" min={-1} max={Math.max(total - 1, -1)} value={cursor} aria-label="Línea de tiempo"
        onChange={(e) => irA(Number(e.target.value))} disabled={!total} />
      <span className="contador">Paso {cursor + 1} / {total}</span>
      <label>Velocidad
        <select value={velocidad} onChange={(e) => setVelocidad(Number(e.target.value))}>
          {VELOCIDADES.map((v) => <option key={v} value={v}>{v}×</option>)}
        </select>
      </label>
      <label>Mostrar
        <select value={filtro} onChange={(e) => setFiltro(e.target.value as Filtro)}>
          <option value="todos">todo</option>
          <option value="arp">ARP</option>
          <option value="icmp">ICMP</option>
          <option value="ip">IPv4</option>
          <option value="otros">otros</option>
        </select>
      </label>
      {descartadasVista > 0 && (
        <span className="aviso-perdidas" title="Siguen en el PCAP descargable">
          {descartadasVista} observaciones no entran en la vista
        </span>
      )}
    </div>
  );
}
