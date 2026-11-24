import { useEffect } from 'react';
import { useSimulacion } from '../estado/simulacionStore';
import { compilarFiltro, ErrorFiltro } from './filtroWireshark';
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
  const { pasos, cursor, modo, velocidad, filtro, descartadasVista, play, pausa, siguiente, anterior, irA, setVelocidad, setFiltro,
    vista, setVista, fondo, setFondo, filtroWs, setFiltroWs } = useSimulacion();
  const total = pasos.length;
  let errorFiltro: string | null = null;
  try { compilarFiltro(filtroWs); } catch (e) { errorFiltro = e instanceof ErrorFiltro ? e.message : String(e); }
  return (
    <div className="barra-repro" role="toolbar" aria-label="Reproducción">
      <div className="selector-vista" role="radiogroup" aria-label="Vista">
        <button role="radio" aria-checked={vista === 'simple'} className={vista === 'simple' ? 'activo' : ''}
          title="Estilo Packet Tracer: un sobre por salto, modelo OSI y decisiones explicadas" onClick={() => setVista('simple')}>Simple</button>
        <button role="radio" aria-checked={vista === 'avanzado'} className={vista === 'avanzado' ? 'activo' : ''}
          title="Estilo Wireshark: cada captura, tiempos, correlación, capas de tshark y filtro" onClick={() => setVista('avanzado')}>Avanzado</button>
      </div>
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
{vista === 'simple' ? (
        <>
                <label>Mostrar
            <select value={filtro} onChange={(e) => setFiltro(e.target.value as Filtro)}>
              <option value="todos">todo</option>
              <option value="arp">ARP</option>
              <option value="icmp">ICMP</option>
              <option value="ip">IPv4</option>
              <option value="dhcp">DHCP</option>
              <option value="dns">DNS</option>
              <option value="http">HTTP</option>
              <option value="ospf">OSPF</option>
              <option value="otros">otros</option>
            </select>
          </label>
          <label title="Hello de OSPF, verificaciones ARP que Linux hace solo, IPv6">
            <input type="checkbox" checked={fondo} onChange={(e) => setFondo(e.target.checked)} />
            Tráfico de fondo
          </label>
        </>
      ) : (
        <label className="filtro-ws">Filtro
          <input value={filtroWs} spellCheck={false} placeholder="p. ej. icmp && ip.addr == 10.0.0.2"
            aria-label="Filtro estilo Wireshark" aria-invalid={!!errorFiltro} className={errorFiltro ? 'invalido' : filtroWs ? 'valido' : ''}
            onChange={(e) => setFiltroWs(e.target.value)} title={errorFiltro ?? 'Sintaxis de Wireshark: arp, icmp, ip.addr == x, vlan.id == 10, tcp.port == 80, !, &&, ||'} />
          {errorFiltro && <span className="aviso-perdidas">{errorFiltro}</span>}
        </label>
      )}
      {descartadasVista > 0 && (
        <span className="aviso-perdidas" title="Siguen en el PCAP descargable">
          {descartadasVista} observaciones no entran en la vista
        </span>
      )}
    </div>
  );
}
