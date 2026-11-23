import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { subprotocolos, urlWs } from '../api/cliente';

// Terminal de un nodo: bash con PTY dentro de su namespace de red (WS /ws/terminal/<id>).
export function TerminalNodo({ nodo, visible }: { nodo: string; visible: boolean }) {
  const caja = useRef<HTMLDivElement>(null);
  const ajustar = useRef<() => void>(() => {});
  const [estado, setEstado] = useState('conectando…');

  useEffect(() => {
    const term = new Terminal({
      fontFamily: 'ui-monospace, "DejaVu Sans Mono", monospace', fontSize: 14, cursorBlink: true,
      theme: { background: '#111827' }, scrollback: 3000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(caja.current!);
    const ws = new WebSocket(urlWs(`/ws/terminal/${nodo}`), subprotocolos);
    ws.binaryType = 'arraybuffer';
    const codificador = new TextEncoder();
    const enviarTam = () => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ tipo: 'resize', filas: term.rows, columnas: term.cols }));
    };
    ajustar.current = () => {
      try { fit.fit(); } catch { /* oculta */ }
      enviarTam();
    };
    ws.onopen = () => { setEstado(''); ajustar.current(); term.focus(); };
    ws.onmessage = (m) => term.write(new Uint8Array(m.data as ArrayBuffer));
    ws.onclose = (e) => {
      setEstado(e.reason ? `cerrada: ${e.reason}` : 'terminal cerrada');
      term.write('\r\n\x1b[33m[terminal cerrada]\x1b[0m\r\n');
    };
    const datos = term.onData((d) => ws.readyState === WebSocket.OPEN && ws.send(codificador.encode(d)));
    const obs = new ResizeObserver(() => ajustar.current());
    obs.observe(caja.current!);
    return () => {
      obs.disconnect();
      datos.dispose();
      ws.close();
      term.dispose();
    };
  }, [nodo]);

  useEffect(() => {
    if (visible) setTimeout(() => ajustar.current(), 0);
  }, [visible]);

  return (
    <div className="terminal" style={{ display: visible ? 'flex' : 'none' }}>
      {estado && <div className="terminal-estado">{estado}</div>}
      <div className="terminal-caja" ref={caja} />
    </div>
  );
}
