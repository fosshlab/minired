import type { Evento } from './tipos';
import { subprotocolos, urlWs } from './cliente';

// WebSocket de eventos con reconexión y espera creciente.
export function conectarEventos(alRecibir: (e: Evento) => void, alCambiar: (conectado: boolean) => void) {
  let ws: WebSocket | null = null;
  let espera = 500;
  let cerrado = false;
  let temporizador: number | undefined;

  const abrir = () => {
    ws = new WebSocket(urlWs('/ws/eventos'), subprotocolos);
    ws.onopen = () => { espera = 500; alCambiar(true); };
    ws.onmessage = (m) => {
      try { alRecibir(JSON.parse(m.data) as Evento); } catch { /* mensaje inválido */ }
    };
    ws.onclose = () => {
      alCambiar(false);
      if (cerrado) return;
      temporizador = window.setTimeout(abrir, espera);
      espera = Math.min(espera * 2, 8000);
    };
  };
  abrir();
  return () => {
    cerrado = true;
    window.clearTimeout(temporizador);
    ws?.close();
  };
}
