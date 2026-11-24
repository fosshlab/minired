import { useEffect, useState } from 'react';
import { api, ErrorApi } from '../api/cliente';
import type { CapaOsi, Decision, Fuente, Observacion, VistaOsi } from '../api/tipos';
import { useLab } from '../estado/labStore';
import { useSimulacion } from '../estado/simulacionStore';
import { etiquetaSimple, nombresDe } from './simple';

// Ventana del PDU del modo simple, como la de Packet Tracer: pestaña "Modelo OSI" con las capas de
// entrada y de salida del dispositivo y las decisiones explicadas, y pestaña de detalle de la PDU.
// Todo sale del tráfico real capturado; cada decisión dice de dónde se sabe.

const CAPAS = [7, 6, 5, 4, 3, 2, 1];
const NOMBRE_CAPA: Record<number, string> = {
  7: 'Aplicación', 6: 'Presentación', 5: 'Sesión', 4: 'Transporte', 3: 'Red', 2: 'Enlace', 1: 'Física',
};
export const FUENTE: Record<Fuente, { texto: string; ayuda: string }> = {
  observado: { texto: 'observado', ayuda: 'Está en la captura: se vio pasar.' },
  configuracion: { texto: 'configuración', ayuda: 'Lo declara el laboratorio (VLAN, ACL, servicios).' },
  estado: { texto: 'estado', ayuda: 'Leído del equipo al iniciar o detener la captura (tabla de rutas, tabla MAC).' },
  inferido: { texto: 'inferido', ayuda: 'Lo implica el funcionamiento estándar; no se puede leer en ese instante.' },
};
const RESULTADO: Record<VistaOsi['resultado'], string> = {
  inundado: 'Inunda', reenviado: 'Reenvía', traducido: 'Traduce (NAT) y reenvía', entregado: 'Lo recibe',
  respondido: 'Lo recibe y responde', descartado: 'Descarta', sin_salida: 'No se observó salida',
};

const cache = new Map<string, VistaOsi>();

function TablaCapas({ entrada, salida, tituloEntrada, tituloSalida }: {
  entrada: CapaOsi[] | null; salida: CapaOsi[] | null; tituloEntrada: string; tituloSalida: string;
}) {
  const celda = (capas: CapaOsi[] | null, n: number) => {
    const c = (capas ?? []).filter((x) => x.capa === n);
    return c.length ? c.map((x) => <div key={x.nombre}><b>{x.nombre}</b> {x.texto}</div>) : <span className="tenue">—</span>;
  };
  return (
    <table className="tabla-osi">
      <thead><tr><th>Capa</th><th>{tituloEntrada}</th><th>{tituloSalida}</th></tr></thead>
      <tbody>
        {CAPAS.map((n) => (
          <tr key={n} className={(entrada ?? []).some((x) => x.capa === n) || (salida ?? []).some((x) => x.capa === n) ? '' : 'vacia'}>
            <td className="capa-n">{n} {NOMBRE_CAPA[n]}</td>
            <td>{entrada ? celda(entrada, n) : <span className="tenue">—</span>}</td>
            <td>{salida ? celda(salida, n) : <span className="tenue">—</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Decisiones({ lista }: { lista: Decision[] }) {
  return (
    <ol className="decisiones">
      {lista.map((d) => (
        <li key={d.n}>
          <span className="capa-chip">Capa {d.capa}</span> {d.texto}{' '}
          <span className={`fuente fuente-${d.fuente}`} title={FUENTE[d.fuente].ayuda}>{FUENTE[d.fuente].texto}</span>
        </li>
      ))}
    </ol>
  );
}

function Campos({ o }: { o: Observacion | undefined }) {
  if (!o) return <p className="tenue">—</p>;
  const r = o.resumen;
  const filas: [string, string][] = [];
  if (r.eth) filas.push(['Ethernet', `origen ${r.eth.src} · destino ${r.eth.dst} · tipo ${r.eth.tipo}`]);
  if (r.vlan) filas.push(['802.1Q', `VLAN ${r.vlan.id} · prioridad ${r.vlan.pcp}`]);
  if (r.arp) filas.push(['ARP', `${r.arp.op === 1 ? 'solicitud' : 'respuesta'} · MAC origen ${r.arp.sha} · IP origen ${r.arp.spa} · MAC buscada ${r.arp.tha} · IP buscada ${r.arp.tpa}`]);
  if (r.ip) filas.push(['IPv4', `origen ${r.ip.src} · destino ${r.ip.dst} · TTL ${r.ip.ttl} · protocolo ${r.ip.proto} · id ${r.ip.id}`]);
  if (r.icmp) filas.push(['ICMP', `tipo ${r.icmp.tipo} · código ${r.icmp.codigo}${r.icmp.seq !== undefined ? ` · id ${r.icmp.ident} · secuencia ${r.icmp.seq}` : ''}`]);
  if (r.udp) filas.push(['UDP', `puerto origen ${r.udp.sport} · puerto destino ${r.udp.dport}`]);
  if (r.tcp) filas.push(['TCP', `puerto origen ${r.tcp.sport} · puerto destino ${r.tcp.dport} · banderas ${r.tcp.banderas}`]);
  if (r.dhcp) filas.push(['DHCP', `tipo ${r.dhcp.tipo} · xid ${r.dhcp.xid} · IP ${r.dhcp.yiaddr} · cliente ${r.dhcp.chaddr}`]);
  if (r.dns) filas.push(['DNS', `${r.dns.respuesta ? 'respuesta' : 'consulta'} ${r.dns.nombre ?? ''}${r.dns.respuestas?.length ? ' → ' + r.dns.respuestas.join(', ') : ''}`]);
  if (r.http) filas.push(['HTTP', r.http.linea]);
  return <dl className="campos-pdu">{filas.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>;
}

export function PanelOsi() {
  const seleccion = useSimulacion((s) => s.seleccion);
  const observaciones = useSimulacion((s) => s.observaciones);
  const { elegir, setVista } = useSimulacion();
  const { nodos, enlaces } = useLab();
  const [vista, setDatos] = useState<VistaOsi | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pestana, setPestana] = useState<'osi' | 'pdu'>('osi');
  const [salida, setSalida] = useState(0);
  const [verOrigen, setVerOrigen] = useState(false);

  useEffect(() => {
    if (!seleccion) return;
    let vigente = true;
    setError(null);
    setSalida(0);
    setVerOrigen(false);
    const guardada = cache.get(seleccion);
    if (guardada) { setDatos(guardada); return; }
    setDatos(null);
    api.get<VistaOsi>(`/api/captura/observaciones/${seleccion}/osi`)
      .then((d) => { if (!vigente) return; if (!useLab.getState().captura?.activa) cache.set(seleccion, d); setDatos(d); })
      .catch((e) => vigente && setError(e instanceof ErrorApi ? e.message : String(e)));
    return () => { vigente = false; };
  }, [seleccion]);

  const obs = observaciones.find((o) => o.id === seleccion);
  if (!seleccion || !obs) return null;
  const nombres = nombresDe({ version: 1, nodos, enlaces }, observaciones);
  const actual = vista?.salidas[salida];
  const hijo = actual ? observaciones.find((o) => o.id === actual.obs) : undefined;
  return (
    <div className="panel-osi">
      <div className="capas-cabecera">
        <h3>{vista ? <>En <b>{vista.nombre}</b> <span className="tenue">(llega desde {vista.desde_nombre})</span></> : 'Paquete'}</h3>
        <button className="cerrar" onClick={() => elegir(null)} aria-label="Cerrar detalle">✕</button>
      </div>
      <p className="etiqueta-pdu">{etiquetaSimple(obs, nombres)} <span className="tenue">· paquete {obs.paquete}</span></p>
      <nav className="pestanas-osi" role="tablist">
        <button role="tab" aria-selected={pestana === 'osi'} className={pestana === 'osi' ? 'activa' : ''} onClick={() => setPestana('osi')}>Modelo OSI</button>
        <button role="tab" aria-selected={pestana === 'pdu'} className={pestana === 'pdu' ? 'activa' : ''} onClick={() => setPestana('pdu')}>Detalle de la PDU</button>
      </nav>
      {error && <p className="aviso">{error}</p>}
      {!vista && !error && <p className="tenue">Interpretando la captura…</p>}
      {vista && pestana === 'osi' && !verOrigen && (
        <>
          {vista.salidas.length > 1 && (
            <div className="fila salidas">
              Salida por:
              {vista.salidas.map((s, i) => (
                <button key={s.obs} className={i === salida ? 'activo' : ''} onClick={() => setSalida(i)}>{s.intf} → {s.hacia_nombre}</button>
              ))}
            </div>
          )}
          <TablaCapas entrada={vista.entrada} salida={actual?.capas ?? null}
            tituloEntrada="Capas de entrada" tituloSalida={actual ? 'Capas de salida' : 'Capas de salida (no sale)'} />
          <p className={`resultado resultado-${vista.resultado}`}>{RESULTADO[vista.resultado]}</p>
          <Decisiones lista={vista.decisiones} />
          <div className="fila navegar">
            {vista.origen && <button onClick={() => setVerOrigen(true)}>◀ Dónde nace: {vista.origen.nombre}</button>}
            {vista.salidas.map((s) => (
              <button key={s.obs} onClick={() => elegir(s.obs)}>Siguiente salto: {s.hacia_nombre} ▶</button>
            ))}
          </div>
        </>
      )}
      {vista && pestana === 'osi' && verOrigen && vista.origen && (
        <>
          <p>El paquete nace en <b>{vista.origen.nombre}</b>:</p>
          <TablaCapas entrada={null} salida={vista.origen.salida} tituloEntrada="Capas de entrada" tituloSalida="Capas de salida" />
          <Decisiones lista={vista.origen.decisiones} />
          <button onClick={() => setVerOrigen(false)}>Volver a {vista.nombre}</button>
        </>
      )}
      {vista && pestana === 'pdu' && (
        <div className="pdu">
          <h4>PDU de entrada (en {vista.nombre})</h4>
          <Campos o={obs} />
          <h4>PDU de salida{actual ? ` (por ${actual.intf})` : ''}</h4>
          {actual ? <Campos o={hijo} /> : <p className="tenue">No se observó una salida para este paquete.</p>}
        </div>
      )}
      <p className="nota-osi tenue">
        Tráfico real capturado. Las decisiones se explican con lo observado, la configuración del laboratorio
        {vista?.estado_red.length ? ' y el estado leído de los equipos al ' + vista.estado_red.map((m) => (m === 'inicio' ? 'iniciar' : 'detener')).join(' y ') + ' la captura' : ''}.
      </p>
      <button className="chico" onClick={() => { setVista('avanzado'); elegir(obs.id); }}>Ver capas completas de tshark (Avanzado)</button>
    </div>
  );
}
