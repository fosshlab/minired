import { useState } from 'react';
import { api, ErrorApi } from '../api/cliente';
import type { Diagnostico, Interfaz, Nodo, ReglaACL, Servicios } from '../api/tipos';
import { interfazDe, nombreIntf, useLab } from '../estado/labStore';
import { enlacesAfectados, textoConfirmacion } from '../estado/seleccion';
import { usePanel } from '../estado/panelStore';
import { NOMBRE_TIPO } from './iconos';

export function PanelPropiedades() {
  const { seleccion, marcados, nodos, enlaces, estadoRed } = useLab();
  if (marcados.nodos.length + marcados.enlaces.length > 1) return <PanelVarios />;
  if (!seleccion) {
    return (
      <div className="panel-vacio">
        <p>Elegí un equipo o un enlace para ver sus datos.</p>
        <p className="tenue">Flujo: armá la red → <b>Iniciar red</b> → abrí terminales → activá <b>Simulación</b> y hacé un <code>ping -c 1</code>.</p>
        <p className="tenue">¿Primera vez? Probá uno de los <b>Ejemplos</b> de la barra superior.</p>
        <p className="tenue">Para elegir varios equipos, arrastrá en el fondo del lienzo un rectángulo, o usá Shift/Ctrl+clic.</p>
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
  // key: cada nodo con su propio estado (salidas de ping, diagnóstico, textos en edición).
  return estadoRed === 'diseño' || estadoRed === 'error'
    ? <EditarNodo key={nodo.id} nodo={nodo} /> : <NodoActivo key={nodo.id} nodo={nodo} />;
}

function puertosConectados(nodo: Nodo, enlaces: ReturnType<typeof useLab.getState>['enlaces']) {
  return enlaces.flatMap((e) => [e.a, e.b]).filter((x) => x.nodo === nodo.id).map((x) => x.puerto).sort((a, b) => a - b);
}

// Lista de números "10, 20 30" -> [10, 20, 30]; null si queda vacía.
function numeros(texto: string): number[] | null {
  const r = texto.split(/[\s,;]+/).filter(Boolean).map(Number).filter((n) => Number.isInteger(n));
  return r.length ? r : null;
}

function Campo({ titulo, valor, cambiar, ejemplo, deshabilitado }: {
  titulo: string; valor: string | null | undefined; cambiar: (v: string | null) => void; ejemplo?: string; deshabilitado?: boolean;
}) {
  return (
    <label>{titulo}
      <input placeholder={ejemplo} spellCheck={false} value={valor ?? ''} disabled={deshabilitado}
        onChange={(e) => cambiar(e.target.value.trim() || null)} />
    </label>
  );
}

function EditarNodo({ nodo }: { nodo: Nodo }) {
  const { enlaces, actualizarNodo, borrarSeleccion } = useLab();
  const puertos = nodo.tipo === 'pc' || nodo.tipo === 'servidor' ? [0] : puertosConectados(nodo, enlaces);
  const host = nodo.tipo === 'pc' || nodo.tipo === 'servidor';
  return (
    <div className="propiedades">
      <h3>{NOMBRE_TIPO[nodo.tipo]} {nodo.nombre}</h3>
      <label>Nombre
        <input value={nodo.nombre} maxLength={8} spellCheck={false}
          onChange={(e) => actualizarNodo(nodo.id, { nombre: e.target.value.toLowerCase() })} />
      </label>
      <p className="tenue">Minúsculas y números, hasta 8, empezando por letra.</p>

      {nodo.tipo === 'pc' && (
        <label className="casilla">
          <input type="checkbox" checked={!!nodo.dhcp} onChange={(e) => {
            if (e.target.checked) {
              actualizarNodo(nodo.id, { dhcp: true, gateway: null, interfaces: nodo.interfaces.map((i) => ({ ...i, ip: null })) });
            } else actualizarNodo(nodo.id, { dhcp: false });
          }} />
          Pedir IP por DHCP
        </label>
      )}
      {host && !nodo.dhcp && <IpPuerto nodo={nodo} puerto={0} />}
      {host && !nodo.dhcp && (
        <Campo titulo="Gateway (opcional)" ejemplo="10.0.0.254" valor={nodo.gateway}
          cambiar={(v) => actualizarNodo(nodo.id, { gateway: v })} />
      )}
      {host && !nodo.dhcp && (
        <Campo titulo="Servidor DNS (opcional)" ejemplo="10.0.0.53" valor={nodo.dns}
          cambiar={(v) => actualizarNodo(nodo.id, { dns: v })} />
      )}
      {nodo.tipo === 'servidor' && <EditarServicios nodo={nodo} />}

      {nodo.tipo === 'switch' && (
        <>
          <p className="tenue">Switch Open vSwitch en modo bridge (aprende MAC, sin controlador ni STP).</p>
          {puertos.length === 0 && <p className="tenue">Conectá equipos para configurar sus puertos.</p>}
          {puertos.map((p) => <PuertoSwitch key={p} nodo={nodo} puerto={p} />)}
        </>
      )}

      {nodo.tipo === 'router' && (
        <>
          {puertos.length === 0 && <p className="tenue">Conectá el router para configurar sus interfaces.</p>}
          {puertos.map((p) => <InterfazRouter key={p} nodo={nodo} puerto={p} />)}
          <EditarRouter nodo={nodo} />
        </>
      )}
      <button className="peligro" onClick={borrarSeleccion}>Eliminar {nodo.nombre}</button>
    </div>
  );
}

function IpPuerto({ nodo, puerto }: { nodo: Nodo; puerto: number }) {
  const ponerIp = useLab((s) => s.ponerIp);
  return (
    <Campo titulo={`IP de ${nombreIntf(nodo, puerto)}`} ejemplo="10.0.0.1/24" valor={interfazDe(nodo, puerto).ip}
      cambiar={(v) => ponerIp(nodo.id, puerto, v ?? '')} />
  );
}

function PuertoSwitch({ nodo, puerto }: { nodo: Nodo; puerto: number }) {
  const editar = useLab((s) => s.editarInterfaz);
  const i = interfazDe(nodo, puerto);
  const modo = i.troncal != null ? 'troncal' : i.vlan != null ? 'acceso' : 'todas';
  const [texto, setTexto] = useState((i.troncal ?? []).join(', '));
  return (
    <fieldset className="grupo-campos">
      <legend><code>{nombreIntf(nodo, puerto)}</code></legend>
      <div className="fila">
        <select value={modo} aria-label={`Modo de ${nombreIntf(nodo, puerto)}`} onChange={(e) => {
          const m = e.target.value;
          if (m === 'acceso') editar(nodo.id, puerto, { vlan: i.vlan ?? 10, troncal: null });
          else if (m === 'troncal') { editar(nodo.id, puerto, { vlan: null, troncal: [10, 20] }); setTexto('10, 20'); }
          else editar(nodo.id, puerto, { vlan: null, troncal: null });
        }}>
          <option value="todas">sin VLAN</option>
          <option value="acceso">acceso</option>
          <option value="troncal">troncal 802.1Q</option>
        </select>
        {modo === 'acceso' && (
          <input type="number" min={1} max={4094} aria-label="VLAN" value={i.vlan ?? ''}
            onChange={(e) => editar(nodo.id, puerto, { vlan: e.target.value ? Number(e.target.value) : null })} />
        )}
        {modo === 'troncal' && (
          <input aria-label="VLAN permitidas" placeholder="10, 20" value={texto} spellCheck={false}
            onChange={(e) => { setTexto(e.target.value); editar(nodo.id, puerto, { troncal: numeros(e.target.value) ?? [] }); }} />
        )}
      </div>
    </fieldset>
  );
}

function InterfazRouter({ nodo, puerto }: { nodo: Nodo; puerto: number }) {
  const editar = useLab((s) => s.editarInterfaz);
  const i = interfazDe(nodo, puerto);
  const subs = i.subinterfaces ?? [];
  const cambiar = (c: Partial<Interfaz>) => editar(nodo.id, puerto, c);
  return (
    <fieldset className="grupo-campos">
      <legend><code>{nombreIntf(nodo, puerto)}</code></legend>
      <IpPuerto nodo={nodo} puerto={puerto} />
      {subs.map((s, n) => (
        <div className="fila" key={n}>
          <span className="sufijo">.{' '}</span>
          <input type="number" min={1} max={4094} aria-label="VLAN de la subinterfaz" className="corto" value={s.vlan}
            onChange={(e) => cambiar({ subinterfaces: subs.map((x, k) => (k === n ? { ...x, vlan: Number(e.target.value) } : x)) })} />
          <input placeholder="10.10.0.254/24" aria-label="IP de la subinterfaz" value={s.ip} spellCheck={false}
            onChange={(e) => cambiar({ subinterfaces: subs.map((x, k) => (k === n ? { ...x, ip: e.target.value.trim() } : x)) })} />
          <button className="cerrar" aria-label="Quitar subinterfaz" onClick={() => cambiar({ subinterfaces: subs.filter((_, k) => k !== n) })}>✕</button>
        </div>
      ))}
      <button className="chico" onClick={() => cambiar({ subinterfaces: [...subs, { vlan: 10 + 10 * subs.length, ip: '' }] })}>
        + subinterfaz VLAN (router-on-a-stick)
      </button>
      <label>NAT
        <select value={i.nat ?? ''} onChange={(e) => cambiar({ nat: (e.target.value || null) as Interfaz['nat'] })}>
          <option value="">sin NAT</option>
          <option value="interior">interior (inside)</option>
          <option value="exterior">exterior (outside)</option>
        </select>
      </label>
      <EditarACL reglas={i.acl_entrada ?? []} cambiar={(acl_entrada) => cambiar({ acl_entrada })} />
    </fieldset>
  );
}

function EditarACL({ reglas, cambiar }: { reglas: ReglaACL[]; cambiar: (r: ReglaACL[]) => void }) {
  const poner = (n: number, c: Partial<ReglaACL>) => cambiar(reglas.map((r, k) => (k === n ? { ...r, ...c } : r)));
  return (
    <div className="acl">
      <div className="acl-titulo">ACL de entrada {reglas.length > 0 && <span className="tenue">(en orden; al final: deny any implícito)</span>}</div>
      {reglas.map((r, n) => (
        <div className="acl-regla" key={n}>
          <span className="num">{n + 1}</span>
          <select value={r.accion} aria-label="Acción" onChange={(e) => poner(n, { accion: e.target.value as ReglaACL['accion'] })}>
            <option value="permitir">permitir</option>
            <option value="denegar">denegar</option>
          </select>
          <select value={r.protocolo} aria-label="Protocolo" onChange={(e) => {
            const protocolo = e.target.value as ReglaACL['protocolo'];
            poner(n, { protocolo, puerto: protocolo === 'tcp' || protocolo === 'udp' ? r.puerto : null });
          }}>
            {['ip', 'icmp', 'tcp', 'udp'].map((p) => <option key={p}>{p}</option>)}
          </select>
          <input placeholder="origen (any)" aria-label="Origen" value={r.origen ?? ''} spellCheck={false}
            onChange={(e) => poner(n, { origen: e.target.value.trim() || null })} />
          <input placeholder="destino (any)" aria-label="Destino" value={r.destino ?? ''} spellCheck={false}
            onChange={(e) => poner(n, { destino: e.target.value.trim() || null })} />
          {(r.protocolo === 'tcp' || r.protocolo === 'udp') && (
            <input type="number" min={1} max={65535} placeholder="puerto" aria-label="Puerto destino" className="corto"
              value={r.puerto ?? ''} onChange={(e) => poner(n, { puerto: e.target.value ? Number(e.target.value) : null })} />
          )}
          <button className="cerrar" aria-label="Subir regla" disabled={n === 0}
            onClick={() => { const c = [...reglas]; [c[n - 1], c[n]] = [c[n], c[n - 1]]; cambiar(c); }}>↑</button>
          <button className="cerrar" aria-label="Quitar regla" onClick={() => cambiar(reglas.filter((_, k) => k !== n))}>✕</button>
        </div>
      ))}
      <button className="chico" onClick={() => cambiar([...reglas, { accion: 'permitir', protocolo: 'ip' }])}>+ regla</button>
    </div>
  );
}

function EditarRouter({ nodo }: { nodo: Nodo }) {
  const actualizarNodo = useLab((s) => s.actualizarNodo);
  const rutas = nodo.rutas ?? [];
  return (
    <fieldset className="grupo-campos">
      <legend>Enrutamiento</legend>
      {rutas.map((r, n) => (
        <div className="fila" key={n}>
          <input placeholder="red destino 10.9.0.0/24" aria-label="Red destino" value={r.destino} spellCheck={false}
            onChange={(e) => actualizarNodo(nodo.id, { rutas: rutas.map((x, k) => (k === n ? { ...x, destino: e.target.value.trim() } : x)) })} />
          <input placeholder="vía 10.0.0.2" aria-label="Siguiente salto" value={r.via} spellCheck={false}
            onChange={(e) => actualizarNodo(nodo.id, { rutas: rutas.map((x, k) => (k === n ? { ...x, via: e.target.value.trim() } : x)) })} />
          <button className="cerrar" aria-label="Quitar ruta" onClick={() => actualizarNodo(nodo.id, { rutas: rutas.filter((_, k) => k !== n) })}>✕</button>
        </div>
      ))}
      <button className="chico" onClick={() => actualizarNodo(nodo.id, { rutas: [...rutas, { destino: '', via: '' }] })}>+ ruta estática</button>
      <label className="casilla">
        <input type="checkbox" checked={!!nodo.frr}
          onChange={(e) => actualizarNodo(nodo.id, { frr: e.target.checked, ospf: e.target.checked && !!nodo.ospf })} />
        FRRouting (consola <code>vtysh</code>, parecida a IOS)
      </label>
      <label className="casilla">
        <input type="checkbox" checked={!!nodo.ospf} disabled={!nodo.frr}
          onChange={(e) => actualizarNodo(nodo.id, { ospf: e.target.checked })} />
        OSPF área 0 en todas sus redes
      </label>
    </fieldset>
  );
}

function EditarServicios({ nodo }: { nodo: Nodo }) {
  const actualizarNodo = useLab((s) => s.actualizarNodo);
  const srv: Servicios = nodo.servicios ?? {};
  const poner = (c: Partial<Servicios>) => {
    const nuevo = { ...srv, ...c };
    const vacio = !nuevo.dhcp && !nuevo.dns?.length && !nuevo.http;
    actualizarNodo(nodo.id, { servicios: vacio ? null : nuevo });
  };
  const pool = srv.dhcp;
  const registros = srv.dns ?? [];
  return (
    <fieldset className="grupo-campos">
      <legend>Servicios</legend>
      <label className="casilla">
        <input type="checkbox" checked={!!pool}
          onChange={(e) => poner({ dhcp: e.target.checked ? { desde: '', hasta: '' } : null })} />
        Servidor DHCP (dnsmasq)
      </label>
      {pool && (
        <>
          <div className="fila">
            <input placeholder="desde 10.0.0.100" aria-label="Primera IP del rango" value={pool.desde} spellCheck={false}
              onChange={(e) => poner({ dhcp: { ...pool, desde: e.target.value.trim() } })} />
            <input placeholder="hasta 10.0.0.150" aria-label="Última IP del rango" value={pool.hasta} spellCheck={false}
              onChange={(e) => poner({ dhcp: { ...pool, hasta: e.target.value.trim() } })} />
          </div>
          <div className="fila">
            <input placeholder="gateway (opcional)" aria-label="Gateway que entrega" value={pool.gateway ?? ''} spellCheck={false}
              onChange={(e) => poner({ dhcp: { ...pool, gateway: e.target.value.trim() || null } })} />
            <input placeholder="DNS (opcional)" aria-label="DNS que entrega" value={pool.dns ?? ''} spellCheck={false}
              onChange={(e) => poner({ dhcp: { ...pool, dns: e.target.value.trim() || null } })} />
          </div>
        </>
      )}
      <div className="acl-titulo">Registros DNS</div>
      {registros.map((r, n) => (
        <div className="fila" key={n}>
          <input placeholder="web.lab" aria-label="Nombre" value={r.nombre} spellCheck={false}
            onChange={(e) => poner({ dns: registros.map((x, k) => (k === n ? { ...x, nombre: e.target.value.trim().toLowerCase() } : x)) })} />
          <input placeholder="10.0.0.10" aria-label="IP del nombre" value={r.ip} spellCheck={false}
            onChange={(e) => poner({ dns: registros.map((x, k) => (k === n ? { ...x, ip: e.target.value.trim() } : x)) })} />
          <button className="cerrar" aria-label="Quitar registro" onClick={() => poner({ dns: registros.filter((_, k) => k !== n) })}>✕</button>
        </div>
      ))}
      <button className="chico" onClick={() => poner({ dns: [...registros, { nombre: '', ip: '' }] })}>+ registro DNS</button>
      <label className="casilla">
        <input type="checkbox" checked={!!srv.http} onChange={(e) => poner({ http: e.target.checked })} />
        Servidor HTTP (puerto 80)
      </label>
    </fieldset>
  );
}

function NodoActivo({ nodo }: { nodo: Nodo }) {
  const abrirTerminal = usePanel((s) => s.abrirTerminal);
  const avisar = useLab((s) => s.avisar);
  const [destino, setDestino] = useState('');
  const [salida, setSalida] = useState<string | null>(null);
  const [ocupado, setOcupado] = useState(false);
  const [diag, setDiag] = useState<Diagnostico | null>(null);
  const accion = async (fn: () => Promise<{ salida: string }>) => {
    setOcupado(true);
    setSalida(null);
    try {
      setSalida((await fn()).salida);
    } catch (e) {
      avisar(e instanceof ErrorApi ? e.message : String(e));
    } finally {
      setOcupado(false);
    }
  };
  const diagnosticar = async () => {
    try {
      setDiag(await api.get<Diagnostico>(`/api/nodos/${nodo.id}/diagnostico`));
    } catch (e) {
      avisar(e instanceof ErrorApi ? e.message : String(e));
    }
  };
  const ips = nodo.interfaces.flatMap((i) => [
    ...(i.ip ? [[nombreIntf(nodo, i.puerto), i.ip]] : []),
    ...(i.subinterfaces ?? []).map((s) => [`${nombreIntf(nodo, i.puerto)}.${s.vlan}`, s.ip]),
  ]);
  return (
    <div className="propiedades">
      <h3>{NOMBRE_TIPO[nodo.tipo]} {nodo.nombre}</h3>
      {ips.map(([n, ip]) => <p key={n}><code>{n}</code> {ip}</p>)}
      {nodo.dhcp && <p>IP por DHCP</p>}
      {nodo.gateway && <p>Gateway <code>{nodo.gateway}</code></p>}
      {nodo.tipo === 'switch' ? (
        <p className="tenue">El switch vive en el espacio de red del sistema: no tiene terminal propia.</p>
      ) : (
        <>
          <button className="primario" onClick={() => abrirTerminal(nodo.id)}>Abrir terminal de {nodo.nombre}</button>
          {nodo.frr && <p className="tenue">En la terminal, <code>vtysh</code> abre la consola de FRR (<code>show ip route</code>, <code>conf t</code>…).</p>}
          {nodo.dhcp && (
            <button disabled={ocupado} onClick={() => accion(() => api.post(`/api/nodos/${nodo.id}/dhcp`))}
              title="DISCOVER, OFFER, REQUEST y ACK: activá la simulación antes para verlos">
              Pedir IP por DHCP de nuevo
            </button>
          )}
          <form className="fila" onSubmit={(e) => { e.preventDefault(); accion(() => api.post(`/api/nodos/${nodo.id}/ping`, { destino: destino.trim(), cantidad: 1 })); }}>
            <input placeholder="IP destino" value={destino} onChange={(e) => setDestino(e.target.value)} spellCheck={false} />
            <button disabled={ocupado || !destino.trim()}>ping -c 1</button>
          </form>
          {salida && <pre className="salida">{salida}</pre>}
        </>
      )}
      <button onClick={diagnosticar}>{diag ? 'Actualizar estado' : 'Ver estado (rutas, VLAN, ARP, NAT…)'}</button>
      {diag && diag.secciones.map((s) => (
        <details key={s.titulo} className="diag" open>
          <summary>{s.titulo}{s.comando && <code className="diag-cmd">{s.comando}</code>}</summary>
          <pre className="salida">{s.salida.trim() || '(vacío)'}</pre>
        </details>
      ))}
    </div>
  );
}

// Borrado en bloque: pide confirmación y solo con la red detenida.
export function confirmarYBorrar() {
  const s = useLab.getState();
  if (s.estadoRed !== 'diseño' && s.estadoRed !== 'error') return;
  if (s.marcados.nodos.length + s.marcados.enlaces.length === 0) return;
  if (window.confirm(textoConfirmacion(s.marcados, s))) s.borrarSeleccion();
}

function PanelVarios() {
  const { marcados, nodos, enlaces, estadoRed, seleccionar } = useLab();
  const diseno = estadoRed === 'diseño' || estadoRed === 'error';
  const nombres = nodos.filter((n) => marcados.nodos.includes(n.id)).map((n) => n.nombre);
  const nEnlaces = enlacesAfectados(marcados, enlaces).length;
  return (
    <div className="propiedades">
      <h3>{nombres.length} equipos y {marcados.enlaces.length} enlaces seleccionados</h3>
      {nombres.length > 0 && <p className="lista-nombres">{nombres.map((n) => <code key={n}>{n}</code>)}</p>}
      <p className="tenue">Arrastrá cualquiera de ellos para moverlos juntos. Shift/Ctrl+clic suma o quita uno.</p>
      {diseno ? (
        <button className="peligro" onClick={confirmarYBorrar}>
          Eliminar selección ({nombres.length} equipos, {nEnlaces} enlaces)
        </button>
      ) : (
        <p className="tenue">Para borrar, detené la red.</p>
      )}
      <button onClick={() => seleccionar(null)}>Quitar selección</button>
    </div>
  );
}

function PanelEnlace({ id }: { id: string }) {
  const { enlaces, nodos, estadoRed, enlacesCaidos, borrarSeleccion, avisar, editarEnlace } = useLab();
  const [ocupado, setOcupado] = useState(false);
  const e = enlaces.find((x) => x.id === id)!;
  const a = nodos.find((n) => n.id === e.a.nodo);
  const b = nodos.find((n) => n.id === e.b.nodo);
  const activa = estadoRed === 'activa';
  const caido = enlacesCaidos.includes(id);
  const cambiar = async (arriba: boolean) => {
    setOcupado(true);
    try {
      await api.post(`/api/enlaces/${id}/estado`, { arriba });
      // El servidor publica el estado nuevo por WebSocket; se refleja ya para no esperar.
      useLab.setState((s) => ({
        enlacesCaidos: arriba ? s.enlacesCaidos.filter((x) => x !== id) : [...new Set([...s.enlacesCaidos, id])],
      }));
    } catch (err) {
      avisar(err instanceof ErrorApi ? err.message : String(err));
    } finally {
      setOcupado(false);
    }
  };
  return (
    <div className="propiedades">
      <h3>Enlace {id}</h3>
      <p><code>{nombreIntf(a, e.a.puerto)}</code> ↔ <code>{nombreIntf(b, e.b.puerto)}</code></p>
      {activa && (
        <p>Estado: <span className={`estado-enlace ${caido ? 'abajo' : 'arriba'}`}>{caido ? 'caído' : 'arriba'}</span></p>
      )}
      <p className="tenue">Par veth. En simulación se captura lo que llega a cada extremo.</p>
      {activa ? (
        caido ? (
          <>
            <p className="tenue">Las dos interfaces están apagadas (<code>ip link set down</code>): no pasa tráfico, como un cable desenchufado.</p>
            <button className="primario" disabled={ocupado} onClick={() => cambiar(true)}>Subir enlace</button>
          </>
        ) : (
          <button disabled={ocupado} onClick={() => cambiar(false)}>Bajar enlace</button>
        )
      ) : (
        <>
          {estadoRed === 'diseño' || estadoRed === 'error' ? (
            <>
              <label className="casilla">
                <input type="checkbox" checked={!!e.desconectado} onChange={(ev) => editarEnlace(id, { desconectado: ev.target.checked })} />
                Arranca desconectado (cable suelto)
              </label>
              <p className="tenue">
                {e.desconectado
                  ? 'Al iniciar la red este enlace queda caído, para practicar diagnóstico. "Subir enlace" con la red en marcha no cambia el diseño: el ejercicio se puede repetir.'
                  : 'Bajar y subir el enlace se puede con la red iniciada.'}
              </p>
            </>
          ) : null}
          {estadoRed !== 'iniciando' && estadoRed !== 'deteniendo' && <button className="peligro" onClick={borrarSeleccion}>Eliminar enlace</button>}
        </>
      )}
    </div>
  );
}
