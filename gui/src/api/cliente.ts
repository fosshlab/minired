// Cliente REST. El token llega en el fragmento de la URL (#token=...), que el navegador
// no envía a ningún servidor; se guarda en sessionStorage y se borra de la barra de direcciones.

const CLAVE = 'minired.token';

function leerToken(): string {
  const m = /(?:^|[#&])token=([A-Za-z0-9_-]+)/.exec(window.location.hash);
  if (m) {
    try { sessionStorage.setItem(CLAVE, m[1]); } catch { /* sin almacenamiento */ }
    history.replaceState(null, '', window.location.pathname + window.location.search);
    return m[1];
  }
  try { return sessionStorage.getItem(CLAVE) ?? ''; } catch { return ''; }
}

export const token = leerToken();

export class ErrorApi extends Error {
  constructor(mensaje: string, public estado: number, public errores: string[] = []) {
    super(mensaje);
  }
}

async function pedir<T>(metodo: string, ruta: string, cuerpo?: unknown): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(ruta, {
      method: metodo,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(cuerpo !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: cuerpo !== undefined ? JSON.stringify(cuerpo) : undefined,
    });
  } catch {
    throw new ErrorApi('No hay conexión con el servidor de minired', 0);
  }
  if (resp.status === 401) {
    throw new ErrorApi('Falta el token: abrí la dirección completa que mostró "minired gui"', 401);
  }
  const tipo = resp.headers.get('content-type') ?? '';
  const datos = tipo.includes('json') ? await resp.json() : await resp.text();
  if (!resp.ok) {
    const det = typeof datos === 'object' && datos !== null ? datos : { detalle: String(datos) };
    const detalle = typeof det.detalle === 'string' ? det.detalle
      : typeof det.detail === 'string' ? det.detail : `Error ${resp.status}`;
    throw new ErrorApi(detalle, resp.status, Array.isArray(det.errores) ? det.errores : []);
  }
  return datos as T;
}

export const api = {
  get: <T>(ruta: string) => pedir<T>('GET', ruta),
  post: <T>(ruta: string, cuerpo?: unknown) => pedir<T>('POST', ruta, cuerpo),
  put: <T>(ruta: string, cuerpo?: unknown) => pedir<T>('PUT', ruta, cuerpo),

  async descargar(ruta: string, nombre: string) {
    const resp = await fetch(ruta, { headers: { Authorization: `Bearer ${token}` } });
    if (!resp.ok) throw new ErrorApi(`No se pudo descargar (${resp.status})`, resp.status);
    const url = URL.createObjectURL(await resp.blob());
    const a = document.createElement('a');
    a.href = url;
    a.download = nombre;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
};

export function urlWs(ruta: string): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}${ruta}`;
}

// El navegador no permite cabeceras en WebSocket: el token viaja como subprotocolo.
export const subprotocolos = ['minired', `token.${token}`];
