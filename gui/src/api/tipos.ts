// Espejo de los modelos Pydantic (minired/modelo/topologia.py) y de los eventos del backend.

export type TipoNodo = 'pc' | 'switch' | 'router' | 'servidor';

export interface Subinterfaz {
  vlan: number;
  ip: string;
}

export interface ReglaACL {
  accion: 'permitir' | 'denegar';
  protocolo: 'ip' | 'icmp' | 'tcp' | 'udp';
  origen?: string | null;
  destino?: string | null;
  puerto?: number | null;
}

export interface Interfaz {
  puerto: number;
  ip?: string | null;
  vlan?: number | null;                 // switch: puerto de acceso
  troncal?: number[] | null;            // switch: troncal 802.1Q
  subinterfaces?: Subinterfaz[];        // router
  nat?: 'interior' | 'exterior' | null; // router
  acl_entrada?: ReglaACL[];             // router
}

export interface Ruta {
  destino: string;
  via: string;
}

export interface Servicios {
  dhcp?: { desde: string; hasta: string; gateway?: string | null; dns?: string | null } | null;
  dns?: { nombre: string; ip: string }[];
  http?: boolean;
}

export interface Nodo {
  id: string;
  tipo: TipoNodo;
  nombre: string;
  x: number;
  y: number;
  interfaces: Interfaz[];
  gateway?: string | null;
  dhcp?: boolean;
  dns?: string | null;
  servicios?: Servicios | null;
  rutas?: Ruta[];
  frr?: boolean;
  ospf?: boolean;
}

export interface Extremo {
  nodo: string;
  puerto: number;
}

export interface Enlace {
  id: string;
  a: Extremo;
  b: Extremo;
  desconectado?: boolean;   // arranca caído (cable suelto); "Subir enlace" en vivo no lo cambia
}

export interface Lab {
  version: 1;
  nodos: Nodo[];
  enlaces: Enlace[];
}

export type EstadoRed = 'diseño' | 'iniciando' | 'activa' | 'deteniendo' | 'error';

export interface Resumen {
  capas: string[];
  protocolo: string;
  info: string;
  eth?: { src: string; dst: string; tipo: string };
  arp?: { op: number; sha: string; spa: string; tha: string; tpa: string };
  ip?: { src: string; dst: string; ttl: number; proto: number; id: number; largo?: number };
  icmp?: { tipo: number; codigo: number; ident?: number; seq?: number };
  udp?: { sport: number; dport: number };
  tcp?: { sport: number; dport: number; banderas: string };
  vlan?: { id: number; pcp: number };
  dhcp?: { tipo?: number; xid: string; yiaddr: string; chaddr: string };
  dns?: { nombre?: string; respuesta: boolean; respuestas?: string[] };
  http?: { linea: string };
  ospf?: { tipo: number };
}

export type Confianza = 'alta' | 'media' | 'baja' | 'sin_correlacionar';

export interface Diagnostico {
  nodo: string;
  secciones: { titulo: string; comando: string | null; salida: string }[];
}

// Un frame REAL capturado al llegar al extremo `hacia` del enlace.
export interface Observacion {
  id: string;
  seq: number;
  ts_ns: string;
  t_us: number;
  enlace: string;
  hacia: 'a' | 'b';
  nodo: string;
  emisor: string;
  intf: string;
  largo: number;
  pcap: { archivo: string; n: number };
  resumen: Resumen;
  paquete: string;
  padre: string | null;
  confianza: Confianza;
  profundidad: number;
}

export interface EstadoCapturador {
  intf: string;
  enlace: string;
  capturados: number | null;
  caidos_kernel: number | null;
  error: string | null;
}

export interface EstadoCaptura {
  activa: boolean;
  observaciones: number;
  descartadas_vista: number;
  capturadores: EstadoCapturador[];
}

export interface Campo {
  nombre: string;
  titulo: string;
  valor: string;
  pos?: number;
  largo?: number;
  campos?: Campo[];
}

export interface DetalleCapas {
  id: string;
  intf: string;
  pcap: { archivo: string; n: number };
  hex: string;
  capas: Campo[];
}

export type Evento =
  | { tipo: 'estado'; estado: EstadoRed; error: string | null;
      enlaces: Record<string, { a: string; b: string }> | null; captura: EstadoCaptura | null;
      enlaces_caidos?: string[] }
  | { tipo: 'observaciones'; items: Observacion[]; reinicio?: boolean; descartadas_vista?: number }
  | ({ tipo: 'captura'; reinicio?: boolean } & EstadoCaptura)
  | { tipo: 'aviso'; texto: string; perdidos: number };

// Vista OSI estilo Packet Tracer (GET /api/captura/observaciones/{id}/osi), inferida del tráfico real.
export interface CapaOsi { capa: number; nombre: string; texto: string }
export type Fuente = 'observado' | 'configuracion' | 'estado' | 'inferido';
export interface Decision { n: number; capa: number; texto: string; fuente: Fuente }
export interface VistaOsi {
  obs: string;
  paquete: string;
  dispositivo: string;
  nombre: string;
  tipo: TipoNodo | null;
  desde: string;
  desde_nombre: string;
  entrada: CapaOsi[];
  salidas: { obs: string; intf: string | null; hacia: string; hacia_nombre: string; capas: CapaOsi[] }[];
  decisiones: Decision[];
  resultado: 'inundado' | 'reenviado' | 'traducido' | 'entregado' | 'respondido' | 'descartado' | 'sin_salida';
  origen?: { dispositivo: string; nombre: string; tipo: TipoNodo | null; salida: CapaOsi[]; decisiones: Decision[] };
  estado_red: string[];
}
