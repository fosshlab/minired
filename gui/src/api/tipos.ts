// Espejo de los modelos Pydantic (minired/modelo/topologia.py) y de los eventos del backend.

export type TipoNodo = 'pc' | 'switch' | 'router';

export interface Interfaz {
  puerto: number;
  ip?: string | null;
}

export interface Nodo {
  id: string;
  tipo: TipoNodo;
  nombre: string;
  x: number;
  y: number;
  interfaces: Interfaz[];
  gateway?: string | null;
}

export interface Extremo {
  nodo: string;
  puerto: number;
}

export interface Enlace {
  id: string;
  a: Extremo;
  b: Extremo;
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
  ip?: { src: string; dst: string; ttl: number; proto: number; id: number };
  icmp?: { tipo: number; codigo: number; ident?: number; seq?: number };
  udp?: { sport: number; dport: number };
  tcp?: { sport: number; dport: number; banderas: string };
}

export type Confianza = 'alta' | 'media' | 'sin_correlacionar';

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
      enlaces: Record<string, { a: string; b: string }> | null; captura: EstadoCaptura | null }
  | { tipo: 'observaciones'; items: Observacion[]; reinicio?: boolean; descartadas_vista?: number }
  | ({ tipo: 'captura'; reinicio?: boolean } & EstadoCaptura)
  | { tipo: 'aviso'; texto: string; perdidos: number };
