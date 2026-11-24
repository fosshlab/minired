import type { Observacion } from '../api/tipos';

// Filtro de visualización del modo AVANZADO: un subconjunto de la sintaxis de Wireshark.
//   protocolos:  eth arp ip icmp udp tcp dhcp dns http ospf vlan
//   campos:      ip.addr ip.src ip.dst eth.addr eth.src eth.dst vlan.id
//                tcp.port udp.port ip.ttl frame.len   con == != > < >= <=
//   lógica:      ! not  && and  || or  ( )
// Devuelve una función o lanza ErrorFiltro con un mensaje en español.

export class ErrorFiltro extends Error {}

type Pred = (o: Observacion) => boolean;

const PROTOCOLOS = new Set(['eth', 'arp', 'ip', 'icmp', 'udp', 'tcp', 'dhcp', 'dns', 'http', 'ospf', 'vlan']);
const OPERADORES = ['==', '!=', '>=', '<=', '>', '<'];

function tokens(texto: string): string[] {
  const r: string[] = [];
  const re = /\s*(\(|\)|&&|\|\||==|!=|>=|<=|>|<|!|[A-Za-z0-9_.:/-]+)/y;
  let m: RegExpExecArray | null;
  while (re.lastIndex < texto.length) {
    const antes = re.lastIndex;
    m = re.exec(texto);
    if (!m) {
      if (texto.slice(antes).trim() === '') break;
      throw new ErrorFiltro(`no entiendo "${texto.slice(antes).trim()}"`);
    }
    r.push(m[1]);
  }
  return r;
}

function valores(o: Observacion, campo: string): (string | number)[] | null {
  const r = o.resumen;
  switch (campo) {
    case 'ip.addr': return r.ip ? [r.ip.src, r.ip.dst] : [];
    case 'ip.src': return r.ip ? [r.ip.src] : [];
    case 'ip.dst': return r.ip ? [r.ip.dst] : [];
    case 'ip.ttl': return r.ip ? [r.ip.ttl] : [];
    case 'eth.addr': return r.eth ? [r.eth.src, r.eth.dst] : [];
    case 'eth.src': return r.eth ? [r.eth.src] : [];
    case 'eth.dst': return r.eth ? [r.eth.dst] : [];
    case 'vlan.id': return r.vlan ? [r.vlan.id] : [];
    case 'tcp.port': return r.tcp ? [r.tcp.sport, r.tcp.dport] : [];
    case 'udp.port': return r.udp ? [r.udp.sport, r.udp.dport] : [];
    case 'frame.len': return [o.largo];
    default: return null;
  }
}

function comparar(a: string | number, op: string, b: string): boolean {
  const num = typeof a === 'number';
  const x = num ? a : String(a).toLowerCase();
  const y = num ? Number(b) : b.toLowerCase();
  if (num && Number.isNaN(y)) throw new ErrorFiltro(`"${b}" no es un número`);
  switch (op) {
    case '==': return x === y;
    case '!=': return x !== y;
    case '>': return x > y;
    case '<': return x < y;
    case '>=': return x >= y;
    default: return x <= y;
  }
}

export function compilarFiltro(texto: string): Pred {
  const t = tokens(texto.trim());
  if (!t.length) return () => true;
  let i = 0;
  const ver = () => t[i];
  const tomar = () => t[i++];

  function o(): Pred {
    let izq = y();
    while (ver() === '||' || ver() === 'or') {
      tomar();
      const der = y();
      const a = izq;
      izq = (x) => a(x) || der(x);
    }
    return izq;
  }
  function y(): Pred {
    let izq = no();
    while (ver() === '&&' || ver() === 'and') {
      tomar();
      const der = no();
      const a = izq;
      izq = (x) => a(x) && der(x);
    }
    return izq;
  }
  function no(): Pred {
    if (ver() === '!' || ver() === 'not') {
      tomar();
      const p = no();
      return (x) => !p(x);
    }
    return primario();
  }
  function primario(): Pred {
    const tok = tomar();
    if (tok === undefined) throw new ErrorFiltro('el filtro termina antes de tiempo');
    if (tok === '(') {
      const p = o();
      if (tomar() !== ')') throw new ErrorFiltro('falta cerrar un paréntesis');
      return p;
    }
    if (OPERADORES.includes(ver() ?? '')) {
      const op = tomar();
      const valor = tomar();
      if (valor === undefined) throw new ErrorFiltro(`falta el valor después de ${op}`);
      const campo = tok.toLowerCase();
      if (valores({ resumen: { capas: [], protocolo: '', info: '' }, largo: 0 } as unknown as Observacion, campo) === null) {
        throw new ErrorFiltro(`campo desconocido: ${tok}`);
      }
      // Como en Wireshark: "!=" exige que el campo exista y que NINGUNO de sus valores sea igual
      // (ip.addr tiene dos: origen y destino); una trama sin IP no cumple "ip.addr != x".
      if (op === '!=') {
        return (x) => {
          const vs = valores(x, campo)!;
          return vs.length > 0 && !vs.some((v) => comparar(v, '==', valor));
        };
      }
      return (x) => valores(x, campo)!.some((v) => comparar(v, op, valor));
    }
    const proto = tok.toLowerCase();
    if (!PROTOCOLOS.has(proto)) throw new ErrorFiltro(`protocolo o campo desconocido: ${tok}`);
    return (x) => x.resumen.capas.includes(proto);
  }

  const pred = o();
  if (i < t.length) throw new ErrorFiltro(`sobra "${t.slice(i).join(' ')}"`);
  return pred;
}
