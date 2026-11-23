import { Handle, Position, useConnection, type Node, type NodeProps } from '@xyflow/react';
import type { Nodo } from '../api/tipos';
import { Icono } from './iconos';

export type NodoFlujo = Node<{ nodo: Nodo; conectable: boolean; recibe: boolean }, 'red'>;

// Un handle chico para arrastrar un enlace y, mientras se arrastra, todo el nodo como destino:
// el puerto se asigna solo (el primero libre), como en Packet Tracer.
export function NodoRed({ data, selected }: NodeProps<NodoFlujo>) {
  const { nodo, conectable, recibe } = data;
  const conexion = useConnection();
  const ips = nodo.interfaces.flatMap((i) => [i.ip, ...(i.subinterfaces ?? []).map((x) => x.ip)]).filter(Boolean);
  const marcas = [
    nodo.dhcp && 'DHCP',
    nodo.frr && (nodo.ospf ? 'FRR·OSPF' : 'FRR'),
    nodo.interfaces.some((i) => i.nat) && 'NAT',
    nodo.interfaces.some((i) => i.acl_entrada?.length) && 'ACL',
    nodo.servicios?.dhcp && 'DHCP srv',
    nodo.servicios?.dns?.length && 'DNS',
    nodo.servicios?.http && 'HTTP',
  ].filter(Boolean) as string[];
  return (
    <div className={`nodo nodo-${nodo.tipo}${selected ? ' seleccionado' : ''}${recibe ? ' recibe' : ''}`}>
      <Icono tipo={nodo.tipo} />
      <div className="nodo-nombre">{nodo.nombre}</div>
      {ips.length > 0 && <div className="nodo-ip">{nodo.tipo === 'router' ? `${ips.length} IP` : ips[0]}</div>}
      {marcas.length > 0 && <div className="nodo-marcas">{marcas.map((m) => <span key={m}>{m}</span>)}</div>}
      <Handle type="source" position={Position.Right} id="s" className="asa" isConnectable={conectable}
        title="Arrastrá hasta otro equipo para conectarlo" />
      <Handle type="target" position={Position.Left} id="t" isConnectable={conectable}
        className={conexion.inProgress ? 'asa-destino activa' : 'asa-destino'} />
    </div>
  );
}
