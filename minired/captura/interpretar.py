"""Vista OSI estilo Packet Tracer, a partir del tráfico REAL capturado.

Para una observación (un frame que llegó a un dispositivo) arma:

- las capas de ENTRADA (lo que llegó), de la 7 a la 1;
- las capas de SALIDA: lo que ese dispositivo emitió por ese paquete, es decir sus hijos
  en el grafo de correlación (o, para un paquete que nace en el dispositivo, el propio frame);
- las DECISIONES numeradas y explicadas en español, cada una con su fuente:
    observado      está en la captura (salió por 2 puertos, el TTL bajó de 64 a 63);
    configuracion  lo declara el laboratorio (puerto de acceso VLAN 10, regla 1 de la ACL);
    estado         se leyó del dispositivo al iniciar o al detener la captura (tabla de rutas);
    inferido       lo implica el comportamiento estándar y no se puede leer en ese instante
                   (por ejemplo, que OVS aprende la MAC de origen).

Nunca se inventa un paquete: si no se observó una salida, se dice.
"""

from ipaddress import IPv4Address, IPv4Network, ip_interface

from ..modelo.topologia import TipoNodo, ips_nodo, nombre_intf

OBSERVADO = 'observado'
CONFIGURACION = 'configuracion'
ESTADO = 'estado'
INFERIDO = 'inferido'

BROADCAST = 'ff:ff:ff:ff:ff:ff'
NOMBRES_CAPA = {1: 'Física', 2: 'Enlace de datos', 3: 'Red', 4: 'Transporte', 7: 'Aplicación'}
DHCP_TIPOS = {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE'}
ICMP_TIPOS = {0: 'respuesta de eco', 3: 'destino inalcanzable', 8: 'solicitud de eco', 11: 'TTL excedido'}
VENTANA_RESPUESTA_NS = 2_000_000_000


def _ip(texto):
    try:
        return IPv4Address(texto)
    except ValueError:
        return None


def capas(resumen, intf, describir_mac):
    """Capas OSI de un frame, de la 7 a la 1, con un texto corto por capa."""
    r = []
    eth = resumen.get('eth')
    if 'dhcp' in resumen:
        d = resumen['dhcp']
        r.append((7, 'DHCP', 'DHCP %s, xid %s%s' % (DHCP_TIPOS.get(d.get('tipo'), 'BOOTP'), d['xid'],
                                                     ', IP ofrecida %s' % d['yiaddr'] if d.get('yiaddr', '0.0.0.0') != '0.0.0.0' else '')))
    elif 'dns' in resumen:
        d = resumen['dns']
        r.append((7, 'DNS', ('respuesta' if d['respuesta'] else 'consulta') + ' %s %s' % (
            d.get('qtipo', ''), d.get('nombre', '')) + (' → %s' % ', '.join(d['respuestas']) if d.get('respuestas') else '')))
    elif 'http' in resumen:
        r.append((7, 'HTTP', resumen['http']['linea']))
    if 'udp' in resumen:
        u = resumen['udp']
        r.append((4, 'UDP', 'puerto origen %d → puerto destino %d' % (u['sport'], u['dport'])))
    elif 'tcp' in resumen:
        t = resumen['tcp']
        r.append((4, 'TCP', 'puerto %d → %d, banderas [%s]' % (t['sport'], t['dport'], t['banderas'])))
    if 'ip' in resumen:
        ip = resumen['ip']
        texto = 'IPv4 %s → %s, TTL %d' % (ip['src'], ip['dst'], ip['ttl'])
        if 'icmp' in resumen:
            texto += '; ICMP %s' % ICMP_TIPOS.get(resumen['icmp']['tipo'], 'tipo %d' % resumen['icmp']['tipo'])
        elif 'ospf' in resumen:
            texto += '; OSPF'
        r.append((3, 'IPv4' + (' + ICMP' if 'icmp' in resumen else ''), texto))
    if 'arp' in resumen:
        a = resumen['arp']
        r.append((2, 'ARP', ('solicitud: ¿quién tiene %s? avisar a %s' % (a['tpa'], a['spa'])) if a['op'] == 1
                  else 'respuesta: %s está en %s' % (a['spa'], a['sha'])))
    if eth:
        texto = 'Ethernet II: %s → %s' % (describir_mac(eth['src']), describir_mac(eth['dst']))
        if 'vlan' in resumen:
            texto += ', etiqueta 802.1Q VLAN %d' % resumen['vlan']['id']
        r.append((2, 'Ethernet', texto))
    r.append((1, 'Puerto', intf))
    return [{'capa': n, 'nombre': nombre, 'texto': texto} for n, nombre, texto in r]


class Interprete:
    def __init__(self, plan, observaciones, estado_red=None):
        """observaciones: Observacion ya correlacionadas (en orden de tiempo)."""
        self.plan = plan
        self.lab = plan.lab
        self.obs = sorted(observaciones, key=lambda o: (o.ts_ns, o.seq))
        self.por_id = {o.id: o for o in self.obs}
        self.hijos = {}
        for o in self.obs:
            if o.padre:
                self.hijos.setdefault(o.padre, []).append(o)
        self.estado = estado_red or {}
        self.mac_intf = {mac: intf for intf, mac in plan.macs.items()}
        self.nodos = {n.id: n for n in self.lab.nodos}

    # --- utilidades -------------------------------------------------------

    def nombre(self, nodo_id):
        n = self.nodos.get(nodo_id)
        return n.nombre if n else nodo_id

    def describir_mac(self, mac):
        if mac == BROADCAST:
            return '%s (broadcast)' % mac
        if mac.startswith('01:00:5e'):
            return '%s (multicast)' % mac
        intf = self.mac_intf.get(mac)
        return '%s (%s)' % (mac, intf) if intf else mac

    def _macs_de(self, nodo_id):
        return {self.plan.macs[i] for i, ep in self.plan.por_intf.items() if ep.nodo == nodo_id}

    def _ips_de(self, nodo_id):
        """IPv4Interface del nodo: las del laboratorio y, si pide DHCP, las leídas del estado."""
        nodo = self.nodos[nodo_id]
        ips = [ip for _, ip in ips_nodo(nodo)]
        for momento in ('inicio', 'fin'):
            for texto in self.estado.get(momento, {}).get('direcciones', {}).get(nodo_id, []):
                ip = ip_interface(texto)
                if ip not in ips:
                    ips.append(ip)
        return ips

    def _es_mia(self, nodo_id, ip):
        ip = _ip(ip)
        return ip is not None and any(ip == i.ip for i in self._ips_de(nodo_id))

    def _intf_propia(self, nodo_id, enlace_id):
        for ep in self.plan.enlaces[enlace_id]:
            if ep.nodo == nodo_id:
                return ep.intf
        return None

    def _config_puerto(self, nodo_id, intf):
        nodo = self.nodos[nodo_id]
        for i in nodo.interfaces:
            if nombre_intf(nodo, i.puerto) == intf:
                return i
        return None

    def _rutas(self, nodo_id):
        for momento in ('inicio', 'fin'):
            rutas = self.estado.get(momento, {}).get('rutas', {}).get(nodo_id)
            if rutas:
                return rutas, momento
        return None, None

    def _buscar_ruta(self, nodo_id, destino):
        rutas, momento = self._rutas(nodo_id)
        if rutas is None:
            return None, None
        ip = _ip(destino)
        mejor = None
        for r in rutas:
            red = IPv4Network('0.0.0.0/0') if r.get('dst') == 'default' else IPv4Network(r['dst'], strict=False)
            if ip in red and (mejor is None or red.prefixlen > mejor[0].prefixlen):
                mejor = (red, r)
        return mejor, momento

    def _posterior(self, o, cumple):
        """Primera observación RAÍZ posterior a o (dentro de 2 s) que cumple: respuestas, ARP del router."""
        for p in self.obs:
            if p.ts_ns > o.ts_ns and p.ts_ns - o.ts_ns <= VENTANA_RESPUESTA_NS and p.profundidad == 0 and cumple(p):
                return p
        return None

    # --- vista OSI ----------------------------------------------------------

    def visita(self, obs_id):
        o = self.por_id.get(obs_id)
        if o is None:
            return None
        nodo = self.nodos.get(o.nodo)
        tipo = nodo.tipo if nodo else None
        decisiones = []
        hijos = self.hijos.get(o.id, [])
        if tipo == TipoNodo.switch:
            resultado = self._switch(o, hijos, decisiones)
        elif tipo == TipoNodo.router:
            resultado = self._router(o, hijos, decisiones)
        else:
            resultado = self._host(o, decisiones)
        visita = {
            'obs': o.id, 'paquete': o.paquete, 'dispositivo': o.nodo, 'nombre': self.nombre(o.nodo),
            'tipo': tipo.value if tipo else None, 'desde': o.emisor, 'desde_nombre': self.nombre(o.emisor),
            'entrada': capas(o.resumen, o.intf, self.describir_mac),
            'salidas': [{'obs': h.id, 'intf': self._intf_propia(o.nodo, h.enlace), 'hacia': h.nodo,
                         'hacia_nombre': self.nombre(h.nodo),
                         'capas': capas(h.resumen, self._intf_propia(o.nodo, h.enlace), self.describir_mac)}
                        for h in hijos],
            'decisiones': [{'n': i, **d} for i, d in enumerate(decisiones, start=1)],
            'resultado': resultado,
        }
        if o.profundidad == 0 and o.confianza != 'sin_correlacionar':
            visita['origen'] = self._origen(o)
        return visita

    def _d(self, decisiones, capa, texto, fuente):
        decisiones.append({'capa': capa, 'texto': texto, 'fuente': fuente})

    # --- switch -------------------------------------------------------------

    def _vlan_de_entrada(self, o, cfg):
        if cfg is not None and cfg.vlan is not None:
            return cfg.vlan, 'Entra por un puerto de acceso de la VLAN %d: la trama pertenece a esa VLAN.' % cfg.vlan, CONFIGURACION
        if 'vlan' in o.resumen:
            vid = o.resumen['vlan']['id']
            return vid, 'Entra por una troncal con etiqueta 802.1Q de la VLAN %d.' % vid, OBSERVADO
        return None, None, None

    def _switch(self, o, hijos, d):
        sw = o.nodo
        cfg = self._config_puerto(sw, o.intf)
        eth = o.resumen.get('eth', {})
        self._d(d, 1, 'Recibe la trama por el puerto %s.' % o.intf, OBSERVADO)
        vlan, texto, fuente = self._vlan_de_entrada(o, cfg)
        if texto:
            self._d(d, 2, texto, fuente)
        en_vlan = ' (VLAN %d)' % vlan if vlan else ''
        texto = 'Aprende la MAC de origen: %s está detrás del puerto %s%s.' % (eth.get('src'), o.intf, en_vlan)
        fdb = [f for f in self.estado.get('fin', {}).get('fdb', {}).get(sw, []) if f['mac'] == eth.get('src')]
        self._d(d, 2, texto, INFERIDO)
        if fdb:
            self._d(d, 2, 'Al detener la captura, la tabla MAC de %s lo confirma (%s en %s).'
                    % (self.nombre(sw), fdb[0]['mac'], fdb[0]['intf']), ESTADO)
        dst = eth.get('dst', '')
        salidas = ', '.join(self._intf_propia(sw, h.enlace) for h in hijos)
        multidifusion = dst == BROADCAST or int(dst[:2] or '0', 16) & 1
        if multidifusion:
            self._d(d, 2, 'La MAC destino es %s: la inunda por todos los puertos%s menos el de entrada.'
                    % ('broadcast' if dst == BROADCAST else 'multicast', ' de la VLAN %d' % vlan if vlan else ''),
                    INFERIDO)
            resultado = 'inundado' if hijos else 'sin_salida'
        elif len(hijos) == 1:
            self._d(d, 2, 'La MAC destino %s está en su tabla MAC, asociada a %s: la reenvía solo por ese puerto.'
                    % (self.describir_mac(dst), salidas), INFERIDO)
            resultado = 'reenviado'
        elif len(hijos) > 1:
            self._d(d, 2, 'La MAC destino %s no está en su tabla MAC: la inunda (unicast desconocido).'
                    % self.describir_mac(dst), INFERIDO)
            resultado = 'inundado'
        else:
            resultado = 'sin_salida'
        if hijos:
            self._d(d, 1, 'Se observó salir por: %s.' % salidas, OBSERVADO)
            for h in hijos:
                salida = self._intf_propia(sw, h.enlace)
                cfg_s = self._config_puerto(sw, salida)
                if cfg_s is not None and cfg_s.troncal is not None:
                    self._d(d, 2, 'Sale por %s, que es troncal: agrega la etiqueta 802.1Q de la VLAN %s.'
                            % (salida, h.resumen.get('vlan', {}).get('id', vlan)), CONFIGURACION)
                elif cfg_s is not None and cfg_s.vlan is not None and vlan and 'vlan' in o.resumen:
                    self._d(d, 2, 'Sale por %s, puerto de acceso de la VLAN %d: quita la etiqueta.'
                            % (salida, cfg_s.vlan), CONFIGURACION)
        else:
            otros = self._puertos_misma_vlan(sw, o.intf, vlan)
            if not otros:
                self._d(d, 2, 'No hay otros puertos conectados en la VLAN %s: la trama no sale.'
                        % (vlan or 'del puerto'), CONFIGURACION)
                resultado = 'descartado'
            else:
                self._d(d, 1, 'No se observó la salida de esta trama.', OBSERVADO)
        return resultado

    def _puertos_misma_vlan(self, sw, entrada, vlan):
        r = []
        for intf, ep in self.plan.por_intf.items():
            if ep.nodo != sw or intf == entrada:
                continue
            cfg = self._config_puerto(sw, intf)
            if vlan is None or cfg is None or (cfg.vlan is None and cfg.troncal is None) \
                    or cfg.vlan == vlan or (cfg.troncal is not None and vlan in cfg.troncal):
                r.append(intf)
        return r

    # --- router -------------------------------------------------------------

    def _router(self, o, hijos, d):
        r = o.nodo
        res = o.resumen
        eth = res.get('eth', {})
        entrada = o.intf + ('.%d' % res['vlan']['id'] if 'vlan' in res else '')
        self._d(d, 1, 'Recibe la trama por %s%s.' % (o.intf, ' (subinterfaz %s)' % entrada if 'vlan' in res else ''),
                OBSERVADO)
        if 'arp' in res:
            return self._arp_recibido(o, d, 'router')
        dst_mac = eth.get('dst', '')
        if dst_mac in self._macs_de(r):
            self._d(d, 2, 'La MAC destino es la de %s: la trama es para el router; saca el paquete IP.'
                    % self.mac_intf.get(dst_mac, o.intf), OBSERVADO)
        elif dst_mac.startswith('01:00:5e'):
            self._d(d, 2, 'MAC destino multicast: el router la acepta.', OBSERVADO)
        else:
            self._d(d, 2, 'La MAC destino no es suya: descarta la trama.', OBSERVADO)
            return 'descartado'
        if 'ip' not in res:
            return 'sin_salida'
        ip = res['ip']
        if 'ospf' in res:
            self._d(d, 3, 'Es un mensaje OSPF para el grupo 224.0.0.5: lo procesa ospfd (FRR) y no se reenvía.',
                    CONFIGURACION)
            return 'entregado'
        destino = ip['dst']
        if self._es_mia(r, ip['dst']):
            if not hijos:
                self._d(d, 3, 'La IP destino %s es suya: el paquete es para el router.' % ip['dst'], OBSERVADO)
                return self._entregar(o, d)
            # Respuesta a una conexión que el NAT tradujo: conntrack la reconoce y la reenvía.
            destino = hijos[0].resumen.get('ip', {}).get('dst', destino)
            self._d(d, 3, 'La IP destino %s es suya, pero es la respuesta a una conexión traducida por NAT: '
                    'conntrack sabe que en realidad va a %s.' % (ip['dst'], destino), OBSERVADO)
        # Reenvío
        denegado = self._acl(o, entrada, d)
        if denegado:
            if not hijos:
                self._d(d, 3, 'No se observó la salida: el paquete se descartó.', OBSERVADO)
            return 'descartado'
        ruta, momento = self._buscar_ruta(r, destino)
        if ruta is None and momento is not None:
            self._d(d, 3, 'No hay ruta hacia %s en su tabla: descarta el paquete.' % destino, ESTADO)
        elif ruta is not None:
            red, fila = ruta
            via = fila.get('gateway')
            origen = {'kernel': 'red conectada', 'ospf': 'aprendida por OSPF', 'static': 'estática (FRR)',
                      None: 'estática'}.get(fila.get('protocol'), fila.get('protocol'))
            self._d(d, 3, 'Busca %s en la tabla de rutas: coincide %s%s, por %s (%s; tabla leída al %s la captura).'
                    % (destino, 'la ruta por defecto' if fila['dst'] == 'default' else fila['dst'],
                       ' vía %s' % via if via else ', entrega directa', fila.get('dev'), origen,
                       'iniciar' if momento == 'inicio' else 'detener'), ESTADO)
        if not hijos:
            if ip['ttl'] <= 1:
                self._d(d, 3, 'El TTL llega a 0: descarta el paquete (avisa con ICMP "TTL excedido").', OBSERVADO)
                return 'descartado'
            self._d(d, 3, 'No se observó la salida de este paquete.', OBSERVADO)
            return 'sin_salida'
        h = hijos[0]
        hip = h.resumen.get('ip', {})
        self._d(d, 3, 'Baja el TTL: %d → %d.' % (ip['ttl'], hip.get('ttl', 0)), OBSERVADO)
        resultado = 'reenviado'
        if hip.get('src') != ip['src']:
            self._d(d, 3, 'NAT (PAT) traduce la IP de origen %s → %s para salir por la interfaz exterior.'
                    % (ip['src'], hip.get('src')), OBSERVADO)
            resultado = 'traducido'
        if hip.get('dst') != ip['dst']:
            self._d(d, 3, 'NAT deshace la traducción: la IP destino %s → %s (conntrack recuerda la conexión).'
                    % (ip['dst'], hip.get('dst')), OBSERVADO)
            resultado = 'traducido'
        siguiente = (ruta[1].get('gateway') if ruta else None) or hip.get('dst')
        arp = self._posterior(o, lambda p: p.emisor == r and p.resumen.get('arp', {}).get('op') == 1
                              and p.resumen['arp']['tpa'] == siguiente and p.ts_ns < h.ts_ns)
        if arp is not None:
            self._d(d, 2, 'No conocía la MAC de %s: preguntó por ARP (paquete %s) y esperó la respuesta.'
                    % (siguiente, arp.paquete), OBSERVADO)
        else:
            self._d(d, 2, 'Ya tenía la MAC de %s en su tabla ARP.' % siguiente, INFERIDO)
        salida = self._intf_propia(r, h.enlace)
        heth = h.resumen.get('eth', {})
        self._d(d, 2, 'Arma una trama nueva para salir por %s%s: MAC origen %s, destino %s.'
                % (salida, '.%d (subinterfaz: etiqueta 802.1Q VLAN %d)' % ((h.resumen['vlan']['id'],) * 2)
                   if 'vlan' in h.resumen else '',
                   self.describir_mac(heth.get('src', '')), self.describir_mac(heth.get('dst', ''))), OBSERVADO)
        return resultado

    def _acl(self, o, entrada, d):
        """Evalúa la ACL de entrada del puerto (configuración). Devuelve True si descarta."""
        nodo = self.nodos[o.nodo]
        cfg = self._config_puerto(o.nodo, o.intf)
        if cfg is None or not cfg.acl_entrada:
            return False
        ip = o.resumen['ip']
        proto = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(ip['proto'])
        puerto = o.resumen.get('tcp', o.resumen.get('udp', {})).get('dport')
        for n, regla in enumerate(cfg.acl_entrada, start=1):
            if regla.protocolo != 'ip' and regla.protocolo != proto:
                continue
            if regla.origen is not None and _ip(ip['src']) not in regla.origen:
                continue
            if regla.destino is not None and _ip(ip['dst']) not in regla.destino:
                continue
            if regla.puerto is not None and regla.puerto != puerto:
                continue
            texto = '%s %s%s%s%s' % (regla.accion, regla.protocolo, ' desde %s' % regla.origen if regla.origen else '',
                                     ' hacia %s' % regla.destino if regla.destino else '',
                                     ' puerto %d' % regla.puerto if regla.puerto else '')
            if regla.accion == 'denegar':
                self._d(d, 3, 'La ACL de entrada de %s coincide con la regla %d (%s): descarta el paquete.'
                        % (nombre_intf(nodo, cfg.puerto), n, texto), CONFIGURACION)
                return True
            self._d(d, 3, 'La ACL de entrada de %s permite el paquete por la regla %d (%s).'
                    % (nombre_intf(nodo, cfg.puerto), n, texto), CONFIGURACION)
            return False
        self._d(d, 3, 'Ninguna regla de la ACL de entrada de %s coincide: el "deny any" implícito lo descarta.'
                % nombre_intf(nodo, cfg.puerto), CONFIGURACION)
        return True

    # --- PC y servidor ------------------------------------------------------

    def _host(self, o, d):
        n = o.nodo
        res = o.resumen
        eth = res.get('eth', {})
        self._d(d, 1, 'Recibe la trama por %s.' % o.intf, OBSERVADO)
        if 'arp' in res:
            return self._arp_recibido(o, d, 'host')
        dst = eth.get('dst', '')
        if dst == BROADCAST:
            self._d(d, 2, 'La MAC destino es broadcast: la acepta.', OBSERVADO)
        elif dst in self._macs_de(n):
            self._d(d, 2, 'La MAC destino es la suya: acepta la trama.', OBSERVADO)
        else:
            self._d(d, 2, 'La MAC destino %s no es suya: descarta la trama.' % self.describir_mac(dst), OBSERVADO)
            return 'descartado'
        if 'ip' not in res:
            return 'entregado'
        ip = res['ip']
        if not (self._es_mia(n, ip['dst']) or ip['dst'] == '255.255.255.255' or 'dhcp' in res):
            self._d(d, 3, 'La IP destino %s no es suya: descarta el paquete (una PC no reenvía).' % ip['dst'],
                    OBSERVADO)
            return 'descartado'
        return self._entregar(o, d)

    def _entregar(self, o, d):
        """El paquete es para este dispositivo: qué hace cada protocolo y qué respuesta se observó."""
        n = o.nodo
        res = o.resumen
        ip = res['ip']
        nodo = self.nodos[n]
        if 'icmp' in res:
            tipo = res['icmp']['tipo']
            if tipo == 8:
                rta = self._posterior(o, lambda p: p.emisor == n and p.resumen.get('icmp', {}).get('tipo') == 0
                                      and p.resumen.get('icmp', {}).get('seq') == res['icmp'].get('seq'))
                self._d(d, 3, 'Solicitud de eco para él: responde con una respuesta de eco%s.'
                        % (' (paquete %s)' % rta.paquete if rta else ' (no se observó la respuesta)'),
                        OBSERVADO)
                return 'respondido' if rta else 'entregado'
            self._d(d, 3, 'ping recibe la %s de %s: el paquete llegó a destino.'
                    % (ICMP_TIPOS.get(tipo, 'ICMP tipo %d' % tipo), ip['src']), OBSERVADO)
            return 'entregado'
        if 'dhcp' in res:
            t = res['dhcp'].get('tipo')
            es_servidor = nodo.servicios is not None and nodo.servicios.dhcp is not None
            if t in (1, 3) and es_servidor:
                rta = self._posterior(o, lambda p: p.emisor == n and p.resumen.get('dhcp', {}).get('xid') == res['dhcp']['xid'])
                self._d(d, 7, 'dnsmasq (servidor DHCP) recibe el %s y contesta con %s%s.'
                        % (DHCP_TIPOS[t], 'OFFER' if t == 1 else 'ACK',
                           ' (paquete %s)' % rta.paquete if rta else ', aunque no se observó la respuesta'),
                        OBSERVADO if rta else CONFIGURACION)
                return 'respondido' if rta else 'entregado'
            if t in (1, 3):
                self._d(d, 7, 'No es servidor DHCP: ningún proceso escucha en el puerto 67; ignora el %s.'
                        % DHCP_TIPOS[t], CONFIGURACION)
                return 'descartado'
            if t == 2:
                self._d(d, 7, 'El cliente DHCP recibe la oferta de %s y la pide con un REQUEST.' % res['dhcp']['yiaddr'],
                        INFERIDO)
            elif t == 5:
                self._d(d, 7, 'El cliente DHCP recibe el ACK: configura %s en su interfaz (y gateway y DNS si vienen).'
                        % res['dhcp']['yiaddr'], INFERIDO)
            return 'entregado'
        if 'dns' in res:
            dns = res['dns']
            if not dns['respuesta']:
                rta = self._posterior(o, lambda p: p.emisor == n and p.resumen.get('dns', {}).get('id') == dns.get('id'))
                self._d(d, 7, 'dnsmasq busca %s en sus registros y responde%s.'
                        % (dns.get('nombre'), ' (paquete %s)' % rta.paquete if rta else ''), OBSERVADO)
                return 'respondido' if rta else 'entregado'
            self._d(d, 7, 'El sistema resuelve %s = %s.' % (dns.get('nombre'), ', '.join(dns.get('respuestas', [])) or 'sin respuesta'),
                    OBSERVADO)
            return 'entregado'
        if 'tcp' in res:
            t = res['tcp']
            if 'http' in res:
                self._d(d, 7, 'El servidor HTTP recibe "%s".' % res['http']['linea'], OBSERVADO)
            elif t['banderas'] == 'S':
                self._d(d, 4, 'Pedido de conexión TCP (SYN) al puerto %d.' % t['dport'], OBSERVADO)
            else:
                self._d(d, 4, 'Segmento TCP de la conexión %d → %d [%s].' % (t['sport'], t['dport'], t['banderas']),
                        OBSERVADO)
            return 'entregado'
        self._d(d, 3, 'Entrega el paquete al protocolo %d.' % ip['proto'], OBSERVADO)
        return 'entregado'

    def _arp_recibido(self, o, d, quien):
        n = o.nodo
        a = o.resumen['arp']
        if a['op'] == 1:
            if self._es_mia(n, a['tpa']):
                rta = self._posterior(o, lambda p: p.emisor == n and p.resumen.get('arp', {}).get('op') == 2
                                      and p.resumen['arp']['spa'] == a['tpa'])
                self._d(d, 2, 'Preguntan por su IP %s: anota %s → %s y responde con su MAC%s.'
                        % (a['tpa'], a['spa'], a['sha'], ' (paquete %s)' % rta.paquete if rta else ' (no se observó la respuesta)'),
                        OBSERVADO)
                return 'respondido' if rta else 'entregado'
            texto = 'Preguntan por %s, que no es su IP: ignora la solicitud.' % a['tpa']
            if quien == 'router':
                texto += ' Un router no reenvía broadcasts.'
            self._d(d, 2, texto, OBSERVADO)
            return 'descartado'
        self._d(d, 2, 'Respuesta ARP: anota %s → %s en su tabla ARP y ya puede enviar lo que esperaba.'
                % (a['spa'], a['sha']), INFERIDO)
        return 'entregado'

    # --- el paquete nace en el emisor ---------------------------------------

    def _origen(self, o):
        """Capas de salida y decisiones del dispositivo que CREÓ el paquete (o es raíz)."""
        e = o.emisor
        res = o.resumen
        d = []
        intf = self._intf_propia(e, o.enlace)
        causa = self._causa(o)
        if causa:
            self._d(d, 7 if ('dhcp' in res or 'dns' in res) else 3 if 'ip' in res else 2, causa, OBSERVADO)
        if 'ospf' in res:
            self._d(d, 3, 'ospfd (FRR) envía un mensaje OSPF al grupo 224.0.0.5 (Hello cada 10 s: descubrir '
                    'y mantener vecinos).', CONFIGURACION)
        if 'arp' in res and res['arp']['op'] == 1:
            self._d(d, 2, 'Necesita la MAC de %s: pregunta por ARP con un broadcast (ff:ff:ff:ff:ff:ff).'
                    % res['arp']['tpa'], OBSERVADO)
        elif 'dhcp' in res and res['dhcp'].get('tipo') in (1, 3):
            self._d(d, 7, 'El cliente DHCP todavía no tiene IP: envía %s desde 0.0.0.0 a 255.255.255.255 (broadcast).'
                    % DHCP_TIPOS[res['dhcp']['tipo']], OBSERVADO)
        elif 'ip' in res and res['ip']['dst'] not in ('255.255.255.255',) and not res['ip']['dst'].startswith('224.'):
            destino = _ip(res['ip']['dst'])
            propias = [i for i in self._ips_de(e) if i.ip == _ip(res['ip']['src'])]
            if propias and destino in propias[0].network:
                self._d(d, 3, '%s está en su misma red (%s): lo entrega directo, sin router.'
                        % (destino, propias[0].network), INFERIDO)
            elif propias:
                ruta, momento = self._buscar_ruta(e, str(destino))
                via = ruta[1].get('gateway') if ruta else None
                self._d(d, 3, '%s está fuera de su red (%s): lo manda al gateway%s.'
                        % (destino, propias[0].network, ' %s' % via if via else ''), ESTADO if ruta else INFERIDO)
            eth = res.get('eth', {})
            self._d(d, 2, 'Arma la trama: MAC origen %s, MAC destino %s.'
                    % (self.describir_mac(eth.get('src', '')), self.describir_mac(eth.get('dst', ''))), OBSERVADO)
        self._d(d, 1, 'La envía por %s.' % intf, OBSERVADO)
        return {'dispositivo': e, 'nombre': self.nombre(e), 'tipo': self.nodos[e].tipo.value if e in self.nodos else None,
                'salida': capas(res, intf, self.describir_mac),
                'decisiones': [{'n': i, **x} for i, x in enumerate(d, start=1)]}

    def _causa(self, o):
        """Si es una respuesta, a qué responde (buscando hacia atrás lo que llegó al emisor)."""
        res = o.resumen
        e = o.emisor
        antes = [p for p in self.obs if p.nodo == e and p.ts_ns < o.ts_ns and o.ts_ns - p.ts_ns <= VENTANA_RESPUESTA_NS]
        for p in reversed(antes):
            pr = p.resumen
            if res.get('icmp', {}).get('tipo') == 0 and pr.get('icmp', {}).get('tipo') == 8 \
                    and pr['icmp'].get('seq') == res['icmp'].get('seq'):
                return 'Responde a la solicitud de eco que recibió (paquete %s).' % p.paquete
            if res.get('arp', {}).get('op') == 2 and pr.get('arp', {}).get('op') == 1 \
                    and pr['arp']['tpa'] == res['arp']['spa']:
                return 'Responde a la solicitud ARP que recibió (paquete %s).' % p.paquete
            if 'dhcp' in res and pr.get('dhcp', {}).get('xid') == res['dhcp']['xid'] and res['dhcp'].get('tipo') in (2, 5):
                return 'Responde al %s del cliente (paquete %s).' % (DHCP_TIPOS.get(pr['dhcp'].get('tipo'), 'DHCP'), p.paquete)
            if res.get('dns', {}).get('respuesta') and pr.get('dns', {}).get('id') == res['dns'].get('id'):
                return 'Responde a la consulta DNS que recibió (paquete %s).' % p.paquete
        if 'icmp' in res and res['icmp']['tipo'] == 8:
            return 'ping arma una solicitud de eco ICMP para %s.' % res['ip']['dst']
        return None
