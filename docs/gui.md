# Interfaz web de minired

## Requisitos (VM de laboratorio)

Ubuntu 24.04 con el fork de Mininet (2.3.1b4+edu.1), Open vSwitch, tcpdump, tshark y ethtool.
Para las prácticas de la etapa 3: `apt install frr dnsmasq-base nftables busybox curl` (no hace falta
activar los servicios del sistema: minired lanza sus propias instancias dentro de cada nodo).

```bash
python3 -m venv --system-site-packages ~/.venvs/minired     # ve el paquete mininet del sistema
~/.venvs/minired/bin/pip install -e '.[pruebas]'
(cd gui && npm ci && npm run build)                          # o copiar gui/dist ya compilado
sudo ~/.venvs/minired/bin/python -m minired gui              # escucha solo en 127.0.0.1:8787
```

El comando muestra `http://127.0.0.1:8787/#token=…`: abrir esa dirección completa en el navegador
de la misma máquina (o por túnel: `ssh -L 8787:127.0.0.1:8787 usuario@vm`).

## Uso

1. Armar la red: arrastrar PC/Switch/Router desde la paleta; conectar arrastrando desde el punto
   verde de un equipo hasta otro (el puerto se asigna solo). IP y gateway en el panel derecho.
2. **Iniciar red**. Elegir una PC → **Abrir terminal** (bash dentro de su namespace).
3. **Simulación**: arranca un `tcpdump -Q in` en cada extremo de cada enlace. Hacer `ping -c 1`.
4. La barra amarilla reproduce lo capturado paso a paso (⏮ ◀ ▶ ⏭, velocidad, filtro). Las ramas de
   una inundación se ven en paralelo; una observación sin origen correlacionado se dibuja suelta,
   con borde punteado y "?".
5. Clic en un evento o en un sobre: capas decodificadas por tshark, explicación y bytes en hex.
6. **Descargar PCAP**: PCAPng con una interfaz por extremo, sentido "entrada" y el comentario
   `minired <observación> <paquete> <confianza>` en cada frame.

## Prácticas de la etapa 3

Cada una está en el menú **Ejemplos** de la barra superior.

| Tema | Cómo se configura en el panel | Qué hay debajo |
|---|---|---|
| VLAN y troncal | Switch → puerto: *acceso* (VLAN) o *troncal 802.1Q* (VLAN permitidas) | `ovs-vsctl set port … tag=` / `trunks= vlan_mode=trunk` |
| Inter-VLAN | Router → interfaz → *+ subinterfaz VLAN* (`r1-eth0.10`) | `ip link add link … type vlan` |
| Rutas | Router → *+ ruta estática* | `ip route`, o `ip route` en FRR si está activo |
| FRR y OSPF | Router → *FRRouting* y *OSPF área 0* | zebra, staticd y ospfd con `/etc/frr` y `/run/frr` privados del nodo |
| DHCP, DNS, HTTP | Servidor → *Servicios*; PC → *Pedir IP por DHCP* | dnsmasq, `busybox udhcpc`, `python3 -m http.server` |
| NAT y ACL | Router → interfaz → *NAT interior/exterior* y *ACL de entrada* | tabla `ip minired` de nftables en el namespace del router |

Con la red en marcha, **Ver estado** muestra direcciones, rutas, ARP, VLAN y tabla MAC de un switch,
`show ip route` y vecinos OSPF, reglas nftables con contadores y concesiones DHCP. En la terminal:
`vtysh` en un router con FRR y `renovar-dhcp` en una PC con DHCP.

Diferencias con Cisco que conviene explicar: FRR no es IOS (sintaxis parecida, no idéntica); la ACL
se aplica a lo que entra por la interfaz con un *deny any* implícito al final, pero la sintaxis es la
de nftables; una troncal lleva solo las VLAN permitidas, todas etiquetadas (sin VLAN nativa); el NAT
es PAT (masquerade) sobre la interfaz exterior.

Aislamiento: cada nodo tiene su propio `resolv.conf`; FRR usa carpetas privadas montadas solo en el
namespace del router (el FRR del sistema no se toca); las reglas nftables viven en el namespace del
router. Al detener la red se termina todo proceso que quede en los namespaces del laboratorio.

## Pruebas

```bash
~/.venvs/minired/bin/python -m pytest                 # sin root (la prueba root se saltea)
(cd gui && npm test)                                  # lógica de reproducción
sudo ~/.venvs/minired/bin/python -m pytest -m root    # en la VM: Mininet, OVS, tcpdump, tshark, FRR, dnsmasq, nft
```

## Seguridad

Solo `127.0.0.1`; Host validado (DNS rebinding); token en `Authorization: Bearer` para REST y como
subprotocolo `token.<token>` en WebSocket; Origin obligatorio en WebSocket; sin CORS; CSP estricta.
La terminal es una shell root dentro del namespace del nodo: pensado para una VM por estudiante.
