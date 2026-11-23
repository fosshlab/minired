# Interfaz web de minired (etapa 2, MVP)

## Requisitos (VM de laboratorio)

Ubuntu 24.04 con el fork de Mininet (2.3.1b4+edu.1), Open vSwitch, tcpdump, tshark y ethtool.

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

## Pruebas

```bash
~/.venvs/minired/bin/python -m pytest                 # sin root (la prueba root se saltea)
(cd gui && npm test)                                  # lógica de reproducción
sudo ~/.venvs/minired/bin/python -m pytest -m root    # en la VM: Mininet + OVS + tcpdump + tshark
```

## Seguridad

Solo `127.0.0.1`; Host validado (DNS rebinding); token en `Authorization: Bearer` para REST y como
subprotocolo `token.<token>` en WebSocket; Origin obligatorio en WebSocket; sin CORS; CSP estricta.
La terminal es una shell root dentro del namespace del nodo: pensado para una VM por alumno.
