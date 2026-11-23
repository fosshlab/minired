# Agradecimientos

- **Mininet** (https://github.com/mininet/mininet), BSD-3-Clause: minired usa el
  fork https://github.com/mendezgarabetti/mininet como motor. No se copia su código.
- **latarc/mininet-gui** (BSD-3-Clause): inspiración para la terminal por PTY dentro del
  namespace y para capturar en cada extremo de veth. Se reimplementaron las ideas, sin copiar código.
- Interfaz: React, React Flow (`@xyflow/react`), xterm.js y zustand (MIT). Backend: FastAPI,
  Starlette, Uvicorn y Pydantic (MIT/BSD). Binarios invocados como procesos: tcpdump (BSD-3),
  tshark (GPL-2.0+), Open vSwitch (Apache-2.0).
