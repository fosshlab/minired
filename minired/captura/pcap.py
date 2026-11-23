"""Lectura incremental de PCAP clásico y escritura de PCAPng, solo con stdlib.

tcpdump escribe por stdout un PCAP clásico (sin nombre de interfaz ni sentido).
Para la descarga se arma un PCAPng con un bloque de interfaz por extremo de
enlace, el sentido "entrada" en cada paquete y un comentario con los ids que
usa la interfaz web, de modo que Wireshark/tshark muestren lo mismo.
"""

import struct

MAGIC_US = 0xA1B2C3D4
MAGIC_NS = 0xA1B23C4D
LINKTYPE_ETHERNET = 1


class ErrorPcap(Exception):
    pass


class Registro:
    __slots__ = ('n', 'ts_ns', 'largo_original', 'datos')

    def __init__(self, n, ts_ns, largo_original, datos):
        self.n = n                      # número de frame dentro del archivo (desde 1, como tshark)
        self.ts_ns = ts_ns
        self.largo_original = largo_original
        self.datos = datos


class LectorIncremental:
    """Recibe trozos de bytes en cualquier corte y devuelve registros completos."""

    def __init__(self):
        self._buf = bytearray()
        self._endian = None
        self._factor = None
        self.linktype = None
        self._n = 0

    def alimentar(self, trozo):
        self._buf += trozo
        salida = []
        if self._endian is None:
            if len(self._buf) < 24:
                return salida
            self._cabecera(bytes(self._buf[:24]))
            del self._buf[:24]
        while len(self._buf) >= 16:
            sec, frac, incl, orig = struct.unpack(self._endian + 'IIII', self._buf[:16])
            if incl > 262144 + 64:
                raise ErrorPcap('registro demasiado grande (%d bytes): flujo corrupto' % incl)
            if len(self._buf) < 16 + incl:
                break
            datos = bytes(self._buf[16:16 + incl])
            del self._buf[:16 + incl]
            self._n += 1
            salida.append(Registro(self._n, sec * 1_000_000_000 + frac * self._factor, orig, datos))
        return salida

    def _cabecera(self, cab):
        for endian in ('<', '>'):
            (magic,) = struct.unpack(endian + 'I', cab[:4])
            if magic in (MAGIC_US, MAGIC_NS):
                self._endian = endian
                self._factor = 1 if magic == MAGIC_NS else 1000
                self.linktype = struct.unpack(endian + 'I', cab[20:24])[0]
                return
        raise ErrorPcap('no es un archivo pcap')


def leer_archivo(ruta):
    lector = LectorIncremental()
    with open(ruta, 'rb') as f:
        return lector.alimentar(f.read())


# --- PCAPng -----------------------------------------------------------------

def _opcion(codigo, valor):
    relleno = (-len(valor)) % 4
    return struct.pack('<HH', codigo, len(valor)) + valor + b'\0' * relleno


def _bloque(tipo, cuerpo):
    largo = 12 + len(cuerpo)
    return struct.pack('<II', tipo, largo) + cuerpo + struct.pack('<I', largo)


def _fin_opciones():
    return struct.pack('<HH', 0, 0)


def escribir_pcapng(f, interfaces, paquetes, aplicacion='minired'):
    """interfaces: lista de (nombre, descripcion); paquetes: (idx_intf, ts_ns, largo_orig, datos, comentario).

    Los paquetes se escriben en el orden dado. Todos se marcan como "entrada" (se capturan con -Q in).
    """
    shb = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    shb += _opcion(4, aplicacion.encode()) + _fin_opciones()   # shb_userappl
    f.write(_bloque(0x0A0D0D0A, shb))
    for nombre, descripcion in interfaces:
        idb = struct.pack('<HHI', LINKTYPE_ETHERNET, 0, 0)
        idb += _opcion(2, nombre.encode())                     # if_name
        idb += _opcion(3, descripcion.encode())                # if_description
        idb += _opcion(9, bytes([9]))                          # if_tsresol: 10^-9
        idb += _fin_opciones()
        f.write(_bloque(0x00000001, idb))
    for idx, ts_ns, largo_orig, datos, comentario in paquetes:
        epb = struct.pack('<IIIII', idx, ts_ns >> 32, ts_ns & 0xFFFFFFFF, len(datos), largo_orig)
        epb += datos + b'\0' * ((-len(datos)) % 4)
        if comentario:
            epb += _opcion(1, comentario.encode())             # opt_comment
        epb += _opcion(2, struct.pack('<I', 0x1))              # epb_flags: entrada
        epb += _fin_opciones()
        f.write(_bloque(0x00000006, epb))
