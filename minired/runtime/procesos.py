"""Utilidades para terminar procesos sin dejar restos."""

import os
import signal


def pids_de_sesion(sid):
    """PIDs cuyo id de sesión es `sid` (leído de /proc/<pid>/stat)."""
    pids = []
    for entrada in os.listdir('/proc'):
        if not entrada.isdigit():
            continue
        try:
            with open('/proc/%s/stat' % entrada, 'rb') as f:
                stat = f.read()
        except OSError:
            continue
        # el nombre del comando va entre paréntesis y puede tener espacios
        campos = stat[stat.rfind(b')') + 2:].split()
        if len(campos) > 3 and int(campos[3]) == sid:
            pids.append(int(entrada))
    return pids


def matar_sesion(sid, senal=signal.SIGKILL):
    """Mata todos los procesos de la sesión (bash de la terminal y lo que haya lanzado)."""
    for pid in pids_de_sesion(sid):
        try:
            os.kill(pid, senal)
        except ProcessLookupError:
            pass
