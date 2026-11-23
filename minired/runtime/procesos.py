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


def inodo_netns(pid):
    """Identificador (inodo) del namespace de red del proceso, o None si ya no existe."""
    try:
        return os.stat('/proc/%d/ns/net' % pid).st_ino
    except OSError:
        return None


def pids_en_netns(inodos, excepto=()):
    """PIDs de los procesos que viven en alguno de esos namespaces de red."""
    pids = []
    propio = os.getpid()
    for entrada in os.listdir('/proc'):
        if not entrada.isdigit():
            continue
        pid = int(entrada)
        if pid == propio or pid in excepto:
            continue
        if inodo_netns(pid) in inodos:
            pids.append(pid)
    return pids


def matar_netns(inodos, excepto=(), espera=2.0):
    """Termina todo proceso que quede en los namespaces del laboratorio.

    Un daemon vivo (FRR, dnsmasq, un servidor que el alumno dejó con nohup)
    mantiene el namespace y sus interfaces aunque Mininet haya terminado el nodo.
    Primero SIGTERM (FRR y dnsmasq cierran prolijo), después SIGKILL.
    """
    import time
    # Nunca el namespace del sistema (donde viven los switches OVS y este servidor).
    inodos = {i for i in inodos if i is not None} - {inodo_netns(1), inodo_netns(os.getpid())}
    if not inodos:
        return []
    pids = pids_en_netns(inodos, excepto)
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    limite = time.monotonic() + espera
    while time.monotonic() < limite and pids_en_netns(inodos, excepto):
        time.sleep(0.05)
    restos = pids_en_netns(inodos, excepto)
    for pid in restos:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return pids
