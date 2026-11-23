"""Un único hilo dueño de la red: todas las operaciones de Mininet pasan por su cola.

Mininet no es seguro entre hilos y sus llamadas bloquean, así que el servidor
(asyncio) nunca lo toca directamente: encola una función y espera su futuro.
"""

import asyncio
import concurrent.futures
import queue
import threading


class Worker:
    def __init__(self, nombre='minired-red'):
        self._cola = queue.Queue()
        self._hilo = threading.Thread(target=self._bucle, name=nombre, daemon=True)
        self._hilo.start()

    def _bucle(self):
        while True:
            item = self._cola.get()
            if item is None:
                return
            fn, futuro = item
            if not futuro.set_running_or_notify_cancel():
                continue
            try:
                futuro.set_result(fn())
            except BaseException as exc:  # se propaga al que espera
                futuro.set_exception(exc)

    def enviar(self, fn):
        futuro = concurrent.futures.Future()
        self._cola.put((fn, futuro))
        return futuro

    async def run(self, fn):
        return await asyncio.wrap_future(self.enviar(fn))

    def en_hilo(self):
        return threading.current_thread() is self._hilo

    def cerrar(self, timeout=None):
        self._cola.put(None)
        self._hilo.join(timeout)
