"""`minired gui`: servidor local de la interfaz web (solo 127.0.0.1, con token)."""

import argparse
import os
import sys

from . import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(prog='minired', description='Capa educativa sobre Mininet')
    parser.add_argument('--version', action='version', version='minired ' + __version__)
    sub = parser.add_subparsers(dest='comando', required=True)
    gui = sub.add_parser('gui', help='abrir la interfaz web')
    gui.add_argument('--puerto', type=int, default=8787)
    gui.add_argument('--origen-extra', action='append', default=[],
                     help='origen adicional permitido (p. ej. el servidor de desarrollo de Vite)')
    gui.add_argument('--token-archivo',
                     help='escribir el token en este archivo (permisos 0600) para pruebas automáticas')
    gui.add_argument('--capturas', help='directorio base de las capturas (por defecto, el temporal)')
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        print('minired gui necesita root (Mininet crea namespaces, veth y bridges OVS).\n'
              'Ejecutalo con sudo dentro de la VM de laboratorio.', file=sys.stderr)
        return 1
    if not 1024 <= args.puerto <= 65535:
        parser.error('puerto fuera de rango')

    import uvicorn

    from .runtime.controlador import Controlador
    from .runtime.edunet import RedMininet
    from .servidor.app import crear_app
    from .servidor.seguridad import Config, nuevo_token

    config = Config(puerto=args.puerto, token=nuevo_token(), origenes_extra=args.origen_extra)
    if args.token_archivo:
        fd = os.open(args.token_archivo, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(config.token)
    os.umask(0o077)
    app = crear_app(Controlador(RedMininet, args.capturas), config)
    print('\n  minired %s\n  Abrí en el navegador de esta máquina:\n\n    http://127.0.0.1:%d/#token=%s\n'
          % (__version__, args.puerto, config.token), flush=True)
    uvicorn.run(app, host='127.0.0.1', port=args.puerto, log_level='warning', proxy_headers=False,
                server_header=False, date_header=False, ws_max_size=1 << 20)
    return 0


if __name__ == '__main__':
    sys.exit(main())
