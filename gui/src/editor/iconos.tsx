import type { TipoNodo } from '../api/tipos';

export function Icono({ tipo, tam = 40 }: { tipo: TipoNodo; tam?: number }) {
  const comun = { width: tam, height: tam, viewBox: '0 0 40 40', 'aria-hidden': true } as const;
  if (tipo === 'pc') {
    return (
      <svg {...comun}>
        <rect x="5" y="6" width="30" height="20" rx="2" fill="#e0f2fe" stroke="#0369a1" strokeWidth="2" />
        <rect x="16" y="27" width="8" height="4" fill="#0369a1" />
        <rect x="11" y="31" width="18" height="3" rx="1" fill="#0369a1" />
      </svg>
    );
  }
  if (tipo === 'switch') {
    return (
      <svg {...comun}>
        <rect x="3" y="11" width="34" height="18" rx="3" fill="#dcfce7" stroke="#15803d" strokeWidth="2" />
        <path d="M9 17h16l-3-3M31 23H15l3 3" fill="none" stroke="#15803d" strokeWidth="2" strokeLinecap="round" />
      </svg>
    );
  }
  if (tipo === 'servidor') {
    return (
      <svg {...comun}>
        <rect x="9" y="4" width="22" height="32" rx="2" fill="#ede9fe" stroke="#6d28d9" strokeWidth="2" />
        <path d="M13 12h14M13 19h14M13 26h14" stroke="#6d28d9" strokeWidth="2" strokeLinecap="round" />
        <circle cx="26" cy="31" r="1.6" fill="#6d28d9" />
      </svg>
    );
  }
  return (
    <svg {...comun}>
      <circle cx="20" cy="20" r="15" fill="#fef3c7" stroke="#b45309" strokeWidth="2" />
      <path d="M20 9v9M20 31v-9M9 20h9M31 20h-9" stroke="#b45309" strokeWidth="2" strokeLinecap="round" />
      <path d="M17 12l3-3 3 3M17 28l3 3 3-3M12 17l-3 3 3 3M28 17l3 3-3 3" fill="none" stroke="#b45309" strokeWidth="2" />
    </svg>
  );
}

export const NOMBRE_TIPO: Record<TipoNodo, string> = { pc: 'PC', switch: 'Switch', router: 'Router', servidor: 'Servidor' };
