/**
 * Cliente de la API. Todo relativo al propio origen: la política de contenido
 * del backend prohíbe cualquier otro, así que una URL absoluta a un tercero
 * fallaría aquí antes de llegar a producción.
 */
import type {
  Almacenamiento, Escaneo, EventoDeProgreso, Evidencia, Hallazgo, Metricas,
  PeticionDeEscaneo, Proyecto, Superficie, Trabajo,
} from './types'

/**
 * Fases tras las que no llega nada más. Se enumeran en un sitio: olvidar una
 * deja la interfaz con el botón en «escaneando…» para siempre.
 */
export const FASES_FINALES = [
  'hecho', 'error', 'cancelado',
  'alcance-rechazado', 'ruta-invalida', 'aislamiento-imposible',
]

export class ErrorDeApi extends Error {
  constructor(message: string, readonly status: number) {
    super(message)
    this.name = 'ErrorDeApi'
  }
}

async function pedir<T>(ruta: string, init?: RequestInit): Promise<T> {
  const respuesta = await fetch(`/api${ruta}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (!respuesta.ok) {
    // El backend devuelve {detail: "..."} en los errores; se prefiere ese
    // mensaje al genérico, porque suele explicar qué hacer.
    const cuerpo = await respuesta.json().catch(() => null)
    throw new ErrorDeApi(cuerpo?.detail ?? respuesta.statusText, respuesta.status)
  }
  return respuesta.json() as Promise<T>
}

export const api = {
  salud: () => pedir<{ ok: boolean; version: string; perfiles: string[] }>('/health'),
  proyectos: () => pedir<Proyecto[]>('/projects'),

  escaneos: (project?: string) =>
    pedir<Escaneo[]>(`/scans${project ? `?project=${encodeURIComponent(project)}` : ''}`),
  escaneo: (id: number) => pedir<Escaneo & { tareas: unknown[] }>(`/scans/${id}`),
  hallazgos: (scanId: number) => pedir<Hallazgo[]>(`/scans/${scanId}/findings`),
  evidencia: (findingId: number) => pedir<Evidencia[]>(`/findings/${findingId}/evidence`),
  superficie: (scanId: number) => pedir<Superficie>(`/scans/${scanId}/surface`),
  metricas: (projectId: number) => pedir<Metricas>(`/projects/${projectId}/metrics`),

  almacenamiento: () => pedir<Almacenamiento>('/storage'),
  borrarEscaneos: (ids: number[]) =>
    pedir<{ borrados: number[]; triajes_huerfanos: number; bytes_liberados: number }>(
      '/scans/delete', { method: 'POST', body: JSON.stringify({ ids }) },
    ),

  triar: (projectId: number, fingerprint: string, status: string, note = '') =>
    pedir<{ fingerprint: string; status: string }>(
      `/projects/${projectId}/findings/${fingerprint}`,
      { method: 'PATCH', body: JSON.stringify({ status, note }) },
    ),

  aislamiento: () => pedir<{ disponible: boolean; motivo: string }>('/sandbox'),

  trabajos: () => pedir<Trabajo[]>('/jobs'),
  lanzar: (cuerpo: PeticionDeEscaneo) =>
    pedir<Trabajo>('/jobs', { method: 'POST', body: JSON.stringify(cuerpo) }),
  cancelar: (jobId: string) => pedir<unknown>(`/jobs/${jobId}`, { method: 'DELETE' }),

  informe: (scanId: number, formato: 'html' | 'pdf') =>
    `/api/scans/${scanId}/report.${formato}`,
}

/**
 * Sigue el progreso de un trabajo por SSE.
 *
 * El backend reenvía primero lo ya ocurrido, de modo que abrir la página a
 * mitad de escaneo no muestra una barra vacía. Devuelve la función para
 * cerrar la conexión: dejarla abierta mantiene vivo un worker en el servidor.
 */
export function seguirTrabajo(
  jobId: string,
  alAvanzar: (evento: EventoDeProgreso) => void,
  alTerminar?: () => void,
): () => void {
  const fuente = new EventSource(`/api/jobs/${jobId}/events`)
  fuente.onmessage = (mensaje) => {
    const evento = JSON.parse(mensaje.data) as EventoDeProgreso
    if (evento.fase === 'latido') return
    alAvanzar(evento)
    if (FASES_FINALES.includes(evento.fase)) {
      fuente.close()
      alTerminar?.()
    }
  }
  fuente.onerror = () => {
    fuente.close()
    alTerminar?.()
  }
  return () => fuente.close()
}
