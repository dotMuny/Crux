export type Severidad = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type EstadoTriaje = 'new' | 'confirmed' | 'false_positive' | 'fixed' | 'accepted_risk'

export interface Hallazgo {
  id: number
  fingerprint: string
  source: string
  check_id: string
  title: string
  description: string
  remediation: string
  severity: Severidad
  confidence: number
  cvss_score: number | null
  cwe: string[]
  owasp: string[]
  target: string
  param: string | null
  tags: string[]
  extra: Record<string, unknown>
  status: EstadoTriaje
  note: string
  first_seen: string | null
  evidencias: number
}

export interface Evidencia {
  id: number
  kind: string
  request: string | null
  response: string | null
  snippet: string | null
  path: string | null
  meta: Record<string, unknown>
}

export interface Escaneo {
  id: number
  project_id: number
  kind: string
  profile: string
  status: string
  started_at: string | null
  finished_at: string | null
  duracion: number | null
  error: string | null
  targets: string[]
  por_severidad: Partial<Record<Severidad, number>>
  hallazgos: number
}

export interface Proyecto {
  id: number
  slug: string
  name: string
  created_at: string
  escaneos: number
}

/**
 * Cómo entra el escáner en la aplicación. Son los tres modos que el producto
 * cubre: formulario, cabecera fija, o una sesión capturada a mano.
 *
 * Esto viaja del navegador al servidor y se usa en memoria. No se guarda ni
 * vuelve en ninguna respuesta: lo que la API devuelve de una sesión es su modo
 * («formulario», «cabecera») y nada más.
 */
export interface Credenciales {
  url_login?: string | null
  usuario?: string | null
  clave?: string | null
  selector_usuario?: string | null
  selector_clave?: string | null
  cabeceras?: Record<string, string>
  cookies?: Record<string, string>
  senal_de_exito?: string | null
}

export interface Rol {
  nombre: string
  rol: string
  credenciales: Credenciales
}

export interface PeticionDeEscaneo {
  targets: string[]
  tipo?: 'web' | 'code'
  profile?: string
  project?: string
  allow_public?: boolean
  only?: string[] | null
  credenciales?: Credenciales | null
  roles?: Rol[]
  sandbox?: boolean
}

export interface Trabajo {
  id: string
  targets: string[]
  tipo: 'web' | 'code'
  profile: string
  project: string
  // Modo de la sesión usada: «ninguna», «formulario», «cabecera» o «cookies».
  autenticacion: string
  // Nombres de los roles comparados. Solo nombres.
  roles: string[]
  sandbox: boolean
  estado: 'en-cola' | 'ejecutando' | 'hecho' | 'fallido' | 'cancelado'
  scan_id: number | null
  fase: string
  mensaje: string
  progreso: number
  error: string | null
  creado: string
  terminado: string | null
  resumen: Record<string, unknown>
  // Lo que la API acepta pero conviene decir: p. ej. un solo rol, que no
  // permite comparar nada.
  avisos?: string[]
}

export interface EventoDeProgreso {
  ts: number
  fase: string
  mensaje: string
  progreso: number
}


// ── Panel ──────────────────────────────────────────────────────────────────
export interface Metricas {
  tendencia: Record<string, any>[]
  triaje: Record<string, number>
  resumen: {
    escaneos: number
    hallazgos?: number
    graves?: number
    pendientes?: number
    abiertos?: number
    ultimo?: {
      id: number; kind: string; profile: string; status: string
      fecha: string | null; duracion: number | null
      tareas_fallidas: number; tareas_omitidas: number
    }
  }
  por_herramienta: Record<string, number>
  top_checks: {
    source: string; check_id: string; titulo: string
    severidad: Severidad; total: number
  }[]
  top_objetivos: { objetivo: string; total: number; peor: Severidad; rutas: number }[]
  antiguedad: {
    tramos: Record<string, number>
    mas_viejos: {
      titulo: string; objetivo: string; dias: number
      severidad: Severidad; estado: string; fingerprint: string
    }[]
  }
  cobertura: {
    origenes?: string[]; comprobaciones?: string[]
    conteo?: {
      producidos: number; colapsados_por_huella: number
      absorbidos_por_otro_mejor: number; guardados: number; descuadre?: number
    }
    tareas: {
    name: string; tool: string; status: string; error: string | null
  }[] }
  cambio: {
    antes: number; ahora: number; nuevos: number; corregidos: number
    persistentes: number; sin_comprobar: number; empeoran: number
    hay_regresion: boolean
  } | null
}

// ── Superficie ─────────────────────────────────────────────────────────────
export interface NodoDeSuperficie {
  data: {
    id: string
    label: string
    tipo: 'host' | 'servicio' | 'ruta' | 'hallazgo'
    severidad?: Severidad
    sin_hallazgos?: boolean
    finding_id?: number
    fingerprint?: string
    detalle: Record<string, any>
  }
}

export interface Superficie {
  nodes: NodoDeSuperficie[]
  edges: { data: { source: string; target: string } }[]
  resumen: {
    hosts: number; servicios: number; rutas: number
    rutas_sin_hallazgos: number; rutas_con_parametros: number
    hallazgos: number; hallazgos_dibujados: number; hallazgos_sin_ubicar: number
    paginas_visitadas: number; hubo_recorrido: boolean
    fuera_de_alcance: string[]
    // Falso en escaneos guardados antes de que se registrara la superficie:
    // de esos solo se puede dibujar el árbol de sus hallazgos.
    superficie_registrada: boolean
    es_codigo: boolean
  }
}

export interface Almacenamiento {
  directorio: string
  piezas: { nombre: string; ruta: string; bytes: number }[]
  escaneos: number
  hallazgos: number
}
