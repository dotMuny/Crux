/**
 * Estado compartido: qué proyecto y qué escaneo se están mirando, sus
 * hallazgos y los filtros activos.
 *
 * El filtrado ocurre en el cliente a propósito. Un escaneo interno produce
 * cientos de hallazgos, no millones, y tenerlos en memoria hace que cambiar
 * una faceta sea instantáneo en lugar de un viaje al servidor por clic —que
 * es lo que separa triar con gusto de triar a desgana.
 */
import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api } from '@/api/client'
import type { Escaneo, Hallazgo, Proyecto, Severidad } from '@/api/types'

export const ORDEN_SEVERIDAD: Severidad[] = ['critical', 'high', 'medium', 'low', 'info']

export const useSesion = defineStore('sesion', () => {
  const proyectos = ref<Proyecto[]>([])
  const escaneos = ref<Escaneo[]>([])
  const hallazgos = ref<Hallazgo[]>([])
  const escaneoActual = ref<number | null>(null)
  const cargando = ref(false)
  const error = ref<string | null>(null)

  const filtroSeveridad = ref(new Set<string>())
  const filtroOrigen = ref(new Set<string>())
  const filtroEstado = ref(new Set<string>())
  const busqueda = ref('')
  const seleccionado = ref<number | null>(null)

  const escaneo = computed(() =>
    escaneos.value.find((e) => e.id === escaneoActual.value) ?? null)

  const proyectoActual = computed(() =>
    proyectos.value.find((p) => p.id === escaneo.value?.project_id) ?? null)

  const visibles = computed(() => {
    const texto = busqueda.value.trim().toLowerCase()
    return hallazgos.value.filter((h) => {
      if (filtroSeveridad.value.size && !filtroSeveridad.value.has(h.severity)) return false
      if (filtroOrigen.value.size && !filtroOrigen.value.has(h.source)) return false
      if (filtroEstado.value.size && !filtroEstado.value.has(h.status)) return false
      if (!texto) return true
      return `${h.title} ${h.target} ${h.check_id} ${h.cwe.join(' ')} ${h.source}`
        .toLowerCase()
        .includes(texto)
    })
  })

  const actual = computed(() =>
    hallazgos.value.find((h) => h.id === seleccionado.value) ?? visibles.value[0] ?? null)

  function cuenta(campo: 'severity' | 'source' | 'status') {
    const conteo: Record<string, number> = {}
    for (const h of hallazgos.value) conteo[h[campo]] = (conteo[h[campo]] ?? 0) + 1
    return conteo
  }

  function alternar(cual: 'severidad' | 'origen' | 'estado', valor: string) {
    const conjunto = { severidad: filtroSeveridad, origen: filtroOrigen, estado: filtroEstado }[cual]
    const copia = new Set(conjunto.value)
    copia.has(valor) ? copia.delete(valor) : copia.add(valor)
    // Se reemplaza el Set entero: mutarlo no dispara la reactividad de Vue.
    conjunto.value = copia
  }

  function limpiarFiltros() {
    filtroSeveridad.value = new Set()
    filtroOrigen.value = new Set()
    filtroEstado.value = new Set()
    busqueda.value = ''
  }

  async function cargar() {
    cargando.value = true
    error.value = null
    try {
      const [p, e] = await Promise.all([api.proyectos(), api.escaneos()])
      proyectos.value = p
      escaneos.value = e
      if (e.length && escaneoActual.value === null) await abrirEscaneo(e[0].id)
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e)
    } finally {
      cargando.value = false
    }
  }

  async function abrirEscaneo(id: number) {
    cargando.value = true
    try {
      escaneoActual.value = id
      hallazgos.value = await api.hallazgos(id)
      seleccionado.value = hallazgos.value[0]?.id ?? null
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e)
    } finally {
      cargando.value = false
    }
  }

  async function triar(h: Hallazgo, estado: string, nota = '') {
    const proyecto = escaneo.value?.project_id
    if (!proyecto) return
    const anterior = h.status
    // Optimista: el triaje es la acción que más se repite y esperar al
    // servidor en cada clic se nota. Si falla, se revierte y se avisa.
    h.status = estado as Hallazgo['status']
    h.note = nota
    try {
      await api.triar(proyecto, h.fingerprint, estado, nota)
    } catch (e) {
      h.status = anterior
      error.value = e instanceof Error ? e.message : String(e)
    }
  }

  /**
   * Borra escaneos y recarga la lista.
   *
   * Si el que estaba abierto era uno de ellos, se suelta antes de recargar:
   * dejar apuntando a un escaneo que ya no existe deja la vista de hallazgos
   * con datos de algo borrado.
   */
  async function borrarEscaneos(ids: number[]) {
    const resultado = await api.borrarEscaneos(ids)
    if (escaneoActual.value !== null && ids.includes(escaneoActual.value)) {
      escaneoActual.value = null
      hallazgos.value = []
      seleccionado.value = null
    }
    await cargar()
    return resultado
  }

  function mover(delta: number) {
    const lista = visibles.value
    if (!lista.length) return
    const i = lista.findIndex((h) => h.id === actual.value?.id)
    const siguiente = lista[Math.min(Math.max(i + delta, 0), lista.length - 1)]
    if (siguiente) seleccionado.value = siguiente.id
  }

  return {
    proyectos, escaneos, hallazgos, escaneoActual, cargando, error,
    filtroSeveridad, filtroOrigen, filtroEstado, busqueda, seleccionado,
    escaneo, proyectoActual, visibles, actual,
    cuenta, alternar, limpiarFiltros, cargar, abrirEscaneo, triar, mover,
    borrarEscaneos,
  }
})
