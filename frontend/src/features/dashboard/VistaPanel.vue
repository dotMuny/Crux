<script setup lang="ts">
/**
 * Panel de métricas del proyecto.
 *
 * El criterio de qué entra aquí: una cifra merece sitio si cambia lo que harías
 * a continuación. «Cuántos hallazgos hay» no lo hace —siempre hay—; «cuántos
 * quedan sin mirar», «qué comprobación se repite más» y «qué lleva más tiempo
 * abierto» sí: la primera dice cuánto trabajo queda, la segunda por dónde
 * empezar para cerrar muchos de golpe, la tercera qué se está quedando atrás.
 *
 * Reglas de dibujo que se siguen aquí y por qué:
 * — Las cifras de titular son fichas, no gráficas: un número no mejora por
 *   dibujarlo.
 * — La tendencia son barras apiladas y no un área, porque los escaneos son
 *   sucesos discretos, no una serie continua.
 * — El color de severidad es refuerzo redundante: cada segmento lleva su
 *   etiqueta y hay leyenda. La rampa rojo-naranja-amarillo es indistinguible
 *   bajo protanopía (ΔE 1,0 medido), así que nadie debe depender del color
 *   para leer esto. Ver docs/decisiones.md §18.
 * — Hay vista de tabla: la gráfica no es la única forma de llegar al dato.
 */
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useSesion, ORDEN_SEVERIDAD } from '@/stores/sesion'
import Severidad from '@/components/Severidad.vue'
import type { Metricas, Severidad as NivelSeveridad } from '@/api/types'

const sesion = useSesion()
const router = useRouter()
const lienzo = ref<HTMLElement | null>(null)
const grafica = shallowRef<any>(null)
const datos = ref<Metricas | null>(null)
const comoTabla = ref(false)

const SEV_ES: Record<NivelSeveridad, string> = {
  critical: 'crítica', high: 'alta', medium: 'media', low: 'baja', info: 'info',
}
const ESTADO_ES: Record<string, string> = {
  new: 'sin triar', confirmed: 'confirmado', false_positive: 'falso positivo',
  fixed: 'corregido', accepted_risk: 'riesgo aceptado',
}
const TAREA_ES: Record<string, string> = {
  done: 'hecha', failed: 'falló', skipped: 'omitida',
  running: 'en curso', pending: 'pendiente',
}

function leer(nombre: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(nombre).trim()
}

const resumen = computed(() => datos.value?.resumen ?? null)
const ultimo = computed(() => resumen.value?.ultimo ?? null)

/**
 * Las cinco cifras del titular, en orden de lo que se hace con ellas:
 * cuánto queda por mirar, cuánto sigue abierto, cuánto es grave.
 */
const fichas = computed(() => {
  const r = resumen.value
  if (!r || !r.ultimo) return []
  const c = datos.value?.cambio
  return [
    { k: 'Sin triar', v: r.pendientes ?? 0, acento: (r.pendientes ?? 0) > 0,
      pie: 'nadie los ha mirado todavía' },
    { k: 'Abiertos', v: r.abiertos ?? 0,
      pie: 'nuevos y confirmados, sin descartar' },
    { k: 'Críticos y altos', v: r.graves ?? 0, grave: (r.graves ?? 0) > 0,
      pie: 'en el último escaneo' },
    { k: 'Nuevos', v: c?.nuevos ?? null, delta: true,
      pie: c ? `frente al escaneo #${c.antes}` : 'no hay con qué comparar' },
    { k: 'Escaneos', v: r.escaneos, pie: 'en este proyecto' },
  ]
})

const hayCambio = computed(() => datos.value?.cambio != null)

const conteo = computed(() => datos.value?.cobertura.conteo ?? null)

const tareasConPega = computed(() =>
  (datos.value?.cobertura.tareas ?? []).filter(
    (t) => t.status === 'failed' || t.status === 'skipped'))

function duracion(segundos: number | null | undefined) {
  if (segundos == null) return '—'
  const m = Math.floor(segundos / 60)
  return m ? `${m} min ${String(Math.round(segundos % 60)).padStart(2, '0')} s`
           : `${Math.round(segundos)} s`
}

function fecha(iso: string | null | undefined) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('es', {
    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
  })
}

/** Lleva al triaje ya filtrado por lo que se acaba de pulsar. */
function irAHallazgos(texto: string) {
  sesion.limpiarFiltros()
  sesion.busqueda = texto
  router.push('/hallazgos')
}

async function pintar() {
  const proyecto = sesion.escaneo?.project_id
  if (!proyecto) return
  datos.value = await api.metricas(proyecto)
  if (comoTabla.value || !lienzo.value || !datos.value) return

  // El registro de ECharts vive en su propio módulo con importaciones
  // estáticas, que es lo que permite descartar lo que no se usa. Se carga
  // aquí, en perezoso: el panel no es la primera pantalla.
  const { echarts } = await import('./echarts')
  grafica.value?.dispose()
  grafica.value = echarts.init(lienzo.value, null, { renderer: 'svg' })

  const tinta = leer('--cx-fg-dim')
  const superficie = leer('--cx-bg')
  const TOKEN: Record<NivelSeveridad, string> = {
    critical: leer('--cx-crit'), high: leer('--cx-high'), medium: leer('--cx-med'),
    low: leer('--cx-low'), info: leer('--cx-info'),
  }

  grafica.value.setOption({
    backgroundColor: 'transparent',
    textStyle: { fontFamily: leer('--cx-sans'), color: tinta },
    grid: { left: 44, right: 16, top: 40, bottom: 28 },
    legend: {
      // Con cinco series la leyenda es obligatoria: la identidad no puede
      // depender solo del color.
      top: 0, left: 0, itemWidth: 9, itemHeight: 9, itemGap: 16,
      textStyle: { color: tinta, fontSize: 11 },
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(255,255,255,.04)' } },
      backgroundColor: leer('--cx-surface-2'),
      borderColor: leer('--cx-border-strong'),
      textStyle: { color: leer('--cx-fg'), fontSize: 12, fontFamily: leer('--cx-mono') },
    },
    xAxis: {
      type: 'category',
      data: datos.value.tendencia.map((t) => `#${t.scan_id}`),
      axisLine: { lineStyle: { color: leer('--cx-border') } },
      axisTick: { show: false },
      axisLabel: { color: leer('--cx-fg-faint'), fontFamily: leer('--cx-mono'), fontSize: 11 },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      // Rejilla recesiva: la cuadrícula orienta, no compite con los datos.
      splitLine: { lineStyle: { color: leer('--cx-border'), type: 'dashed' } },
      axisLabel: { color: leer('--cx-fg-faint'), fontFamily: leer('--cx-mono'), fontSize: 11 },
    },
    series: ORDEN_SEVERIDAD.map((nivel) => ({
      name: SEV_ES[nivel],
      type: 'bar',
      stack: 'severidad',
      barMaxWidth: 34,
      itemStyle: {
        color: TOKEN[nivel],
        // Separador de 2px del color de la superficie entre segmentos: es lo
        // que permite contar los bloques cuando dos tonos se parecen.
        borderColor: superficie,
        borderWidth: 2,
      },
      label: {
        // Etiqueta directa en cada segmento: el refuerzo que hace que el color
        // no sea imprescindible.
        show: true,
        color: leer('--cx-sev-ink'),
        fontFamily: leer('--cx-mono'),
        fontSize: 10,
        formatter: (p: any) => (p.value > 0 ? p.value : ''),
      },
      data: datos.value!.tendencia.map((t) => t[nivel] ?? 0),
    })),
  })
}

function redimensionar() { grafica.value?.resize() }

onMounted(() => {
  pintar()
  window.addEventListener('resize', redimensionar)
})
watch([() => sesion.escaneo?.project_id, () => sesion.escaneoActual, comoTabla], pintar)
onBeforeUnmount(() => {
  window.removeEventListener('resize', redimensionar)
  grafica.value?.dispose()
})
</script>

<template>
  <div class="overflow-y-auto">
    <div class="max-w-[1080px] mx-auto px-5 py-8 flex flex-col gap-8">
      <div class="flex items-baseline gap-4 flex-wrap">
        <h1 class="m-0 text-[21px] font-normal">
          {{ sesion.proyectoActual?.name ?? 'Proyecto' }}
        </h1>
        <p v-if="ultimo" class="m-0 font-mono text-[12px] text-fg-faint">
          último: #{{ ultimo.id }} · {{ ultimo.profile }} ·
          {{ fecha(ultimo.fecha) }} · {{ duracion(ultimo.duracion) }}
        </p>
      </div>

      <!-- Cifras de titular: fichas, no gráficas. -->
      <dl class="grid gap-px bg-line border border-line"
          style="grid-template-columns: repeat(auto-fit, minmax(150px, 1fr))">
        <div v-for="f in fichas" :key="f.k" class="bg-surface px-4 py-3 min-w-0">
          <dt class="lbl mb-[5px]">{{ f.k }}</dt>
          <dd class="m-0 font-mono text-[27px] leading-none tabular-nums"
              :class="f.grave ? 'text-crit' : f.acento ? 'text-accent' : ''">
            {{ f.v ?? '—' }}
          </dd>
          <p class="m-0 mt-[6px] text-[11px] text-fg-faint leading-tight">{{ f.pie }}</p>
        </div>
      </dl>

      <!-- Lo que cambió: la sección que de verdad dice si vas ganando. -->
      <section v-if="hayCambio && datos?.cambio" class="flex flex-col gap-3">
        <div class="flex items-baseline gap-3 flex-wrap">
          <h2 class="lbl m-0">
            Desde el escaneo #{{ datos.cambio.antes }}
          </h2>
          <span v-if="datos.cambio.hay_regresion" class="text-[12px] text-high">
            hay regresión: algo nuevo o algo que empeora
          </span>
        </div>
        <div class="grid gap-px bg-line border border-line"
             style="grid-template-columns: repeat(auto-fit, minmax(128px, 1fr))">
          <div v-for="c in [
                 { k: 'Nuevos', v: datos.cambio.nuevos, tono: 'text-high' },
                 { k: 'Corregidos', v: datos.cambio.corregidos, tono: 'text-accent' },
                 { k: 'Persisten', v: datos.cambio.persistentes, tono: '' },
                 { k: 'Empeoran', v: datos.cambio.empeoran, tono: 'text-crit' },
                 { k: 'Sin comprobar', v: datos.cambio.sin_comprobar, tono: 'text-med' },
               ]" :key="c.k" class="bg-surface px-4 py-3">
            <dt class="lbl mb-[5px]">{{ c.k }}</dt>
            <dd class="m-0 font-mono text-[20px] leading-none tabular-nums"
                :class="c.v ? c.tono : 'text-fg-faint'">{{ c.v }}</dd>
          </div>
        </div>
        <p v-if="datos.cambio.sin_comprobar" class="m-0 text-[12px] text-med">
          «Sin comprobar» no es «corregido»: esos hallazgos desaparecieron sin
          que esta vez se buscaran —otro perfil, una herramienta ausente, un
          adaptador que falló—, así que nadie puede decir si siguen ahí.
        </p>
      </section>

      <section class="flex flex-col gap-3">
        <div class="flex items-center gap-3">
          <h2 class="lbl m-0">Severidad por escaneo</h2>
          <button
            class="ml-auto text-[12px] text-accent hover:underline"
            @click="comoTabla = !comoTabla"
          >{{ comoTabla ? 'ver gráfica' : 'ver tabla' }}</button>
        </div>

        <div v-show="!comoTabla" ref="lienzo"
             class="h-[300px] w-full border border-line bg-surface rounded-cx" />

        <table v-if="comoTabla" class="w-full border-collapse text-[13px]">
          <thead>
            <tr>
              <th class="lbl text-left px-3 py-2 border-b border-line">Escaneo</th>
              <th v-for="n in ORDEN_SEVERIDAD" :key="n"
                  class="lbl text-right px-3 py-2 border-b border-line">{{ SEV_ES[n] }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in datos?.tendencia" :key="t.scan_id">
              <td class="font-mono px-3 py-2 border-b border-line text-fg-dim">
                #{{ t.scan_id }}
              </td>
              <td v-for="n in ORDEN_SEVERIDAD" :key="n"
                  class="font-mono text-right tabular-nums px-3 py-2 border-b border-line"
                  :class="t[n] ? 'text-fg' : 'text-fg-faint'">{{ t[n] ?? 0 }}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <!-- Dos columnas de listas: por dónde empezar, y dónde se concentra. -->
      <div class="grid gap-8" style="grid-template-columns: repeat(auto-fit, minmax(330px, 1fr))">
        <section v-if="datos?.top_checks.length" class="flex flex-col gap-3">
          <div class="flex items-baseline gap-3 flex-wrap">
            <h2 class="lbl m-0">Lo que más se repite</h2>
            <span class="text-[11.5px] text-fg-faint">suele ser un arreglo que cierra varios</span>
          </div>
          <button
            v-for="c in datos.top_checks"
            :key="c.source + c.check_id"
            class="flex items-center gap-3 text-left w-full px-3 py-[9px]
                   bg-surface border border-line rounded-cx hover:border-line-strong"
            @click="irAHallazgos(c.check_id)"
          >
            <Severidad :nivel="c.severidad" como="punto" />
            <span class="flex-1 min-w-0">
              <span class="block text-[13px] truncate">{{ c.titulo }}</span>
              <span class="block font-mono text-[11px] text-fg-faint truncate">
                {{ c.source }}:{{ c.check_id }}
              </span>
            </span>
            <span class="font-mono text-[17px] tabular-nums shrink-0">×{{ c.total }}</span>
          </button>
        </section>

        <section v-if="datos?.top_objetivos.length" class="flex flex-col gap-3">
          <h2 class="lbl m-0">Dónde se concentra</h2>
          <div
            v-for="o in datos.top_objetivos"
            :key="o.objetivo"
            class="flex items-center gap-3 px-3 py-[9px]
                   bg-surface border border-line rounded-cx"
          >
            <Severidad :nivel="o.peor" como="punto" />
            <span class="flex-1 min-w-0 font-mono text-[12.5px] truncate">{{ o.objetivo }}</span>
            <span class="text-[11px] text-fg-faint shrink-0">{{ o.rutas }} ruta(s)</span>
            <span class="font-mono text-[17px] tabular-nums shrink-0">{{ o.total }}</span>
          </div>
        </section>

        <section v-if="datos && Object.keys(datos.por_herramienta).length"
                 class="flex flex-col gap-3">
          <div class="flex items-baseline gap-3 flex-wrap">
            <h2 class="lbl m-0">Quién lo encontró</h2>
            <span class="text-[11.5px] text-fg-faint">en el último escaneo</span>
          </div>
          <div class="flex flex-col gap-[5px]">
            <div v-for="(n, herramienta) in datos.por_herramienta" :key="herramienta"
                 class="flex items-center gap-3">
              <span class="w-[92px] shrink-0 font-mono text-[12px] text-fg-dim truncate">
                {{ herramienta }}
              </span>
              <span class="flex-1 h-[10px] bg-surface-2 rounded-[2px] overflow-hidden">
                <span class="block h-full bg-accent-dim"
                      :style="{ width: `${(n / Math.max(...Object.values(datos.por_herramienta))) * 100}%` }" />
              </span>
              <span class="w-[32px] text-right font-mono text-[12px] tabular-nums">{{ n }}</span>
            </div>
          </div>
        </section>

        <section v-if="datos?.antiguedad.mas_viejos.length" class="flex flex-col gap-3">
          <div class="flex items-baseline gap-3 flex-wrap">
            <h2 class="lbl m-0">Lo que lleva más tiempo abierto</h2>
          </div>
          <div class="flex gap-4 flex-wrap font-mono text-[11.5px] text-fg-dim">
            <span v-for="(n, tramo) in datos.antiguedad.tramos" :key="tramo">
              {{ tramo }} <b class="text-fg font-normal">{{ n }}</b>
            </span>
          </div>
          <button
            v-for="v in datos.antiguedad.mas_viejos"
            :key="v.fingerprint"
            class="flex items-center gap-3 text-left w-full px-3 py-[8px]
                   bg-surface border border-line rounded-cx hover:border-line-strong"
            @click="irAHallazgos(v.titulo)"
          >
            <Severidad :nivel="v.severidad" como="punto" />
            <span class="flex-1 min-w-0">
              <span class="block text-[12.5px] truncate">{{ v.titulo }}</span>
              <span class="block font-mono text-[11px] text-fg-faint truncate">
                {{ v.objetivo }}
              </span>
            </span>
            <span class="shrink-0 text-right">
              <span class="block font-mono text-[14px] tabular-nums">{{ v.dias }} d</span>
              <span class="block text-[10.5px] text-fg-faint">{{ ESTADO_ES[v.estado] }}</span>
            </span>
          </button>
        </section>
      </div>

      <section v-if="datos" class="flex flex-col gap-3">
        <h2 class="lbl m-0">Estado del triaje</h2>
        <div v-if="Object.keys(datos.triaje).length"
             class="flex h-[26px] rounded-[2px] overflow-hidden border border-line">
          <span
            v-for="(n, estado) in datos.triaje"
            :key="estado"
            class="grid place-items-center font-mono text-[11px] tabular-nums"
            :style="{
              flex: n,
              background: estado === 'false_positive' ? 'var(--cx-surface-3)'
                : estado === 'accepted_risk' ? 'var(--cx-med)'
                : estado === 'confirmed' ? 'var(--cx-crit)'
                : estado === 'fixed' ? 'var(--cx-accent-dim)' : 'var(--cx-surface-2)',
              color: ['accepted_risk', 'confirmed'].includes(estado as string)
                ? 'var(--cx-sev-ink)' : 'var(--cx-fg-dim)',
            }"
          >{{ n }}</span>
        </div>
        <div class="flex gap-4 flex-wrap font-mono text-[11.5px] text-fg-dim">
          <span v-for="(n, estado) in datos.triaje" :key="estado">
            {{ ESTADO_ES[estado as string] ?? estado }} <b class="text-fg font-normal">{{ n }}</b>
          </span>
        </div>
      </section>

      <!-- Qué se ejecutó y qué no. Sin esto, un adaptador que falló se lee
           como «no había nada que encontrar». -->
      <section v-if="datos?.cobertura.tareas.length" class="flex flex-col gap-3">
        <div class="flex items-baseline gap-3 flex-wrap">
          <h2 class="lbl m-0">Qué se comprobó</h2>
          <span class="text-[11.5px] text-fg-faint">
            en el escaneo #{{ ultimo?.id }}
          </span>
        </div>
        <div class="flex gap-2 flex-wrap">
          <span
            v-for="t in datos.cobertura.tareas"
            :key="t.name"
            class="font-mono text-[11.5px] px-2 py-[3px] rounded-[3px] border"
            :class="t.status === 'failed' ? 'border-crit text-crit'
                  : t.status === 'skipped' ? 'border-med text-med'
                  : 'border-line text-fg-dim'"
            :title="t.error ?? ''"
          >{{ t.name }} · {{ TAREA_ES[t.status] ?? t.status }}</span>
        </div>
        <!-- De cuántos hallazgos se partió y en qué se quedaron. Reducir
             por huella o por absorción es correcto; lo que no puede ser es
             que la diferencia no se pueda explicar. -->
        <p v-if="conteo" class="m-0 font-mono text-[11.5px] text-fg-dim">
          {{ conteo.producidos }} producidos ·
          {{ conteo.colapsados_por_huella }} colapsados por huella ·
          {{ conteo.absorbidos_por_otro_mejor }} absorbidos ·
          <b class="text-fg font-normal">{{ conteo.guardados }} guardados</b>
        </p>
        <p v-if="conteo?.descuadre" class="m-0 text-[12px] text-crit">
          Las cuentas no cuadran por {{ conteo.descuadre }}: este escaneo
          perdió hallazgos entre fases y no se sabe cuáles. Repítelo y no des
          el informe por completo.
        </p>
        <p v-if="tareasConPega.length" class="m-0 text-[12px] text-med">
          Lo que no se ejecutó no encontró nada porque no miró, no porque no
          hubiera. Un hallazgo que desaparezca por aquí no está corregido.
        </p>
      </section>
    </div>
  </div>
</template>
