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
 * — Arriba van el radar y los avisos, que responden sin leer: ¿hay algo
 *   grave?, ¿dónde?, ¿queda algo por mirar? El detalle va debajo.
 * — Cabina oscura: un aviso apagado significa que no hay nada que atender.
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
import RadarDeHallazgos from './RadarDeHallazgos.vue'
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
const PERFIL_ES: Record<string, string> = {
  passive: 'pasivo', 'safe-active': 'activo seguro', aggressive: 'agresivo',
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

const RANGO: Record<NivelSeveridad, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
}

/**
 * Lo abierto en el escaneo que se está mirando: lo que nadie ha descartado.
 * Es lo que dibuja el radar. Un falso positivo o un riesgo aceptado ya tienen
 * dueño y no deben seguir pidiendo atención desde la primera pantalla.
 */
const abiertos = computed(() =>
  sesion.hallazgos.filter((h) => h.status === 'new' || h.status === 'confirmed'))

const descartados = computed(() => sesion.hallazgos.length - abiertos.value.length)

/** Por dónde empezar: los cuatro más graves de lo abierto. */
const decisivos = computed(() =>
  [...abiertos.value].sort((a, b) => RANGO[b.severity] - RANGO[a.severity]).slice(0, 4))

const sinTriar = computed(() => sesion.hallazgos.filter((h) => h.status === 'new').length)

/**
 * Los avisos, con la regla de la cabina oscura: apagado significa que ahí no
 * hay nada que atender. Por eso un cero es gris y no verde —el verde también
 * llama la vista—, y por eso solo se encienden en rojo o en ámbar.
 *
 * Un `null` es otra cosa: no es «cero», es «no se puede saber», y se pinta
 * con una raya. Pasa con todo lo que compara con el escaneo anterior cuando
 * no hay escaneo anterior.
 */
const avisos = computed(() => {
  const r = resumen.value
  const u = ultimo.value
  if (!r || !u) return []
  const c = datos.value?.cambio
  const sinComparar = 'no hay un escaneo anterior con el que comparar'
  return [
    { k: 'Críticos y altos', v: r.graves ?? 0, tono: 'rojo' as const,
      ir: () => filtrar({ severidad: ['critical', 'high'] }) },
    { k: 'Sin triar', v: r.pendientes ?? 0, tono: 'ambar' as const,
      ir: () => filtrar({ estado: ['new'] }) },
    { k: 'Nuevos', v: c?.nuevos ?? null, tono: 'ambar' as const, pie: c ? '' : sinComparar },
    { k: 'Empeoran', v: c?.empeoran ?? null, tono: 'rojo' as const, pie: c ? '' : sinComparar },
    { k: 'Sin comprobar', v: c?.sin_comprobar ?? null, tono: 'ambar' as const,
      pie: c ? '' : sinComparar },
    { k: 'Sin ejecutar', v: u.tareas_fallidas + u.tareas_omitidas,
      tono: 'ambar' as const, pie: 'tareas del escaneo que fallaron o se omitieron' },
    { k: 'Perdidos', v: conteo.value?.descuadre ?? 0, tono: 'rojo' as const,
      pie: 'hallazgos que desaparecieron entre fases sin explicación' },
  ]
})
// Los nombres van escritos enteros: Tailwind solo genera las clases que ve.
const ENCENDIDO = { rojo: 'aviso-rojo', ambar: 'aviso-ambar' }

const hayCambio = computed(() => datos.value?.cambio != null)

const conteo = computed(() => datos.value?.cobertura.conteo ?? null)
const sesionDelEscaneo = computed(() => datos.value?.cobertura.sesion ?? null)

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

/** Lleva al triaje con unas facetas ya puestas. */
function filtrar(f: { severidad?: string[]; estado?: string[] }) {
  sesion.limpiarFiltros()
  if (f.severidad) sesion.filtroSeveridad = new Set(f.severidad)
  if (f.estado) sesion.filtroEstado = new Set(f.estado)
  router.push('/hallazgos')
}

function abrirHallazgo(id: number) {
  sesion.limpiarFiltros()
  sesion.seleccionado = id
  router.push('/hallazgos')
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
      axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(232,241,255,.05)' } },
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
    <div class="max-w-[1360px] mx-auto px-[clamp(16px,3vw,44px)] py-7 flex flex-col gap-11">

      <!-- ── Lo que se ve sin leer ──────────────────────────────────────── -->
      <div class="flex flex-wrap items-start gap-x-[52px] gap-y-8">
        <RadarDeHallazgos
          class="flex-[3_1_500px] max-w-[760px]"
          :hallazgos="abiertos"
          @abrir="abrirHallazgo"
        />

        <div class="flex-[2_1_380px] min-w-0 flex flex-col gap-[26px]">
          <div class="flex flex-col gap-[6px]">
            <h1 class="m-0 text-[clamp(30px,3.2vw,44px)] font-bold leading-[1.08]">
              {{ abiertos.length }}
              {{ abiertos.length === 1 ? 'hallazgo abierto' : 'hallazgos abiertos' }}
            </h1>
            <p v-if="sesion.escaneo" class="m-0 text-fg-dim">
              {{ sesion.proyectoActual?.name }}. Escaneo #{{ sesion.escaneo.id }},
              perfil {{ PERFIL_ES[sesion.escaneo.profile] ?? sesion.escaneo.profile }}, {{ fecha(sesion.escaneo.started_at) }},
              {{ duracion(sesion.escaneo.duracion) }}.
              <template v-if="descartados">
                Hay {{ descartados }} más ya {{ descartados === 1 ? 'descartado' : 'descartados' }}
                en el triaje.
              </template>
            </p>
            <p v-else class="m-0 text-fg-dim">
              Todavía no hay ningún escaneo. Lanza el primero para ver aquí lo
              que encuentre.
            </p>
          </div>

          <section v-if="avisos.length" aria-label="Avisos" class="flex flex-col gap-2">
            <div class="grid gap-2"
                 style="grid-template-columns: repeat(auto-fit, minmax(min(118px, 100%), 1fr))">
              <component
                :is="a.ir && a.v ? 'button' : 'div'"
                v-for="a in avisos"
                :key="a.k"
                class="aviso min-h-[58px] px-3 py-2 flex items-center justify-between
                       gap-[10px] text-left"
                :class="[a.v ? ENCENDIDO[a.tono] + ' font-bold' : '',
                         a.ir && a.v ? 'hover:brightness-125' : '']"
                :title="a.pie || undefined"
                @click="a.ir && a.v ? a.ir() : undefined"
              >
                <span>{{ a.k }}</span>
                <span class="font-mono text-[22px] leading-none tabular-nums"
                      :class="a.v ? 'text-fg' : ''">{{ a.v ?? '—' }}</span>
              </component>
            </div>
            <p class="m-0 text-[13px] text-fg-dim">
              Un aviso apagado significa que ahí no hay nada que atender.
              <template v-if="ultimo && sesion.escaneo && ultimo.id !== sesion.escaneo.id">
                Los avisos son del último escaneo del proyecto, el #{{ ultimo.id }}.
              </template>
            </p>
          </section>

          <section class="flex flex-col gap-[10px]">
            <h2 class="m-0 text-[17px] font-bold">Lo que decide</h2>
            <p v-if="!decisivos.length" class="m-0 text-fg-dim">
              Nada abierto. No hay por dónde empezar porque no queda nada.
            </p>
            <div v-else class="flex flex-col border-t border-line">
              <button
                v-for="(h, i) in decisivos"
                :key="h.id"
                class="min-h-[52px] py-2 flex items-center gap-[14px] text-left
                       border-b border-line hover:bg-surface"
                :class="i === 0 ? 'font-bold' : ''"
                @click="abrirHallazgo(h.id)"
              >
                <Severidad :nivel="h.severity" como="figura" />
                <span class="flex-1 min-w-0">{{ h.title }}</span>
                <span class="font-mono font-normal text-[12px] text-fg-dim truncate max-w-[38%]">
                  {{ h.target.replace(/^https?:\/\/[^/]+/, '') || '/' }}
                </span>
              </button>
            </div>
          </section>

          <div class="flex flex-wrap gap-3">
            <button
              v-if="sinTriar"
              class="min-h-[48px] px-[22px] bg-accent text-accent-ink font-bold rounded-cx
                     hover:brightness-110"
              @click="filtrar({ estado: ['new'] })"
            >{{ sinTriar === 1 ? 'Triar el pendiente' : `Triar los ${sinTriar} pendientes` }}</button>
            <button
              class="min-h-[48px] px-[22px] font-bold rounded-cx border-[1.5px]"
              :class="sinTriar ? 'border-fg-dim text-fg hover:border-fg'
                               : 'bg-accent border-accent text-accent-ink hover:brightness-110'"
              @click="router.push('/escaneos')"
            >Nuevo escaneo</button>
          </div>
        </div>
      </div>

      <!-- ── El detalle ─────────────────────────────────────────────────── -->

      <!-- Lo que cambió: la sección que de verdad dice si vas ganando. -->
      <section v-if="hayCambio && datos?.cambio" class="flex flex-col gap-3">
        <div class="flex items-baseline gap-3 flex-wrap">
          <h2 class="m-0 text-[17px] font-bold">
            Desde el escaneo #{{ datos.cambio.antes }}
          </h2>
          <span v-if="datos.cambio.hay_regresion" class="text-high-fg">
            Hay regresión: algo nuevo o algo que empeora.
          </span>
        </div>
        <dl class="m-0 grid gap-px bg-line border border-line rounded-cx overflow-hidden"
            style="grid-template-columns: repeat(auto-fit, minmax(128px, 1fr))">
          <div v-for="c in [
                 { k: 'Nuevos', v: datos.cambio.nuevos, tono: 'text-high-fg' },
                 { k: 'Corregidos', v: datos.cambio.corregidos, tono: 'text-ok' },
                 { k: 'Persisten', v: datos.cambio.persistentes, tono: 'text-fg' },
                 { k: 'Empeoran', v: datos.cambio.empeoran, tono: 'text-crit-fg' },
                 { k: 'Sin comprobar', v: datos.cambio.sin_comprobar, tono: 'text-high-fg' },
               ]" :key="c.k" class="bg-bg px-4 py-3">
            <dt class="lbl mb-[6px]">{{ c.k }}</dt>
            <dd class="m-0 font-mono text-[22px] leading-none tabular-nums"
                :class="c.v ? c.tono : 'text-fg-faint'">{{ c.v }}</dd>
          </div>
        </dl>
        <p v-if="datos.cambio.sin_comprobar" class="m-0 text-high-fg max-w-[80ch]">
          «Sin comprobar» no es «corregido»: esos hallazgos desaparecieron sin
          que esta vez se buscaran —otro perfil, una herramienta ausente, un
          adaptador que falló—, así que nadie puede decir si siguen ahí.
        </p>
      </section>

      <section class="flex flex-col gap-3">
        <div class="flex items-center gap-3">
          <h2 class="m-0 text-[17px] font-bold">Severidad por escaneo</h2>
          <button
            class="ml-auto min-h-[36px] px-3 text-accent hover:text-fg"
            @click="comoTabla = !comoTabla"
          >{{ comoTabla ? 'Ver la gráfica' : 'Ver la tabla' }}</button>
        </div>

        <div v-show="!comoTabla" ref="lienzo"
             class="h-[300px] w-full border border-line bg-surface rounded-cx" />

        <table v-if="comoTabla" class="w-full border-collapse">
          <thead>
            <tr>
              <th class="lbl text-left px-3 py-2 border-b border-line-strong">Escaneo</th>
              <th v-for="n in ORDEN_SEVERIDAD" :key="n"
                  class="lbl text-right px-3 py-2 border-b border-line-strong">{{ SEV_ES[n] }}</th>
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
      <div class="grid gap-x-12 gap-y-10"
           style="grid-template-columns: repeat(auto-fit, minmax(min(360px, 100%), 1fr))">
        <section v-if="datos?.top_checks.length" class="flex flex-col gap-3">
          <div class="flex flex-col gap-[2px]">
            <h2 class="m-0 text-[17px] font-bold">Lo que más se repite</h2>
            <span class="text-fg-dim">Suele ser un arreglo que cierra varios de golpe.</span>
          </div>
          <div class="flex flex-col border-t border-line">
            <button
              v-for="c in datos.top_checks"
              :key="c.source + c.check_id"
              class="min-h-[52px] py-2 flex items-center gap-[14px] text-left w-full
                     border-b border-line hover:bg-surface"
              @click="irAHallazgos(c.check_id)"
            >
              <Severidad :nivel="c.severidad" como="figura" />
              <span class="flex-1 min-w-0">
                <span class="block truncate">{{ c.titulo }}</span>
                <span class="block font-mono text-[12px] text-fg-dim truncate">
                  {{ c.source }}:{{ c.check_id }}
                </span>
              </span>
              <span class="font-mono text-[18px] tabular-nums shrink-0">{{ c.total }} veces</span>
            </button>
          </div>
        </section>

        <section v-if="datos?.top_objetivos.length" class="flex flex-col gap-3">
          <h2 class="m-0 text-[17px] font-bold">Dónde se concentra</h2>
          <div class="flex flex-col border-t border-line">
            <div
              v-for="o in datos.top_objetivos"
              :key="o.objetivo"
              class="min-h-[52px] py-2 flex items-center gap-[14px] border-b border-line"
            >
              <Severidad :nivel="o.peor" como="figura" />
              <span class="flex-1 min-w-0 font-mono text-[13px] truncate">{{ o.objetivo }}</span>
              <span class="text-[13px] text-fg-dim shrink-0">
                {{ o.rutas }} {{ o.rutas === 1 ? 'ruta' : 'rutas' }}
              </span>
              <span class="font-mono text-[18px] tabular-nums shrink-0 w-[3ch] text-right">
                {{ o.total }}
              </span>
            </div>
          </div>
        </section>

        <section v-if="datos && Object.keys(datos.por_herramienta).length"
                 class="flex flex-col gap-3">
          <div class="flex flex-col gap-[2px]">
            <h2 class="m-0 text-[17px] font-bold">Quién lo encontró</h2>
            <span class="text-fg-dim">En el último escaneo.</span>
          </div>
          <div class="flex flex-col gap-[8px]">
            <div v-for="(n, herramienta) in datos.por_herramienta" :key="herramienta"
                 class="flex items-center gap-3">
              <span class="w-[92px] shrink-0 font-mono text-[13px] text-fg-dim truncate">
                {{ herramienta }}
              </span>
              <span class="flex-1 h-[10px] bg-surface-2 overflow-hidden">
                <!-- Barra neutra a propósito: aquí el color no significa nada,
                     y en este sistema un color que no significa nada no va. -->
                <span class="block h-full bg-fg-dim"
                      :style="{ width: `${(n / Math.max(...Object.values(datos.por_herramienta))) * 100}%` }" />
              </span>
              <span class="w-[32px] text-right font-mono text-[13px] tabular-nums">{{ n }}</span>
            </div>
          </div>
        </section>

        <section v-if="datos?.antiguedad.mas_viejos.length" class="flex flex-col gap-3">
          <h2 class="m-0 text-[17px] font-bold">Lo que lleva más tiempo abierto</h2>
          <div class="flex gap-x-5 gap-y-1 flex-wrap font-mono text-[13px] text-fg-dim">
            <span v-for="(n, tramo) in datos.antiguedad.tramos" :key="tramo">
              {{ tramo }} <b class="text-fg font-normal">{{ n }}</b>
            </span>
          </div>
          <div class="flex flex-col border-t border-line">
            <button
              v-for="v in datos.antiguedad.mas_viejos"
              :key="v.fingerprint"
              class="min-h-[52px] py-2 flex items-center gap-[14px] text-left w-full
                     border-b border-line hover:bg-surface"
              @click="irAHallazgos(v.titulo)"
            >
              <Severidad :nivel="v.severidad" como="figura" />
              <span class="flex-1 min-w-0">
                <span class="block truncate">{{ v.titulo }}</span>
                <span class="block font-mono text-[12px] text-fg-dim truncate">
                  {{ v.objetivo }}
                </span>
              </span>
              <span class="shrink-0 text-right">
                <span class="block font-mono text-[15px] tabular-nums">{{ v.dias }} d</span>
                <span class="block text-[12px] text-fg-dim">{{ ESTADO_ES[v.estado] }}</span>
              </span>
            </button>
          </div>
        </section>
      </div>

      <section v-if="datos" class="flex flex-col gap-3">
        <h2 class="m-0 text-[17px] font-bold">Estado del triaje</h2>
        <!-- Grises, no colores: el triaje no es severidad, y pintar
             «confirmado» de rojo lo confundiría con un crítico. Solo
             «corregido» lleva verde, que aquí siempre significa eso. -->
        <div v-if="Object.keys(datos.triaje).length"
             class="flex h-[28px] rounded-cx overflow-hidden border border-line-strong gap-px bg-bg">
          <span
            v-for="(n, estado) in datos.triaje"
            :key="estado"
            class="grid place-items-center font-mono text-[12px] tabular-nums"
            :style="{
              flex: n,
              background: estado === 'fixed' ? 'var(--cx-ok-dim)'
                : estado === 'confirmed' ? 'var(--cx-fg-dim)'
                : estado === 'new' ? 'var(--cx-border-strong)'
                : 'var(--cx-surface-2)',
              color: estado === 'confirmed' ? 'var(--cx-sev-ink)' : 'var(--cx-fg)',
            }"
          >{{ n }}</span>
        </div>
        <div class="flex gap-x-5 gap-y-1 flex-wrap font-mono text-[13px] text-fg-dim">
          <span v-for="(n, estado) in datos.triaje" :key="estado">
            {{ ESTADO_ES[estado as string] ?? estado }} <b class="text-fg font-normal">{{ n }}</b>
          </span>
        </div>
      </section>

      <!-- Qué se ejecutó y qué no. Sin esto, un adaptador que falló se lee
           como «no había nada que encontrar». -->
      <section v-if="datos?.cobertura.tareas.length" class="flex flex-col gap-3">
        <div class="flex flex-col gap-[2px]">
          <h2 class="m-0 text-[17px] font-bold">Qué se comprobó</h2>
          <span class="text-fg-dim">En el escaneo #{{ ultimo?.id }}.</span>
        </div>
        <div class="flex gap-2 flex-wrap">
          <span
            v-for="t in datos.cobertura.tareas"
            :key="t.name"
            class="aviso font-mono text-[12px] px-[10px] py-[5px]"
            :class="t.status === 'failed' ? 'aviso-rojo'
                  : t.status === 'skipped' ? 'aviso-ambar' : ''"
            :title="t.error ?? ''"
          >{{ t.name }}, {{ TAREA_ES[t.status] ?? t.status }}</span>
        </div>
        <!-- Con qué sesión. Un escaneo con credenciales que no se distinga de
             uno sin ellas es justo el fallo que esto tiene que delatar. -->
        <p v-if="sesionDelEscaneo" class="m-0 text-[13px]"
           :class="sesionDelEscaneo.perdidas?.length ? 'text-crit-fg'
                 : sesionDelEscaneo.verificada ? 'text-fg-dim' : 'text-high-fg'">
          Con la sesión de «{{ sesionDelEscaneo.nombre }}»<template
            v-if="sesionDelEscaneo.proveedor">, por {{ sesionDelEscaneo.proveedor }}</template>.
          <template v-if="sesionDelEscaneo.verificada">
            Comprobada: {{ sesionDelEscaneo.comprobacion.sin_sesion }} sin ella,
            {{ sesionDelEscaneo.comprobacion.con_sesion }} con ella.
          </template>
          <template v-else>No se pudo confirmar fuera del navegador.</template>
          <template v-if="sesionDelEscaneo.renovaciones">
            Se renovó {{ sesionDelEscaneo.renovaciones }}
            {{ sesionDelEscaneo.renovaciones === 1 ? 'vez' : 'veces' }}.
          </template>
          <template v-if="sesionDelEscaneo.perdidas?.length">
            Se perdió en {{ sesionDelEscaneo.perdidas.map((p) => p.fase).join(', ') }}:
            lo que esas fases no encontraron detrás del login no está comprobado.
          </template>
        </p>
        <p v-else-if="ultimo && datos?.cobertura.tareas.length" class="m-0 text-[13px] text-fg-dim">
          Sin credenciales: solo se vio lo que la aplicación enseña a un anónimo.
        </p>
        <!-- De cuántos hallazgos se partió y en qué se quedaron. Reducir
             por huella o por absorción es correcto; lo que no puede ser es
             que la diferencia no se pueda explicar. -->
        <p v-if="conteo" class="m-0 font-mono text-[13px] text-fg-dim">
          {{ conteo.producidos }} producidos,
          {{ conteo.colapsados_por_huella }} colapsados por huella,
          {{ conteo.absorbidos_por_otro_mejor }} absorbidos,
          <b class="text-fg font-normal">{{ conteo.guardados }} guardados</b>
        </p>
        <p v-if="conteo?.descuadre" class="m-0 text-crit-fg max-w-[80ch]">
          Las cuentas no cuadran por {{ conteo.descuadre }}: este escaneo
          perdió hallazgos entre fases y no se sabe cuáles. Repítelo y no des
          el informe por completo.
        </p>
        <p v-if="tareasConPega.length" class="m-0 text-high-fg max-w-[80ch]">
          Lo que no se ejecutó no encontró nada porque no miró, no porque no
          hubiera. Un hallazgo que desaparezca por aquí no está corregido.
        </p>
      </section>
    </div>
  </div>
</template>
