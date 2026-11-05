<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useVirtualizer } from '@tanstack/vue-virtual'
import { useSesion, ORDEN_SEVERIDAD } from '@/stores/sesion'
import Severidad from '@/components/Severidad.vue'
import PanelDeHallazgo from './PanelDeHallazgo.vue'

const sesion = useSesion()

const ESTADO_ES: Record<string, string> = {
  new: 'sin triar', confirmed: 'confirmado', false_positive: 'falso pos.',
  fixed: 'corregido', accepted_risk: 'riesgo acept.',
}

const contenedor = ref<HTMLElement | null>(null)
const ALTURA_FILA = 60

// Virtualización: un escaneo de una intranet grande pasa de mil hallazgos, y
// pintarlos todos deja la lista pegajosa justo cuando más se desplaza.
const virtualizador = useVirtualizer(
  computed(() => ({
    count: sesion.visibles.length,
    getScrollElement: () => contenedor.value,
    estimateSize: () => ALTURA_FILA,
    overscan: 12,
  })),
)

const filas = computed(() => virtualizador.value.getVirtualItems())
const alturaTotal = computed(() => virtualizador.value.getTotalSize())

// Al moverse con el teclado, la fila seleccionada debe seguir a la vista.
watch(() => sesion.actual?.id, (id) => {
  if (id == null) return
  const i = sesion.visibles.findIndex((h) => h.id === id)
  if (i >= 0) virtualizador.value.scrollToIndex(i, { align: 'auto' })
})

const facetas = computed(() => ({
  severidad: ORDEN_SEVERIDAD.map((v) => ({ valor: v, n: sesion.cuenta('severity')[v] ?? 0 }))
    .filter((f) => f.n > 0),
  origen: Object.entries(sesion.cuenta('source'))
    .map(([valor, n]) => ({ valor, n }))
    .sort((a, b) => b.n - a.n),
  estado: Object.entries(sesion.cuenta('status')).map(([valor, n]) => ({ valor, n })),
}))

const hayFiltros = computed(() =>
  sesion.filtroSeveridad.size + sesion.filtroOrigen.size + sesion.filtroEstado.size > 0
  || sesion.busqueda.length > 0)
</script>

<template>
  <div class="grid grid-cols-[216px_minmax(0,1fr)_440px] min-h-0 h-full
              max-[1180px]:grid-cols-[200px_minmax(0,1fr)] max-[720px]:grid-cols-1">
    <!-- Facetas -->
    <nav class="bg-surface border-r border-line overflow-y-auto py-4 max-[720px]:max-h-[200px]">
      <template
        v-for="grupo in [
          { clave: 'severidad', titulo: 'Severidad', items: facetas.severidad, set: sesion.filtroSeveridad },
          { clave: 'origen', titulo: 'Origen', items: facetas.origen, set: sesion.filtroOrigen },
          { clave: 'estado', titulo: 'Estado', items: facetas.estado, set: sesion.filtroEstado },
        ]"
        :key="grupo.clave"
      >
        <h3 class="lbl m-0 mb-2 px-4">{{ grupo.titulo }}</h3>
        <section class="mb-[22px]">
          <button
            v-for="f in grupo.items"
            :key="f.valor"
            class="flex items-center gap-[9px] w-full text-left px-4 py-[5px] text-[13px]
                   border-l-2 border-transparent text-fg-dim
                   hover:bg-surface-2 hover:text-fg"
            :class="grupo.set.has(f.valor) ? '!bg-surface-2 !text-fg !border-l-accent' : ''"
            :aria-pressed="grupo.set.has(f.valor)"
            @click="sesion.alternar(grupo.clave as any, f.valor)"
          >
            <Severidad v-if="grupo.clave === 'severidad'" :nivel="f.valor as any" como="punto" />
            <span class="truncate">
              {{ grupo.clave === 'estado' ? (ESTADO_ES[f.valor] ?? f.valor)
                 : grupo.clave === 'severidad' ? ({critical:'crítica',high:'alta',medium:'media',low:'baja',info:'info'} as any)[f.valor]
                 : f.valor }}
            </span>
            <span
              class="ml-auto font-mono text-[12px] tabular-nums"
              :class="grupo.set.has(f.valor) ? 'text-accent' : 'text-fg-faint'"
            >{{ f.n }}</span>
          </button>
        </section>
      </template>

      <button
        v-if="hayFiltros"
        class="mx-4 text-[12px] text-accent hover:underline"
        @click="sesion.limpiarFiltros()"
      >Quitar los filtros</button>
    </nav>

    <!-- Lista -->
    <main class="flex flex-col min-w-0 min-h-0 bg-bg">
      <div class="flex items-center gap-3 flex-wrap px-4 py-[9px]
                  border-b border-line bg-surface shrink-0">
        <label class="flex-1 min-w-[150px] flex items-center gap-2 bg-bg border border-line
                      rounded-cx px-[10px] py-[5px]">
          <svg viewBox="0 0 16 16" class="size-[13px] shrink-0" fill="none"
               stroke="var(--cx-fg-faint)" stroke-width="1.7">
            <circle cx="6.8" cy="6.8" r="4.5" /><path d="m10.4 10.4 3 3" />
          </svg>
          <input
            v-model="sesion.busqueda"
            type="search"
            placeholder="Filtrar por título, host, CWE o check-id"
            aria-label="Filtrar hallazgos"
            class="flex-1 min-w-0 bg-transparent border-0 outline-none text-fg
                   font-mono text-[13px] placeholder:text-fg-faint"
          >
        </label>
        <span class="font-mono text-[12px] text-fg-dim tabular-nums">
          {{ sesion.visibles.length }} de {{ sesion.hallazgos.length }} hallazgos
        </span>
      </div>

      <div ref="contenedor" class="overflow-y-auto flex-1 min-h-0" role="listbox"
           aria-label="Hallazgos" tabindex="0">
        <p v-if="!sesion.visibles.length" class="px-4 py-7 text-fg-faint text-[13px]">
          {{ sesion.cargando ? 'cargando…' : 'Ningún hallazgo con estos filtros.' }}
        </p>
        <div v-else class="relative w-full" :style="{ height: `${alturaTotal}px` }">
          <button
            v-for="fila in filas"
            :key="fila.key as number"
            class="absolute top-0 left-0 w-full grid items-center gap-[11px] text-left
                   border-b border-line pr-4
                   grid-cols-[44px_58px_minmax(0,1fr)_178px_104px]
                   max-[1180px]:grid-cols-[44px_58px_minmax(0,1fr)_104px]"
            :style="{ height: `${fila.size}px`, transform: `translateY(${fila.start}px)` }"
            :class="sesion.visibles[fila.index].id === sesion.actual?.id
              ? 'bg-surface-2' : 'hover:bg-surface'"
            :aria-selected="sesion.visibles[fila.index].id === sesion.actual?.id"
            role="option"
            @click="sesion.seleccionado = sesion.visibles[fila.index].id"
          >
            <Severidad :nivel="sesion.visibles[fila.index].severity" como="franja" />
            <Severidad :nivel="sesion.visibles[fila.index].severity" />
            <span class="min-w-0">
              <span
                class="block text-[13.5px] leading-[1.35] truncate"
                :class="sesion.visibles[fila.index].status === 'false_positive'
                  ? 'text-fg-faint line-through' : ''"
              >{{ sesion.visibles[fila.index].title }}</span>
              <span class="block font-mono text-[12px] text-fg-faint mt-[3px] truncate">
                {{ sesion.visibles[fila.index].source }}:{{ sesion.visibles[fila.index].check_id }}
                <template v-if="sesion.visibles[fila.index].cwe.length">
                  · {{ sesion.visibles[fila.index].cwe[0] }}
                </template>
                <template v-if="sesion.visibles[fila.index].param">
                  · param {{ sesion.visibles[fila.index].param }}
                </template>
              </span>
            </span>
            <span class="font-mono text-[12px] text-fg-dim truncate max-[1180px]:hidden">
              {{ sesion.visibles[fila.index].target }}
            </span>
            <span
              class="text-[13px] text-right"
              :class="{
                'text-high-fg font-bold': sesion.visibles[fila.index].status === 'new',
                'text-fg': sesion.visibles[fila.index].status === 'confirmed',
                'text-fg-dim': sesion.visibles[fila.index].status === 'accepted_risk',
                'text-ok': sesion.visibles[fila.index].status === 'fixed',
                'text-fg-faint line-through': sesion.visibles[fila.index].status === 'false_positive',
              }"
            >{{ ESTADO_ES[sesion.visibles[fila.index].status] }}</span>
          </button>
        </div>
      </div>
    </main>

    <PanelDeHallazgo
      class="max-[1180px]:col-span-full max-[1180px]:border-l-0
             max-[1180px]:border-t max-[1180px]:max-h-[62vh]"
    />
  </div>
</template>
