<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useSesion } from '@/stores/sesion'
import Severidad from '@/components/Severidad.vue'

const abierta = defineModel<boolean>('abierta', { required: true })
const sesion = useSesion()
const router = useRouter()
const consulta = ref('')
const campo = ref<HTMLInputElement>()
const resaltado = ref(0)

interface Orden { etiqueta: string; atajo?: string; hacer: () => void }

const ordenes = computed<Orden[]>(() => {
  const h = sesion.actual
  const base: Orden[] = [
    { etiqueta: 'Ir a hallazgos', hacer: () => router.push('/hallazgos') },
    { etiqueta: 'Ir a escaneos', hacer: () => router.push('/escaneos') },
    { etiqueta: 'Limpiar todos los filtros', hacer: () => sesion.limpiarFiltros() },
  ]
  if (h) {
    base.unshift(
      { etiqueta: `Confirmar «${h.title}»`, atajo: '⇧C',
        hacer: () => sesion.triar(h, 'confirmed') },
      { etiqueta: 'Marcar como falso positivo', atajo: '⇧F',
        hacer: () => sesion.triar(h, 'false_positive') },
      { etiqueta: 'Aceptar el riesgo', hacer: () => sesion.triar(h, 'accepted_risk') },
    )
  }
  if (sesion.escaneo) {
    base.push({
      etiqueta: 'Descargar el informe en PDF',
      hacer: () => window.open(`/api/scans/${sesion.escaneo!.id}/report.pdf`, '_blank'),
    })
  }
  return base
})

const filtradas = computed(() => {
  const t = consulta.value.trim().toLowerCase()
  const ordenesCoincidentes = t
    ? ordenes.value.filter((o) => o.etiqueta.toLowerCase().includes(t))
    : ordenes.value
  // Buscar un hallazgo concreto es tan frecuente como lanzar una orden, así
  // que la paleta mezcla ambas cosas en lugar de obligar a cambiar de sitio.
  const hallazgos = t
    ? sesion.hallazgos
        .filter((h) => `${h.title} ${h.target} ${h.check_id}`.toLowerCase().includes(t))
        .slice(0, 6)
    : []
  return { ordenes: ordenesCoincidentes, hallazgos }
})

watch(abierta, async (v) => {
  if (!v) return
  consulta.value = ''
  resaltado.value = 0
  await nextTick()
  campo.value?.focus()
})

function ejecutar(i: number) {
  filtradas.value.ordenes[i]?.hacer()
  abierta.value = false
}

function irAHallazgo(id: number) {
  sesion.seleccionado = id
  router.push('/hallazgos')
  abierta.value = false
}

function teclas(e: KeyboardEvent) {
  const total = filtradas.value.ordenes.length
  if (e.key === 'ArrowDown') { e.preventDefault(); resaltado.value = (resaltado.value + 1) % total }
  if (e.key === 'ArrowUp') { e.preventDefault(); resaltado.value = (resaltado.value - 1 + total) % total }
  if (e.key === 'Enter') { e.preventDefault(); ejecutar(resaltado.value) }
}
</script>

<template>
  <div
    v-if="abierta"
    class="fixed inset-0 z-20 flex items-start justify-center pt-[12vh] px-4
           bg-[rgba(5,8,13,.72)]"
    @click.self="abierta = false"
  >
    <div class="w-full max-w-[540px] bg-surface-2 border border-line-strong
                rounded-lg overflow-hidden shadow-[0_24px_60px_rgba(0,0,0,.6)]">
      <input
        ref="campo"
        v-model="consulta"
        type="text"
        placeholder="Escribe un comando o busca un hallazgo…"
        aria-label="Paleta de comandos"
        class="w-full bg-transparent border-0 border-b border-line px-4 py-[14px]
               text-fg font-mono text-[15px] outline-none placeholder:text-fg-faint"
        @keydown="teclas"
      >
      <ul class="list-none m-0 p-[6px] max-h-[52vh] overflow-y-auto">
        <li
          v-for="(o, i) in filtradas.ordenes"
          :key="o.etiqueta"
          class="flex gap-3 items-center px-[11px] py-2 rounded-cx text-[13px] cursor-pointer"
          :class="i === resaltado ? 'bg-surface-3 text-fg' : 'text-fg-dim'"
          @mouseenter="resaltado = i"
          @click="ejecutar(i)"
        >
          {{ o.etiqueta }}
          <code v-if="o.atajo" class="ml-auto font-mono text-[11px] text-fg-faint">{{ o.atajo }}</code>
        </li>

        <template v-if="filtradas.hallazgos.length">
          <li class="lbl px-[11px] pt-3 pb-1">Hallazgos</li>
          <li
            v-for="h in filtradas.hallazgos"
            :key="h.id"
            class="flex gap-[10px] items-center px-[11px] py-2 rounded-cx text-[13px]
                   text-fg-dim hover:bg-surface-3 hover:text-fg cursor-pointer"
            @click="irAHallazgo(h.id)"
          >
            <Severidad :nivel="h.severity" como="punto" />
            <span class="truncate">{{ h.title }}</span>
            <code class="ml-auto font-mono text-[11px] text-fg-faint truncate max-w-[40%]">
              {{ h.target }}
            </code>
          </li>
        </template>
      </ul>
    </div>
  </div>
</template>
