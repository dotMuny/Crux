<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api } from '@/api/client'
import { useSesion } from '@/stores/sesion'
import Chip from '@/components/Chip.vue'
import VisorHttp from './VisorHttp.vue'
import VisorDiff from './VisorDiff.vue'
import type { Evidencia } from '@/api/types'

const sesion = useSesion()
const evidencias = ref<Evidencia[]>([])
const pestana = ref<'peticion' | 'respuesta' | 'diff'>('respuesta')
const cargandoEvidencia = ref(false)

const TOKEN: Record<string, string> = {
  critical: 'var(--cx-crit)', high: 'var(--cx-high)', medium: 'var(--cx-med)',
  low: 'var(--cx-low)', info: 'var(--cx-info)',
}
const SEV_ES: Record<string, string> = {
  critical: 'crítica', high: 'alta', medium: 'media', low: 'baja', info: 'info',
}
const ESTADO_ES: Record<string, string> = {
  new: 'sin triar', confirmed: 'confirmado', false_positive: 'falso positivo',
  fixed: 'corregido', accepted_risk: 'riesgo aceptado',
}

const h = computed(() => sesion.actual)
const primera = computed(() => evidencias.value[0] ?? null)

watch(() => h.value?.id, async (id) => {
  evidencias.value = []
  if (id == null) return
  cargandoEvidencia.value = true
  try {
    evidencias.value = await api.evidencia(id)
  } finally {
    cargandoEvidencia.value = false
  }
}, { immediate: true })

const ACCIONES = [
  { estado: 'confirmed', texto: 'Confirmar', principal: true },
  { estado: 'false_positive', texto: 'Falso positivo', principal: false },
  { estado: 'accepted_risk', texto: 'Riesgo aceptado', principal: false },
] as const

/**
 * Pulsar el estado que ya tiene lo quita: vuelve a «sin triar».
 *
 * Antes el botón activo salía desactivado, así que marcar algo por error no
 * tenía vuelta atrás desde la interfaz. Un juicio equivocado es más fácil de
 * cometer que de detectar, y tiene que poder deshacerse donde se cometió.
 */
function triar(estado: string) {
  if (!h.value) return
  sesion.triar(h.value, h.value.status === estado ? 'new' : estado)
}
</script>

<template>
  <aside
    class="bg-surface border-l border-line overflow-y-auto min-w-0 flex flex-col"
    aria-live="polite"
  >
    <p v-if="!h" class="p-5 text-fg-faint text-[13px]">
      Selecciona un hallazgo para ver su detalle.
    </p>

    <template v-else>
      <div class="px-[18px] pt-4 pb-[14px] border-b border-line">
        <div class="flex items-center gap-[9px] flex-wrap mb-[9px]">
          <span
            class="lbl !text-[10px] px-2 py-[3px] rounded-[3px]"
            :style="{ background: TOKEN[h.severity], color: 'var(--cx-sev-ink)' }"
          >{{ SEV_ES[h.severity] }}</span>
          <Chip>{{ h.source }}:{{ h.check_id }}</Chip>
          <Chip v-for="c in h.cwe" :key="c">{{ c }}</Chip>
          <Chip v-if="h.cvss_score">CVSS {{ h.cvss_score.toFixed(1) }}</Chip>
          <Chip v-if="h.status !== 'new'" tono="acento">{{ ESTADO_ES[h.status] ?? h.status }}</Chip>
        </div>
        <h1 class="m-0 text-[17.5px] leading-[1.32] font-normal text-balance">{{ h.title }}</h1>
        <code class="block mt-[10px] font-mono text-[12px] leading-[1.5] text-accent break-words">
          {{ h.target }}<template v-if="h.param"> · parámetro {{ h.param }}</template>
        </code>
      </div>

      <dl class="grid gap-px bg-line"
          style="grid-template-columns: repeat(auto-fit, minmax(96px, 1fr))">
        <div v-for="m in [
               { k: 'Origen', v: h.source },
               { k: 'Certeza', v: h.confidence === 2 ? 'alta' : h.confidence === 1 ? 'media' : 'baja' },
               { k: 'Evidencias', v: String(h.evidencias) },
               { k: 'Visto desde', v: h.first_seen ? h.first_seen.slice(0, 10) : '—' },
             ]"
             :key="m.k"
             class="bg-surface px-3 py-[9px] min-w-0">
          <dt class="lbl !text-[9.5px] mb-1">{{ m.k }}</dt>
          <dd class="m-0 font-mono text-[12.5px] tabular-nums break-words">{{ m.v }}</dd>
        </div>
      </dl>

      <div class="px-[18px] py-4">
        <template v-if="h.description">
          <h2 class="lbl m-0 mb-[7px]">Qué ocurre</h2>
          <p class="m-0 mb-[17px] text-[13.5px] leading-[1.62] text-[#CBD4E2] max-w-[62ch]">
            {{ h.description }}
          </p>
        </template>
        <template v-if="h.remediation">
          <h2 class="lbl m-0 mb-[7px]">Cómo se corrige</h2>
          <p class="m-0 mb-[17px] text-[13.5px] leading-[1.62] text-[#CBD4E2] max-w-[62ch]
                    border-l-2 border-accent-dim pl-[13px]">
            {{ h.remediation }}
          </p>
        </template>
        <h2 class="lbl m-0">Evidencia</h2>
      </div>

      <div v-if="primera" class="flex gap-px border-b border-line bg-line mt-1">
        <button
          v-for="p in [
            { id: 'peticion', texto: 'Petición', hay: !!primera.request },
            { id: 'respuesta', texto: 'Respuesta', hay: !!primera.response },
            // El diff solo tiene sentido en un hallazgo ya visto antes.
            { id: 'diff', texto: 'Diff', hay: true },
          ]"
          :key="p.id"
          class="flex-1 py-2 px-[6px] bg-surface lbl !text-[10.5px]"
          :class="[
            pestana === p.id ? '!bg-surface-3 !text-accent' : 'hover:!text-fg-dim',
            !p.hay ? 'opacity-40 cursor-not-allowed' : '',
          ]"
          :disabled="!p.hay"
          :aria-selected="pestana === p.id"
          @click="pestana = p.id as any"
        >{{ p.texto }}</button>
      </div>

      <VisorDiff v-if="primera && pestana === 'diff'" :finding-id="h.id" />
      <VisorHttp
        v-else-if="primera"
        :texto="(pestana === 'peticion' ? primera.request : primera.response) ?? ''"
      />
      <p v-else-if="cargandoEvidencia" class="px-[18px] text-fg-faint text-[12.5px]">
        cargando evidencia…
      </p>
      <p v-else class="px-[18px] pb-4 text-fg-faint text-[12.5px]">
        Este hallazgo no tiene evidencia HTTP asociada.
      </p>

      <div class="flex gap-2 flex-wrap px-[18px] py-[14px] pb-[22px] mt-auto border-t border-line">
        <button
          v-for="a in ACCIONES"
          :key="a.estado"
          class="border rounded-cx px-3 py-[6px] text-[12.5px]"
          :class="a.principal
            ? 'bg-accent border-accent text-accent-ink font-bold hover:brightness-110'
            : 'border-line-strong text-fg-dim hover:border-accent-dim hover:text-fg'"
          :aria-pressed="h.status === a.estado"
          :title="h.status === a.estado ? 'Pulsa otra vez para quitar la marca' : ''"
          @click="triar(a.estado)"
        >{{ h.status === a.estado ? '✓ ' + a.texto : a.texto }}</button>
        <p v-if="h.status !== 'new'" class="w-full m-0 text-[11.5px] text-fg-faint">
          Marcado como «{{ ESTADO_ES[h.status] ?? h.status }}». Pulsa el mismo
          botón para quitarlo y dejarlo sin triar.
        </p>
      </div>
    </template>
  </aside>
</template>
