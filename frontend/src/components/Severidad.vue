<script setup lang="ts">
import type { Severidad } from '@/api/types'

const props = withDefaults(
  defineProps<{ nivel: Severidad; como?: 'punto' | 'etiqueta' | 'franja' }>(),
  { como: 'etiqueta' },
)

const ES: Record<Severidad, string> = {
  critical: 'crítica', high: 'alta', medium: 'media', low: 'baja', info: 'info',
}
// El color de severidad es el único saturado del sistema; se toma del token
// compartido con el informe para que ambos coincidan siempre.
const TOKEN: Record<Severidad, string> = {
  critical: 'var(--cx-crit)', high: 'var(--cx-high)', medium: 'var(--cx-med)',
  low: 'var(--cx-low)', info: 'var(--cx-info)',
}
</script>

<template>
  <span
    v-if="props.como === 'punto'"
    class="inline-block size-[7px] rounded-[2px] shrink-0"
    :style="{ background: TOKEN[props.nivel] }"
    :aria-label="ES[props.nivel]"
  />
  <span
    v-else-if="props.como === 'franja'"
    class="block w-[3px] self-stretch shrink-0"
    :style="{ background: TOKEN[props.nivel] }"
    aria-hidden="true"
  />
  <span
    v-else
    class="lbl shrink-0"
    :style="{ color: TOKEN[props.nivel], letterSpacing: '.1em' }"
  >{{ ES[props.nivel] }}</span>
</template>
