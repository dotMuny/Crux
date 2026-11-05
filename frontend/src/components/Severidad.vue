<script setup lang="ts">
/**
 * La severidad, dicha dos veces: con color y con figura.
 *
 * Rombo, triángulo, cuadrado, círculo y círculo hueco. La rampa rojo-ámbar-
 * amarillo no se distingue bajo protanopía, así que el color solo no basta;
 * con la figura la lista se lee igual aunque los tres tonos se confundan. Las
 * figuras están definidas en tokens.css para que el informe use las mismas.
 */
import type { Severidad } from '@/api/types'

const props = withDefaults(
  defineProps<{
    nivel: Severidad
    /** `figura`: solo la figura. `etiqueta`: solo el nombre. `ambas`: las dos. */
    como?: 'figura' | 'etiqueta' | 'ambas' | 'punto' | 'franja'
    /** Tamaño de la figura en px. */
    talla?: number
  }>(),
  { como: 'etiqueta', talla: 14 },
)

const ES: Record<Severidad, string> = {
  critical: 'crítica', high: 'alta', medium: 'media', low: 'baja', info: 'info',
}
// Solo lo que pide atención lleva color en el texto; el resto se lee en gris
// y deja que la figura haga el trabajo.
const TINTA: Record<Severidad, string> = {
  critical: 'var(--cx-crit-fg)', high: 'var(--cx-high-fg)',
  medium: 'var(--cx-fg-dim)', low: 'var(--cx-fg-dim)', info: 'var(--cx-fg-faint)',
}
</script>

<template>
  <!-- `punto` y `franja` son los nombres antiguos: se conservan para que nadie
       tenga que tocar quien los usa, y dibujan la figura. -->
  <span
    v-if="props.como !== 'etiqueta'"
    class="inline-flex items-center gap-[8px] shrink-0"
    :class="props.como === 'franja' ? 'justify-center' : ''"
  >
    <i
      class="cx-fig"
      :class="`sev-${props.nivel}`"
      :style="{ fontSize: `${props.talla}px` }"
      role="img"
      :aria-label="`severidad ${ES[props.nivel]}`"
    />
    <span
      v-if="props.como === 'ambas'"
      class="text-[13px]"
      :class="props.nivel === 'critical' || props.nivel === 'high' ? 'font-bold' : ''"
      :style="{ color: TINTA[props.nivel] }"
    >{{ ES[props.nivel] }}</span>
  </span>
  <span
    v-else
    class="text-[13px] shrink-0"
    :class="props.nivel === 'critical' || props.nivel === 'high' ? 'font-bold' : ''"
    :style="{ color: TINTA[props.nivel] }"
  >{{ ES[props.nivel] }}</span>
</template>
