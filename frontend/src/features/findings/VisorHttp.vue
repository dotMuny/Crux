<script setup lang="ts">
/**
 * Visor de HTTP crudo.
 *
 * Resalta los nombres de cabecera y nada más. Un resaltador de sintaxis
 * completo sobre una respuesta de 8 KB aporta poco y cuesta: lo que el
 * analista busca es la cabecera o el valor concreto, y para eso basta con
 * separar visualmente nombres de valores.
 *
 * El contenido viene del objetivo auditado, así que jamás se inyecta como
 * HTML: se escapa y se trocea en nodos de texto.
 */
import { computed } from 'vue'

const props = defineProps<{ texto: string }>()

interface Trozo { tipo: 'cabecera' | 'texto'; valor: string }

const lineas = computed<Trozo[][]>(() =>
  props.texto.split('\n').map((linea) => {
    const m = /^([A-Za-z][A-Za-z0-9-]*)(:)(.*)$/.exec(linea)
    if (!m) return [{ tipo: 'texto', valor: linea }]
    return [
      { tipo: 'cabecera', valor: m[1] },
      { tipo: 'texto', valor: m[2] + m[3] },
    ]
  }),
)
</script>

<template>
  <pre
    class="m-0 px-[15px] py-[13px] overflow-x-auto bg-surface-3 border-b border-line
           font-mono text-[11.5px] leading-[1.72] text-[#B9C4D4] whitespace-pre"
  ><template v-for="(linea, i) in lineas" :key="i"><span
      v-for="(t, j) in linea" :key="j"
      :class="t.tipo === 'cabecera' ? 'text-accent' : ''"
    >{{ t.valor }}</span>{{ '\n' }}</template></pre>
</template>
