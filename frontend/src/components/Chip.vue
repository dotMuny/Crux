<script setup lang="ts">
withDefaults(defineProps<{ tono?: 'neutro' | 'acento' }>(), { tono: 'neutro' })
</script>

<template>
  <span
    class="font-mono text-[11px] px-[7px] py-[2px] rounded-[3px] border whitespace-nowrap"
    :class="tono === 'acento'
      ? 'text-accent border-accent-dim'
      : 'text-fg-dim border-line-strong'"
  ><slot /></span>
</template>
