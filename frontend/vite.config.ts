import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  // El build va directo a donde FastAPI sirve los estáticos: el dist auditado
  // se versiona y se distribuye, de modo que npm nunca toca el equipo de un
  // analista. Ver docs/decisiones.md.
  build: {
    outDir: '../crux/web/dist',
    emptyOutDir: true,
    // Sin sourcemaps en el entregable: pesan y exponen el código original.
    sourcemap: false,
    rollupOptions: {
      output: {
        // Las librerías pesadas en trozos aparte, para que el arranque no
        // espere al grafo ni a las gráficas. Vite 8 solo admite la forma de
        // función: la de objeto se retiró.
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return
          if (id.includes('cytoscape')) return 'grafo'
          if (id.includes('echarts') || id.includes('zrender')) return 'graficas'
          if (id.includes('@codemirror') || id.includes('@lezer')) return 'editor'
          if (/node_modules\/(vue|vue-router|pinia|@vue)\//.test(id)) return 'vendor'
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    // En desarrollo, la API la sirve el backend en su puerto.
    proxy: { '/api': { target: 'http://127.0.0.1:8777', changeOrigin: false } },
  },
})
