import { createRouter, createWebHistory } from 'vue-router'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/panel' },
    {
      path: '/panel',
      name: 'panel',
      component: () => import('@/features/dashboard/VistaPanel.vue'),
    },
    {
      path: '/hallazgos',
      name: 'hallazgos',
      component: () => import('@/features/findings/VistaHallazgos.vue'),
    },
    {
      path: '/superficie',
      name: 'superficie',
      component: () => import('@/features/surface/VistaSuperficie.vue'),
    },
    {
      path: '/escaneos',
      name: 'escaneos',
      component: () => import('@/features/scans/VistaEscaneos.vue'),
    },
  ],
})
