// @ts-check
import { defineConfig } from "astro/config";
import vue from "@astrojs/vue";
import tailwindcss from "@tailwindcss/vite";

// Enprot documentation site.
//
// Stack: Astro 7 (content-heavy, mostly static), Vite 8 (build),
// Vue 3 islands (interactive components: capability explorer,
// chain visualizer, merge-playground), Tailwind 4 (styling via
// the official Vite plugin — no PostCSS config needed).
//
// Source content lives in src/pages/ as .astro files; deep dives
// on each stage live in src/pages/docs/stages/ and examples in
// src/pages/docs/examples/.
export default defineConfig({
  site: "https://enprot.dev",
  vite: {
    plugins: [tailwindcss()],
  },
  integrations: [vue()],
});
