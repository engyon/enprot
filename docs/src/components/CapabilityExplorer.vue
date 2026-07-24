<script setup lang="ts">
// Interactive capability explorer. User toggles flags, we compute
// the resulting CapabilitySet using the same rules as src/capability.rs.
//
// This is a Vue island — server-rendered shell with client-side
// interactivity hydrated on load.

import { computed, ref } from "vue";

const hasCasdir = ref(true);
const passwords = ref<string[]>(["Agent_007"]);
const newPassword = ref("");

function addPassword() {
  const p = newPassword.value.trim();
  if (p && !passwords.value.includes(p)) {
    passwords.value.push(p);
  }
  newPassword.value = "";
}

function removePassword(word: string) {
  passwords.value = passwords.value.filter((p) => p !== word);
}

interface Cap {
  tier: string;
  detail?: string;
}

const capabilities = computed<Cap[]>(() => {
  const caps: Cap[] = [{ tier: "viewer" }];
  if (hasCasdir.value) caps.push({ tier: "reader" });
  for (const word of passwords.value) {
    caps.push({ tier: "decryptor", detail: word });
  }
  // Stable sort: viewer, reader, then decryptor by WORD alphabetical
  caps.sort((a, b) => {
    const order = ["viewer", "reader", "decryptor", "signer", "verifier"];
    const oa = order.indexOf(a.tier);
    const ob = order.indexOf(b.tier);
    if (oa !== ob) return oa - ob;
    return (a.detail || "").localeCompare(b.detail || "");
  });
  return caps;
});
</script>

<template>
  <div class="grid md:grid-cols-2 gap-6">
    <div class="border border-enprot-ink/10 rounded p-4 bg-white">
      <h3 class="font-semibold mb-3">Flags</h3>

      <label class="flex items-center gap-2 mb-3 cursor-pointer">
        <input type="checkbox" v-model="hasCasdir" class="cursor-pointer" />
        <code class="text-sm">-c &lt;casdir&gt;</code>
        <span class="text-xs text-enprot-muted">(grant Reader)</span>
      </label>

      <div class="mb-3">
        <div class="text-sm font-mono mb-1">passwords</div>
        <ul class="space-y-1 mb-2">
          <li v-for="p in passwords" :key="p" class="flex items-center gap-2">
            <code class="text-sm bg-enprot-ink/5 px-1">-k {{ p }}=…</code>
            <button
              @click="removePassword(p)"
              class="text-xs text-enprot-muted hover:text-red-600 cursor-pointer"
            >
              remove
            </button>
          </li>
        </ul>
        <div class="flex gap-2">
          <input
            v-model="newPassword"
            @keyup.enter="addPassword"
            placeholder="WORD"
            class="border border-enprot-ink/20 px-2 py-1 text-sm flex-1"
          />
          <button
            @click="addPassword"
            class="px-3 py-1 bg-enprot-accent text-white text-sm cursor-pointer"
          >
            add
          </button>
        </div>
      </div>
    </div>

    <div class="border border-enprot-ink/10 rounded p-4 bg-enprot-ink text-enprot-paper">
      <h3 class="font-semibold mb-3">CapabilitySet</h3>
      <pre class="text-sm"><code>$ enprot capabilities
<template v-for="cap in capabilities" :key="cap.tier + (cap.detail || '')">{{ cap.tier }}<template v-if="cap.detail">({{ cap.detail }})</template>
</template></code></pre>
    </div>
  </div>
</template>
