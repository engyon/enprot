# 37 — Plugin system for CAS + transform backends

**Priority**: P3
**Status**: specified

## Problem

enprot's CAS and transform surfaces are extensible *internally*
(`CasStore` trait, transform dispatch table) but not *externally*.
A downstream consumer who wants:

- A custom CAS backend (e.g. a proprietary object store).
- A custom transform (e.g. compress-then-encrypt).
- A custom extfield parser.

…must fork enprot and modify the source. There's no plugin ABI.

This is fine for the current adoption stage. As enprot stabilises,
ecosystem growth will demand a plugin surface so third parties can
extend without forking.

## Goals

- A plugin ABI (stable, versioned) that lets third-party Rust crates
  register custom CAS backends + custom transforms.
- Plugins are loaded at startup via a `--plugin <path>` CLI flag or
  a `[plugins]` section in `.enprot.toml`.
- Plugins are isolated: a panic in a plugin doesn't crash enprot
  (catch_unwind at the ABI boundary).
- Plugins are versioned: the plugin declares its ABI version; enprot
  refuses to load incompatible plugins.

## Design

### Plugin trait

```rust
// src/plugin.rs (new)
pub trait Plugin: Send + Sync {
    /// Plugin name (for error messages + logging).
    fn name(&self) -> &'static str;

    /// ABI version this plugin was built against.
    fn abi_version(&self) -> u32;

    /// Register hooks. Called once at plugin load.
    fn register(&self, registry: &mut PluginRegistry);
}

pub struct PluginRegistry {
    cas_backends: Vec<CasBackendSpec>,
    transforms: Vec<TransformSpec>,
    extfield_parsers: Vec<ExtfieldParserSpec>,
}

impl PluginRegistry {
    pub fn register_cas_backend(&mut self, scheme: &str, ctor: CasCtor) { /* ... */ }
    pub fn register_transform(&mut self, name: &str, ctor: TransformCtor) { /* ... */ }
}
```

### Loading

Two mechanisms:

1. **Static (compile-time)**: a downstream crate adds enprot as a
   dep, implements `Plugin`, and calls `enprot::register_plugin(my_plugin)`
   in its `build.rs` or main. The plugin is linked into the binary.

2. **Dynamic (runtime)**: `libloading`-based `.so`/`.dll`/`.dylib`
   loading. The plugin exports a `extern "C" fn enprot_plugin_create()
   -> *mut dyn Plugin`. enprot loads it via `--plugin <path>`.

Static is the default (zero overhead, type-safe). Dynamic is for
closed-source plugins or runtime extension.

### Isolation

```rust
fn call_plugin_cas_save(plugin: &dyn CasStore, blob: &[u8]) -> Result<String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        plugin.save(blob)
    }))
    .map_err(|_| Error::PluginCrash(plugin.name()))?
}
```

Every plugin call is wrapped in `catch_unwind`. A panic maps to
`Error::PluginCrash(name)`; enprot continues serving other requests.

### Versioning

```rust
const ABI_VERSION: u32 = 1;

impl Plugin for MyPlugin {
    fn abi_version(&self) -> u32 { ABI_VERSION }
}

// At load time:
if plugin.abi_version() != enprot::ABI_VERSION {
    return Err(Error::PluginAbiMismatch {
        plugin: plugin.name().into(),
        plugin_version: plugin.abi_version(),
        enprot_version: enprot::ABI_VERSION,
    });
}
```

## Implementation plan

1. Add `src/plugin.rs` with the `Plugin` trait + `PluginRegistry`.
2. Refactor `cas::open_cas` to consult the registry for the scheme.
3. Add `Error::PluginCrash` + `Error::PluginAbiMismatch` variants.
4. Implement static plugin loading via `inventory` crate (distributed slice).
5. Implement dynamic plugin loading via `libloading`.
6. Add `--plugin <path>` CLI flag.
7. Add `[plugins.<name>]` to `.enprot.toml`.
8. Document the plugin ABI in `docs/plugins.md`.
9. Example plugin in `examples/plugin_custom_cas/`.

## Test plan

- [ ] A static plugin registers a custom CAS backend; `--casdir custom://foo` uses it.
- [ ] A dynamic plugin loaded via `--plugin ./libmyplugin.so` works.
- [ ] A plugin that panics during `save` produces `Error::PluginCrash`, not a process crash.
- [ ] A plugin built against ABI v0 is refused by enprot ABI v1 with a clear message.

## Out of scope

- A stable C ABI for non-Rust plugins (would require a C header +
  `cbindgen`; defer until demand is clear).
- Plugin sandboxing (no filesystem/network access). Use OS-level
  sandboxing instead.
- A plugin marketplace / registry (organisational, not technical).
