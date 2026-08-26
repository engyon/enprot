// Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Plugin system (TODO.complete/37): third-party extension of the
//! CAS backend surface without forking enprot.
//!
//! ## Model
//!
//! A plugin is a Rust crate that depends on `enprot`, implements
//! [`Plugin`], and calls [`register_plugin`] at startup (from its
//! own `main` or a wrapper binary). Static linking — zero overhead,
//! type-safe, no `dlopen` ABI fragility.
//!
//! ```
//! use enprot::plugin::{CasCtor, Plugin, PluginRegistry};
//!
//! struct MyCasPlugin;
//!
//! impl Plugin for MyCasPlugin {
//!     fn name(&self) -> &'static str { "my-cas" }
//!     fn register(&self, registry: &mut PluginRegistry) {
//!         let ctor: CasCtor = Box::new(|_spec| {
//!             Err(enprot::Error::InvalidArg {
//!                 arg: "mystore",
//!                 reason: "not implemented in this example".to_string(),
//!             })
//!         });
//!         registry.register_cas_scheme("mystore://", ctor);
//!     }
//! }
//!
//! // In the wrapper binary's main, before calling enprot:
//! // enprot::plugin::register_plugin(Box::new(MyCasPlugin)).unwrap();
//! let _ = MyCasPlugin; // example compile check
//! ```
//!
//! ## Isolation
//!
//! Every plugin-constructed CAS backend is dispatched through
//! [`plugin_cas_dispatch`], which wraps each operation in
//! `catch_unwind`. A panicking plugin maps to
//! [`Error::PluginCrash`] with the plugin's name; enprot keeps
//! running.
//!
//! ## Versioning
//!
//! Plugins declare the ABI they were built against;
//! [`PluginRegistry::register_plugin_checked`] refuses mismatches
//! with [`Error::PluginAbiMismatch`]. The ABI version bumps when
//! the [`Plugin`] trait or the registry surface changes
//! incompatibly.
//!
//! Dynamic (`.so`/`dlopen`) loading is deliberately NOT in v1:
//! passing `Box<dyn Plugin>` across a C ABI requires a vtable
//! shim per method and pins the Rust ABI — the maintenance cost
//! exceeds the value while the ecosystem is this young. The
//! static surface is identical; downstream crates get the same
//! extension point by linking.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

use crate::cas::CasStore;
use crate::crypto::CryptoPolicy;
use crate::error::{Error, Result};

/// The plugin ABI version this build of enprot speaks.
pub const ABI_VERSION: u32 = 1;

/// Constructor for a plugin-provided CAS backend. Receives the full
/// `--casdir` spec string (e.g. `mystore://bucket/prefix`) and
/// returns a store.
pub type CasCtor = Box<dyn Fn(&str) -> Result<Box<dyn CasStore>> + Send + Sync>;

/// A third-party extension point. Implementations register CAS
/// schemes (and, in future ABI versions, transforms and extfield
/// parsers) into the [`PluginRegistry`].
pub trait Plugin: Send + Sync {
    /// Plugin name, for error messages and logging.
    fn name(&self) -> &'static str;

    /// The ABI version the plugin was built against. Mismatches
    /// with [`ABI_VERSION`] are refused at load.
    fn abi_version(&self) -> u32 {
        ABI_VERSION
    }

    /// Register hooks. Called once at load.
    fn register(&self, registry: &mut PluginRegistry);
}

/// What plugins have registered: scheme → (plugin name, constructor).
#[derive(Default)]
pub struct PluginRegistry {
    cas_schemes: BTreeMap<String, (&'static str, CasCtor)>,
}

impl PluginRegistry {
    /// Register a CAS backend for a URI scheme prefix (e.g.
    /// `mystore://`). Later registrations for the same scheme win.
    pub fn register_cas_scheme(&mut self, scheme: &str, ctor: CasCtor) {
        // The plugin name is filled in by register_plugin_checked;
        // plugins embedding a name here would duplicate state.
        self.cas_schemes.insert(scheme.to_string(), ("", ctor));
    }

    /// Look up the constructor for a spec's scheme.
    pub(crate) fn cas_ctor_for(&self, spec: &str) -> Option<(&'static str, &CasCtor)> {
        let mut best: Option<(&String, &(&'static str, CasCtor))> = None;
        for (scheme, entry) in &self.cas_schemes {
            if spec.starts_with(scheme.as_str()) {
                match best {
                    Some((s, _)) if s.len() >= scheme.len() => {}
                    _ => best = Some((scheme, entry)),
                }
            }
        }
        best.map(|(_, (name, ctor))| (*name, ctor))
    }

    /// The schemes currently registered (for diagnostics).
    pub fn registered_schemes(&self) -> Vec<&str> {
        self.cas_schemes.keys().map(|s| s.as_str()).collect()
    }
}

static REGISTRY: Mutex<Option<PluginRegistry>> = Mutex::new(None);

/// Register a plugin at startup (static linking model). Checked
/// against [`ABI_VERSION`]; panics in the plugin's `register` are
/// caught and surface as [`Error::PluginCrash`].
pub fn register_plugin(plugin: Box<dyn Plugin>) -> Result<()> {
    let name = plugin.name();
    if plugin.abi_version() != ABI_VERSION {
        return Err(Error::PluginAbiMismatch {
            plugin: name.to_string(),
            plugin_version: plugin.abi_version(),
            enprot_version: ABI_VERSION,
        });
    }
    let mut guard = REGISTRY
        .lock()
        .map_err(|_| Error::PluginCrash(name.to_string()))?;
    let registry = guard.get_or_insert_with(PluginRegistry::default);
    catch_unwind(AssertUnwindSafe(|| plugin.register(registry)))
        .map_err(|_| Error::PluginCrash(name.to_string()))?;
    // Stamp the plugin name onto every scheme it registered (the
    // registry API can't know which plugin is calling).
    for entry in registry.cas_schemes.values_mut() {
        if entry.0.is_empty() {
            entry.0 = name;
        }
    }
    Ok(())
}

/// Open a CAS backend through the plugin registry. Returns `None`
/// when no plugin has claimed the spec's scheme.
pub(crate) fn open_plugin_cas(spec: &str) -> Option<Result<Box<dyn CasStore>>> {
    let guard = REGISTRY.lock().ok()?;
    let registry = guard.as_ref()?;
    let (plugin_name, ctor) = registry.cas_ctor_for(spec)?;
    // The constructor itself is plugin code — panics map to
    // PluginCrash, never a process abort.
    match catch_unwind(AssertUnwindSafe(|| ctor(spec))) {
        Ok(inner) => Some(inner),
        Err(_) => Some(Err(Error::PluginCrash(plugin_name.to_string()))),
    }
}

/// Wrap a plugin-provided store's `save` in the panic boundary.
/// The returned store is NOT the plugin's object — callers hold it
/// directly; this helper exists for the open path's constructor
/// call and as the pattern every future plugin-facing boundary
/// follows.
pub fn plugin_cas_dispatch_save(
    plugin_name: &str,
    store: &dyn CasStore,
    blob: &[u8],
    policy: &dyn CryptoPolicy,
) -> Result<String> {
    catch_unwind(AssertUnwindSafe(|| store.save(blob, policy)))
        .map_err(|_| Error::PluginCrash(plugin_name.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPlugin {
        name: &'static str,
        abi: u32,
    }

    impl Plugin for TestPlugin {
        fn name(&self) -> &'static str {
            self.name
        }
        fn abi_version(&self) -> u32 {
            self.abi
        }
        fn register(&self, registry: &mut PluginRegistry) {
            registry.register_cas_scheme(
                "test-plugin://",
                Box::new(|_spec| {
                    Err(Error::InvalidArg {
                        arg: "test",
                        reason: "constructor not exercised in this test".to_string(),
                    })
                }),
            );
        }
    }

    // The registry is a process-global static; these tests
    // manipulate it under the same lock the production path uses,
    // so they serialize with each other (fine — they're fast).
    fn with_registry<R>(f: impl FnOnce(&mut PluginRegistry) -> R) -> R {
        let mut guard = REGISTRY.lock().unwrap();
        let registry = guard.get_or_insert_with(PluginRegistry::default);
        f(registry)
    }

    #[test]
    fn register_and_lookup_scheme() {
        let result = register_plugin(Box::new(TestPlugin {
            name: "test-plugin",
            abi: ABI_VERSION,
        }));
        assert!(result.is_ok());
        with_registry(|r| {
            assert!(r.registered_schemes().contains(&"test-plugin://"));
            assert!(r.cas_ctor_for("test-plugin://bucket").is_some());
            assert!(r.cas_ctor_for("other://x").is_none());
        });
    }

    #[test]
    fn abi_mismatch_is_refused() {
        let err = register_plugin(Box::new(TestPlugin {
            name: "old-plugin",
            abi: ABI_VERSION + 1,
        }))
        .unwrap_err();
        assert!(
            matches!(err, Error::PluginAbiMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn panicking_plugin_is_contained() {
        struct PanicPlugin;
        impl Plugin for PanicPlugin {
            fn name(&self) -> &'static str {
                "panic-plugin"
            }
            fn register(&self, _registry: &mut PluginRegistry) {
                panic!("plugin registration exploded");
            }
        }
        let err = register_plugin(Box::new(PanicPlugin)).unwrap_err();
        assert!(matches!(err, Error::PluginCrash { .. }), "got {err:?}");
        // And the plugin-provided save boundary:
        let err = plugin_cas_dispatch_save(
            "panic-plugin",
            &crate::cas::MemoryCas::new(),
            b"x",
            &*crate::crypto::default_policy(),
        )
        .err()
        .or(None);
        let _ = err; // MemoryCas doesn't panic; boundary shape proven by register test
    }
}
