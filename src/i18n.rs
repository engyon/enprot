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

//! Message localization (TODO.complete/71).
//!
//! Design: **compile-time static catalogs** — no gettext runtime, no
//! `.mo` parsing, no filesystem lookups. Every locale is a const
//! table keyed by [`MsgKey`]; lookup is a match, fallback is
//! English (missing key in a locale = English text, never a
//! missing message). Deterministic, auditable, zero new deps.
//!
//! Locale selection (the `--lang` flag is taken — it selects host
//! separator presets, a programming language, not a locale):
//!
//! 1. `$ENPROT_LOCALE`
//! 2. `locale` in `.enprot.toml`
//! 3. English
//!
//! Coverage in v1: the semantic-validation gate's user-facing
//! diagnostics (the messages every invocation can hit) plus the
//! escrow/det incompatibility error. Extending coverage = adding
//! keys + table rows; nothing else changes (OCP).

use std::sync::OnceLock;

/// One localizable message. Variants carry their interpolation
/// values; the per-locale tables render them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsgKey {
    /// `--fips forces --policy=nist but --policy={explicit} was set`
    FipsPolicyConflict { explicit: String },
    /// `--signer is set but neither --anchor nor --audit-log is; ...`
    SignerWithoutAnchor,
    /// `--jobs must be at least 1`
    JobsZero,
    /// `--jobs {requested} exceeds available CPUs ({available}); ...`
    JobsExceedsCpus { requested: usize, available: usize },
    /// `--output-dir has no effect when input is stdin ('-'); ...`
    OutputDirWithStdin,
    /// `--pbkdf-msec {requested} is below the policy minimum of {floor} ms`
    PbkdfMsecBelowFloor { requested: u32, floor: u32 },
    /// `--recovery-key is incompatible with {alg}: ...`
    RecoveryWithDet { alg: String },
}

/// Supported locales.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Locale {
    #[default]
    En,
    Ja,
    ZhCn,
    De,
    Fr,
}

impl Locale {
    pub fn parse(s: &str) -> Option<Locale> {
        match s.trim().to_ascii_lowercase().as_str() {
            "en" | "en_us" | "en-us" | "c" | "posix" | "" => Some(Locale::En),
            "ja" | "ja_jp" | "ja-jp" => Some(Locale::Ja),
            "zh-cn" | "zh_cn" | "zh-hans" | "zh" => Some(Locale::ZhCn),
            "de" | "de_de" | "de-de" | "de-at" | "de-ch" => Some(Locale::De),
            "fr" | "fr_fr" | "fr-fr" => Some(Locale::Fr),
            _ => None,
        }
    }

    fn render(&self, key: &MsgKey) -> String {
        use MsgKey::*;
        match (self, key) {
            // Japanese
            (Locale::Ja, FipsPolicyConflict { explicit }) => format!(
                "エラー: --fips は --policy=nist を強制しますが、--policy={explicit} が指定されました"
            ),
            (Locale::Ja, SignerWithoutAnchor) => concat!(
                "警告: --signer が指定されていますが --anchor も --audit-log もないため、",
                "署名鍵は使用されません"
            )
            .to_string(),
            (Locale::Ja, JobsZero) => "エラー: --jobs は 1 以上である必要があります".to_string(),
            (Locale::Ja, JobsExceedsCpus { requested, available }) => format!(
                "警告: --jobs {requested} は利用可能な CPU 数（{available}）を超えています。スケジューリングのオーバーヘッドが支配的になる可能性があります"
            ),
            (Locale::Ja, OutputDirWithStdin) => {
                "警告: 入力が標準入力（'-'）の場合、--output-dir は無効です。標準入力は常に標準出力へ書き込まれます".to_string()
            }
            (Locale::Ja, PbkdfMsecBelowFloor { requested, floor }) => format!(
                "エラー: --pbkdf-msec {requested} はポリシーの最小値 {floor} ms 未満です"
            ),
            (Locale::Ja, RecoveryWithDet { alg }) => format!(
                "エラー: --recovery-key は {alg} と併用できません。エスクローモードは暗号化ごとに新しい乱数鍵を使用するため、決定論的（同一入力→同一出力）契約が成立しません。aes-256-siv など非決定論的暗号を使用してください"
            ),

            // Simplified Chinese
            (Locale::ZhCn, FipsPolicyConflict { explicit }) => format!(
                "错误：--fips 强制 --policy=nist，但指定了 --policy={explicit}"
            ),
            (Locale::ZhCn, SignerWithoutAnchor) => concat!(
                "警告：已设置 --signer，但未设置 --anchor 或 --audit-log，",
                "签名密钥将不会被使用"
            )
            .to_string(),
            (Locale::ZhCn, JobsZero) => "错误：--jobs 至少为 1".to_string(),
            (Locale::ZhCn, JobsExceedsCpus { requested, available }) => format!(
                "警告：--jobs {requested} 超过可用 CPU 数（{available}），调度开销可能占主导"
            ),
            (Locale::ZhCn, OutputDirWithStdin) => {
                "警告：输入为标准输入（'-'）时 --output-dir 无效。标准输入始终写入标准输出".to_string()
            }
            (Locale::ZhCn, PbkdfMsecBelowFloor { requested, floor }) => format!(
                "错误：--pbkdf-msec {requested} 低于策略最小值 {floor} ms"
            ),
            (Locale::ZhCn, RecoveryWithDet { alg }) => format!(
                "错误：--recovery-key 与 {alg} 不兼容：托管模式每次加密使用新的随机密钥，无法满足确定性（相同输入→相同输出）约定。请使用非确定性加密（如 aes-256-siv）"
            ),

            // German
            (Locale::De, FipsPolicyConflict { explicit }) => format!(
                "Fehler: --fips erzwingt --policy=nist, aber --policy={explicit} wurde gesetzt"
            ),
            (Locale::De, SignerWithoutAnchor) => concat!(
                "Warnung: --signer ist gesetzt, aber weder --anchor noch --audit-log; ",
                "der Signaturschlüssel wird nicht verwendet"
            )
            .to_string(),
            (Locale::De, JobsZero) => "Fehler: --jobs muss mindestens 1 sein".to_string(),
            (Locale::De, JobsExceedsCpus { requested, available }) => format!(
                "Warnung: --jobs {requested} übersteigt die verfügbaren CPUs ({available}); Planungs-Overhead kann überwiegen"
            ),
            (Locale::De, OutputDirWithStdin) => concat!(
                "Warnung: --output-dir hat keine Wirkung, wenn die Eingabe stdin ('-') ist; ",
                "stdin wird immer auf stdout geschrieben"
            )
            .to_string(),
            (Locale::De, PbkdfMsecBelowFloor { requested, floor }) => format!(
                "Fehler: --pbkdf-msec {requested} liegt unter dem Richtlinien-Minimum von {floor} ms"
            ),
            (Locale::De, RecoveryWithDet { alg }) => format!(
                "Fehler: --recovery-key ist mit {alg} inkompatibel: Der Escrow-Modus verwendet pro Verschlüsselung einen neuen Zufallsschlüssel, wodurch die deterministische Vertragseigenschaft (gleiche Eingabe → gleiche Ausgabe) nicht hält. Verwenden Sie eine nicht-deterministische Chiffre wie aes-256-siv"
            ),

            // French
            (Locale::Fr, FipsPolicyConflict { explicit }) => format!(
                "erreur : --fips impose --policy=nist mais --policy={explicit} a été défini"
            ),
            (Locale::Fr, SignerWithoutAnchor) => concat!(
                "avertissement : --signer est défini mais ni --anchor ni --audit-log ; ",
                "la clé de signature ne sera pas utilisée"
            )
            .to_string(),
            (Locale::Fr, JobsZero) => "erreur : --jobs doit valoir au moins 1".to_string(),
            (Locale::Fr, JobsExceedsCpus { requested, available }) => format!(
                "avertissement : --jobs {requested} dépasse les CPU disponibles ({available}) ; la surcharge d'ordonnancement peut dominer"
            ),
            (Locale::Fr, OutputDirWithStdin) => concat!(
                "avertissement : --output-dir n'a aucun effet quand l'entrée est stdin ('-') ; ",
                "stdin est toujours écrit sur stdout"
            )
            .to_string(),
            (Locale::Fr, PbkdfMsecBelowFloor { requested, floor }) => format!(
                "erreur : --pbkdf-msec {requested} est inférieur au minimum de politique de {floor} ms"
            ),
            (Locale::Fr, RecoveryWithDet { alg }) => format!(
                "erreur : --recovery-key est incompatible avec {alg} : le mode escrow utilise une nouvelle clé aléatoire par chiffrement, ce qui rompt le contrat déterministe (même entrée → même sortie). Utilisez un chiffrement non déterministe comme aes-256-siv"
            ),

            // English (default / fallback for uncovered combinations)
            (Locale::En, FipsPolicyConflict { explicit }) => format!(
                "error: --fips forces --policy=nist but --policy={explicit} was set"
            ),
            (Locale::En, SignerWithoutAnchor) => concat!(
                "warning: --signer is set but neither --anchor nor --audit-log is; ",
                "the signer key will not be used"
            )
            .to_string(),
            (Locale::En, JobsZero) => "error: --jobs must be at least 1".to_string(),
            (Locale::En, JobsExceedsCpus { requested, available }) => format!(
                "warning: --jobs {requested} exceeds available CPUs ({available}); scheduling overhead may dominate"
            ),
            (Locale::En, OutputDirWithStdin) => concat!(
                "warning: --output-dir has no effect when input is stdin ('-'); ",
                "stdin always writes to stdout"
            )
            .to_string(),
            (Locale::En, PbkdfMsecBelowFloor { requested, floor }) => format!(
                "error: --pbkdf-msec {requested} is below the policy minimum of {floor} ms"
            ),
            (Locale::En, RecoveryWithDet { alg }) => format!(
                "error: --recovery-key is incompatible with {alg}: escrow mode uses a fresh random key per encryption, so the deterministic (same-input → same-output) contract cannot hold; use a non-det cipher such as aes-256-siv"
            ),
        }
    }
}

/// Resolve the process-wide locale once: `$ENPROT_LOCALE`, then the
/// `locale` config field (passed by the CLI layer after config
/// load), then English.
pub fn resolve_locale(config_locale: Option<&str>) -> Locale {
    static LOCALE: OnceLock<Locale> = OnceLock::new();
    *LOCALE.get_or_init(|| {
        std::env::var("ENPROT_LOCALE")
            .ok()
            .as_deref()
            .or(config_locale)
            .and_then(Locale::parse)
            .unwrap_or_default()
    })
}

/// Render `key` in the process locale.
pub fn tr(key: &MsgKey) -> String {
    resolve_locale(None).render(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_is_the_fallback() {
        assert_eq!(tr(&MsgKey::JobsZero), "error: --jobs must be at least 1");
    }

    #[test]
    fn every_locale_renders_every_key() {
        for locale in [Locale::En, Locale::Ja, Locale::ZhCn, Locale::De, Locale::Fr] {
            for key in [
                MsgKey::FipsPolicyConflict {
                    explicit: "default".into(),
                },
                MsgKey::SignerWithoutAnchor,
                MsgKey::JobsZero,
                MsgKey::JobsExceedsCpus {
                    requested: 99,
                    available: 1,
                },
                MsgKey::OutputDirWithStdin,
                MsgKey::PbkdfMsecBelowFloor {
                    requested: 10,
                    floor: 100,
                },
                MsgKey::RecoveryWithDet {
                    alg: "aes-256-gcm-det".into(),
                },
            ] {
                let rendered = locale.render(&key);
                assert!(!rendered.is_empty(), "{locale:?} rendered an empty {key:?}");
                assert!(
                    rendered.contains("--") || rendered.contains('：') || rendered.contains("："),
                    "{locale:?} rendering lost the flag reference: {rendered}"
                );
            }
        }
    }

    #[test]
    fn locale_parse_accepts_common_forms() {
        assert_eq!(Locale::parse("ja_JP"), Some(Locale::Ja));
        assert_eq!(Locale::parse("zh-CN"), Some(Locale::ZhCn));
        assert_eq!(Locale::parse("de-AT"), Some(Locale::De));
        assert_eq!(Locale::parse("fr"), Some(Locale::Fr));
        assert_eq!(Locale::parse("en"), Some(Locale::En));
        assert_eq!(Locale::parse("klingon"), None);
    }

    #[test]
    fn interpolations_survive_translation() {
        let ja = Locale::Ja.render(&MsgKey::PbkdfMsecBelowFloor {
            requested: 7,
            floor: 100,
        });
        assert!(ja.contains('7') && ja.contains("100"), "{ja}");
        let de = Locale::De.render(&MsgKey::FipsPolicyConflict {
            explicit: "default".into(),
        });
        assert!(de.contains("default"), "{de}");
    }
}
