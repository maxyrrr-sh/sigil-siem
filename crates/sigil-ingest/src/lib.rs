//! `sigil-ingest` — inputs, codecs, template mining (DESIGN §5).
//!
//! Phase 0 scope: the `file` input ([`input::FileTailer`]) with checkpointing,
//! `syslog` UDP/TCP listeners, and the `json` / `syslog` codecs
//! ([`codec::build_codec`]). Template mining (DESIGN §9.2) lands in Phase 3.

pub mod codec;
pub mod input;
pub mod template;

pub use codec::{build_codec, JsonCodec, RawCodec, SyslogCodec};
pub use input::{spawn_syslog_tcp, spawn_syslog_udp, FileTailer};
pub use template::{Mined, TemplateMiner};
