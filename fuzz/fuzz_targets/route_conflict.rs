#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(config) = aegisproxy_config::load_bytes(data) {
        let _ = aegisproxy_core::RouteIndex::compile(&config).fingerprint();
    }
});
