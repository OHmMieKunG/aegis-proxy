#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use rustls::server::Acceptor;

fuzz_target!(|data: &[u8]| {
    let mut acceptor = Acceptor::default();
    let _ = acceptor.read_tls(&mut Cursor::new(data));
    let _ = acceptor.accept();
});
