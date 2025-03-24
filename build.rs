fn main() {
    #[cfg(feature = "modem-log")]
    cc::Build::new()
        .file("wrapper/nrf_modem_os_log.c")
        .compile("nrf_modem_os_log");
}
