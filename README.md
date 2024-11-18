# nRF-Modem

[![crates.io](https://img.shields.io/crates/v/nrf-modem.svg)](https://crates.io/crates/nrf-modem) [![Documentation](https://docs.rs/nrf-modem/badge.svg)](https://docs.rs/nrf-modem)

This is a library that provides a high-level async API for the modem on the Nordic nRF91* series chips (System-in-Packages). Supported chips are the following:

* nRF9160
* nRF9151
* nRF9161

It can be used with any executor.

## Using

In your own program or library, you can depend on this crate in the usual fashion.

nrf9160:

```toml
[dependencies]
nrf-modem = { version = "x.x.x", features = ["nrf9160"] }
```

nrf9161:

```toml
[dependencies]
nrf-modem = { version = "x.x.x", features = ["nrf9161"] }
```

nrf9151:

```toml
[dependencies]
nrf-modem = { version = "x.x.x", features = ["nrf9151"] }
```

 The built-in modem DNS resolver is blocking. If you want to use an async DNS resolver you can enable the feature `dns-async`. This will switch to an async implementation which uses publicly availabe DNS servers.

## Errors and recovery

Dropping LteLink and Gnss (which also include all sockets and GnssStream) *can* lead to the modem staying active.
There's an internal mutex that can be locked. Panicking is the only sane reaction to that.
If you have a better idea, please open an issue or PR!
The async `deactivate` function is way less likely to go wrong and you'll get a Result back so you know that something has gone wrong.

If anything does go wrong, `has_runtime_state_error()` will return true.
Everything should stay working, but it's likely that the modem won't be properly turned off.
This can be recovered by calling the `reset_runtime_state()` function when you've made sure nothing of the modem is used anymore.

## Setup

There are a couple of things you must do to be able to use the library.

First of which, make sure to have the `llvm-tools` installed.
This can be done using `rustup component add llvm-tools-preview`.

The library also needs some `libc` functions.
The best way to import them is with [tinyrlibc](https://github.com/rust-embedded-community/tinyrlibc).
As of writing the newest release is `0.3.0`. This version does not include a needed API,
so it's better to include the latest master branch or any newer released version.

This library has been tested with modem firmware version `1.3.4` but might work with earlier versions.
When this library starts to require a newer version, then that will be seen as a breaking change.
But it's easy to miss something, so this is a 'best effort' guarantee only.

### Nonsecure

Nordic has made it so that the modem can only be used when in the nonsecure context.
Make sure you are in that context by using e.g. the SPM or TF-M.

### Interrupts

The `EGU1` and `IPC` interrupts must be routed to the modem software.

```rust,ignore
// Interrupt Handler for LTE related hardware. Defer straight to the library.
#[interrupt]
#[allow(non_snake_case)]
fn IPC() {
    nrf_modem::ipc_irq_handler();
}

let mut cp = unwrap!(cortex_m::Peripherals::take());

// Enable the modem interrupts
unsafe {
    NVIC::unmask(pac::Interrupt::IPC);
    cp.NVIC.set_priority(pac::Interrupt::IPC, 0 << 5);
}
```

### Power

The DC/DC converter is automatically enabled for you when the library is initialized.
This is required for certified operation of the modem.

### Initialization

Now it's time to initialize the library. Here you can make a selection for the connectivity for the modem:

```rust,ignore
nrf_modem::init(SystemMode {
    lte_support: true,
    lte_psm_support: true,
    nbiot_support: true,
    gnss_support: true,
    preference: ConnectionPreference::None,
})
.await
.unwrap();
```

Now the library is ready to be used.

## AT Commands

```rust,ignore
let response = nrf_modem::send_at::<64>("AT+CGMI").await.unwrap();
assert_eq!(response, "AT+CGMI\n\rNordic Semiconductor ASA\n\rOK\n\r");
```

## DNS request

```rust,ignore
let google_ip = nrf_modem::get_host_by_name("www.google.com").await.unwrap();
```

## Tcp connection

```rust,ignore
let stream = nrf_modem::TcpStream::connect(SocketAddr::from((google_ip, 80))).await.unwrap();

stream
    .write("GET / HTTP/1.0\nHost: google.com\r\n\r\n".as_bytes())
    .await
    .unwrap();

let mut buffer = [0; 1024];
let received = stream.receive(&mut buffer).await.unwrap();

println!("Google response: {}", core::str::from_utf8(received).unwrap());

// Drop the stream async (normal Drop is ok too, but that's blocking)
stream.deactivate().await.unwrap();
```

## Udp socket

```rust,ignore
let socket =
    nrf_modem::UdpSocket::bind(SocketAddr::from_str("0.0.0.0:53").unwrap())
        .await
        .unwrap();

// Do a DNS request
socket
    .send_to(
        &[
            0xdb, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x0C, 0x6E, 0x6F, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74, 0x65, 0x72,
            0x6E, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01,
        ],
        SocketAddr::from_str("8.8.8.8:53").unwrap(),
    )
    .await
    .unwrap();
let (response, source_addr) = socket.receive_from(&mut buffer).await.unwrap();

println!("Result: {:X}", response);
println!("Source: {}", source_addr);
```
