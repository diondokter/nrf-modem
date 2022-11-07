# nRF-Modem

This is a library that provides a high-level async API for the nRF9160 modem.

It can be used with any executor.

## Setup

There are a couple of things you must do to be able to use the library.

### Nonsecure

Nordic has made it so that the modem can only be used when in the nonsecure context.
Make sure you are in that context by using e.g. the SPM.

### Interrupts

The `EGU1` and `IPC` interrupts must be routed to the modem software.
In embassy you can do that as follows:

```rust
let egu1 = embassy_nrf::interrupt::take!(EGU1);
egu1.set_priority(Priority::P4);
egu1.set_handler(|_| {
    nrf_modem::application_irq_handler();
    cortex_m::asm::sev();
});
egu1.enable();

let ipc = embassy_nrf::interrupt::take!(IPC);
ipc.set_priority(Priority::P0);
ipc.set_handler(|_| {
    nrf_modem::ipc_irq_handler();
    cortex_m::asm::sev();
});
ipc.enable();
```
This can be done using the normal `cortex-m-rt` interrupts as well of course.

### Power

The DC/DC converter is automatically enabled for you when the library is initialized.
This is required for certified operation of the modem.

### Initialization

Now it's time to initialize the library. Here you can make a selection for the connectivity for the modem:

```rust
nrf_modem::init(SystemMode {
    lte_support: true,
    nbiot_support: true,
    gnss_support: true,
    preference: ConnectionPreference::None,
})
.await
.unwrap();
```
Now the library is ready to be used.

## AT Commands

```rust
let response = nrf_modem::send_at::<64>("AT+CGMI").await.unwrap();
assert_eq!(response, "AT+CGMI\n\rNordic Semiconductor ASA\n\rOK\n\r");
```

## DNS request

```rust
let google_ip = nrf_modem::get_host_by_name("www.google.com").await.unwrap();
```

## Tcp connection

```rust
let stream = nrf_modem::TcpStream::connect(SocketAddr::from((google_ip, 80)).await.unwrap();

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

```rust
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