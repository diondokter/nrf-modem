# nRF-Modem

This is a library that provides a high-level async API for the nRF9160 modem.

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
