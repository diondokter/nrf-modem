# Changelog

## Unreleased

- Improve handling of XSYSTEMMODE command
- *Breaking:* Updated to nrfxlib-sys 2.9.1
- Add helper to get tracing data out of the nrfxlib modem driver. Feature: `modem-trace`
- Add logging output for the nrfxlib modem driver. Feature: `modem-log`

## 0.6.1 (2024-12-27)

- Made some code more open to different bindgen generation that apparently can happen
- Fixed async dns where it wasn't properly updated to `core::net`

## 0.6.0 (2024-12-06)

- Added TLS support (https://github.com/diondokter/nrf-modem/pull/26)
- Fixed small socket addres length bug (https://github.com/diondokter/nrf-modem/pull/28)
- Added opt-in non-blocking async DNS resolver (https://github.com/diondokter/nrf-modem/pull/27)
  - Exposed as a cargo feature
- Moved to `core::net` instead of using `no-std-net`
- Move MSRV to 1.82 for the raw references and c strings
- Added embedded-io-async traits to Tcp stream types and Tls stream types

## 0.5.1 (2024-08-28)

- Fix documentation generation for docs.rs

## 0.5.0 (2024-08-09)

- *Breaking:* Updated to nrfxlib-sys 2.7.1
- *Breaking:* Added support for nrf9151. You must now select a feature flag for your chip

## 0.4.3 (2024-06-18)

- Added extra check that prevents initializing the modem multiple times
- Updated embassy-sync
- Stopped using `cortex_m::interrupt::free` in favour of `critical_section`

## 0.4.2 (2024-06-17)

- Fixed a memory ownership issue in `nrf_modem_init`. The `nrf_modem_init_params` pointer given to the init must
  have a static lifetime. This has been a stack variable since forever, including in the original `nrfxlib` rust crate.  
  Originally this seems to have not been required, but this changed +-4 years ago
  without documentation update from Nordic.

## 0.4.1 (2023-09-22)

- Added a new modem init function where the memory layout can be manually specified
- Sockets now use the built-in nrfxlib callbacks instead of waking at every IPC interrupt

## 0.4.0 (2023-09-07)

- Update nrfxlib-sys to 2.4.2, removing the need for the `EGU1` interrupt

## 0.3.4 (2023-09-05)

- Fixed issue where LTE link waiting couldn't be cancelled

## 0.3.3 (2023-08-07)

- Fixed issue where a split socket polled on two different tasks would not properly wake up one of the two tasks if both were waiting on the same socket. (#14)
- Fixed the low-level semaphore implementation to make it wait the appropriate time (#16)

## 0.3.2 (2023-04-24)

- Fixed at notification issue where a too small string buffer would panic. Now the notification is truncated to the size of the string.

## 0.3.1  (2023-04-18)

- Updated embassy-sync to 0.2.0 (to fix new nightly compilation issue)
- Updated num-enum to 0.6

## 0.3.0 (2023-04-03)

- *Breaking*: LteLink is no longer Clone.
- *Breaking*: There is no longer a race going on for turning the modem on and off.
  This does mean that dropping LteLink or GNSS can lead to the modem not being turned off when it happens at the same time as another drop or deactivate.
  (There's a mutex that if it cannot be unlocked will lead to this behaviour)
- *Breaking*: Splitting sockets is now async and fallible
- GNSS now has an async deactivate function that you can call in place of drop
- When both the LTE and GPS are turned off the `CFUN=0` at command is used to turn off the modem fully.
  This also saves the modem settings to its NVM.0
- Added an error recovery method. See the readme for more information.

## 0.2.3 (2023-03-13)

- `NRF_ENOTCONN` socket errors are now reported as Disconnected instead of as unknown nrf errors

## 0.2.2 (2023-03-12)

- Sockets are now waken up from IPC interrupts instead of APP interrupts. This makes it so the wakers are only woken ~62% of the times in the previous version
- Sockets now have a fixed amount of wakers, which makes some perf better and uses less sketchy unsafe code. This replaces the previously used intrusive linked list.
- Added some disconnect detection on sockets. This is one of the new errors a socket can return. Previously a receive call would just return 0 bytes being read.

## 0.2.1 (2023-02-27)

- Stop gnss when GnssStream is dropped (https://github.com/diondokter/nrf-modem/pull/11)

## 0.2.0 (2023-01-19)

- *Breaking*: The error enum is now non-exhaustive
- UICC is now disabled when the LTE is disabled to save on power.
- Added the ability to send SMS messages (https://github.com/diondokter/nrf-modem/pull/9)

## 0.1.1 (2022-12-26)

- Fix: Made GnssUsecase fields public (https://github.com/diondokter/nrf-modem/pull/8)

## 0.1.0 (2022-12-25)

Initial release with support for:
- AT commands
- AT notifications
- DNS
- TCP
- UDP
- DTLS
