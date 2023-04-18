# Changelog

## 0.3.1

- Updated embassy-sync to 0.2.0 (to fix new nightly compilation issue)
- Updated num-enum to 0.6

## 0.3.0

- *Breaking*: LteLink is no longer Clone.
- *Breaking*: There is no longer a race going on for turning the modem on and off.
  This does mean that dropping LteLink or GNSS can lead to the modem not being turned off when it happens at the same time as another drop or deactivate.
  (There's a mutex that if it cannot be unlocked will lead to this behaviour)
- *Breaking*: Splitting sockets is now async and fallible
- GNSS now has an async deactivate function that you can call in place of drop
- When both the LTE and GPS are turned off the `CFUN=0` at command is used to turn off the modem fully.
  This also saves the modem settings to its NVM.0
- Added an error recovery method. See the readme for more information.

## 0.2.3 (13-03-23)

- `NRF_ENOTCONN` socket errors are now reported as Disconnected instead of as unknown nrf errors

## 0.2.2 (12-03-23)

- Sockets are now waken up from IPC interrupts instead of APP interrupts. This makes it so the wakers are only woken ~62% of the times in the previous version
- Sockets now have a fixed amount of wakers, which makes some perf better and uses less sketchy unsafe code. This replaces the previously used intrusive linked list.
- Added some disconnect detection on sockets. This is one of the new errors a socket can return. Previously a receive call would just return 0 bytes being read.

## 0.2.1 (27-02-23)

- Stop gnss when GnssStream is dropped (https://github.com/diondokter/nrf-modem/pull/11)

## 0.2.0 (19-01-23)

- *Breaking*: The error enum is now non-exhaustive
- UICC is now disabled when the LTE is disabled to save on power.
- Added the ability to send SMS messages (https://github.com/diondokter/nrf-modem/pull/9)

## 0.1.1 (26-12-22)

- Fix: Made GnssUsecase fields public (https://github.com/diondokter/nrf-modem/pull/8)

## 0.1.0 (25-12-22)

Initial release with support for:
- AT commands
- AT notifications
- DNS
- TCP
- UDP
- DTLS
