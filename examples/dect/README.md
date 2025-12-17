nRF9151 DECT examples
=====================

For all demos, ensure that you have the DECT network core firmware flashed,
and that you understand your legislation's requirements for operating experimental radio equipment.

Steps to obtain and flash that firmware are currently documented
[in the hophop project](https://github.com/ariel-os/hophop/blob/main/doc/dect-firmware.md).

RSSI demo
---------

```console
$ cargo run --bin rssi_demo
```

This measures the RSSI on various frequencies a few times, and then stops.
The output is automaticallys saved in `./default.out`.

(Data transfer and conversion is pretty inefficient, but good enough for a demo).

To visualize, you can run:

```console
$ python3 ./show.py default.out
```

Note that this does not follow the typical spectrogram conventions because it is a plain and simple demo:
Lines represent continuous runs of RSSI measurement (240 data points spread over 10ms),
rows represent repetitions of that measurement after about 1s each.

The slider allows selecting different bands.

TX demo and RX demo
-------------------

These demos are best run in pairs on different devices,
and after having made sure that the demos' default channel (1665) is currently unused.

On one device, run:

```console
$ cargo run --bin rx
```

and on the other:

```console
$ cargo run --bin tx
```

Whenever you press button 1 on the transmitting device, you should see a beacon message show up on the receiving device.
