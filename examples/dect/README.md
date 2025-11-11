nRF9151 DECT examples
=====================

RSSI demo
---------

Ensure you have the DECT network core firmware flashed, then run:

```console
$ cargo run
```

This measures the RSSI on various frequencies a few times, and then stops.
The output is automaticallys saved in `./default.out`.

(Data transfer and conversion is pretty inefficient, but good enough for a demo).

To visualize, you can run:

```console
$ python3 ./show.py default.out
```

Note that this does not follow the typical spectrogram conventions because it is a quick-and-dirty demo:
Lines represent continuous runs of RSSI measurement (240 data points spread over 10ms),
rows represent repetitions of that measurement after about 1s each.

The slider allows selecting different bands.
