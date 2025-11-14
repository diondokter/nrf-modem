#!/usr/bin/env python3

import array
import sys
import re

import matplotlib.pyplot as plt
from matplotlib.widgets import Slider
import numpy as np

perchannel = {}
abs_min = 0
abs_max = -128

escapes = re.compile("\x1b\\[(.*?)m")

for line in open(sys.argv[1]):
    # Just tolerating, not expecting escapes, so that things also work when
    # cargo run is redirected and thus doesn't produce color output
    line = escapes.sub("", line)

    (pre, carrier, tail) = line.partition(" carrier ")
    if carrier:
        (carrier_num, _, _) = tail.partition("; ")
        carrier_num = int(carrier_num)
        continue

    (pre, info, hexdata) = line.partition("[INFO ] [")
    if info:
        (hexdata, _, _) = hexdata.partition("]")
        values = array.array("b", bytes.fromhex(hexdata.replace(", ", "")))

        abs_min = min(abs_min, min(values))
        abs_max = max(abs_max, max(values))

        perchannel.setdefault(carrier_num, []).append(values)

minband = min(perchannel.keys())
maxband = max(perchannel.keys())

bands = list(range(minband, maxband + 1))
percentiles = {q: [None for _ in bands] for q in [1, 5, 10, 25, 50, 75, 90, 95, 99]}

for (i, band) in enumerate(bands):
    for (q, qp) in percentiles.items():
        if band in perchannel:
            qp[i] = np.percentile(perchannel[band], q)

print(f"Over all, {abs_min=} {abs_max=}")

fig, (top, bottom) = plt.subplots(2)
fig.subplots_adjust(bottom=0.2)

alldata = np.array(perchannel[1663])

# FIXME: scale better
heatmap = top.imshow(alldata, vmin=abs_min, vmax=abs_max)

for (q, qd) in percentiles.items():
    bottom.plot(bands, qd, label=str(q))
vertical, = bottom.plot([minband, minband], [abs_min, abs_max], label="selected")
bottom.legend()

ax_slider = fig.add_axes([0.20, 0.1, 0.65, 0.03])
slider = Slider(
    ax_slider,
    label="Absolute Channel Number",
    valmin=minband,
    valmax=maxband,
    valstep=1,
)

def update(val):
    if val in perchannel:
        heatmap.set_visible(True)
        heatmap.set_data(perchannel[val])
    else:
        heatmap.set_visible(False)
    vertical.set(xdata=[val, val])
    fig.canvas.draw_idle()


slider.on_changed(update)

plt.show()
