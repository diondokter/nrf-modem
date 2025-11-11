#!/usr/bin/env python3

import array
import sys
import re

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

print(f"Over all, {abs_min=} {abs_max=}")

import matplotlib.pyplot as plt
from matplotlib.widgets import Slider
import numpy as np

fig, ax = plt.subplots()
fig.subplots_adjust(bottom=0.2)

alldata = np.array(perchannel[1663])

# FIXME: scale better
heatmap = ax.imshow(alldata, vmin=-128, vmax=-50)

ax_slider = fig.add_axes([0.20, 0.1, 0.65, 0.03])
slider = Slider(
    ax_slider,
    label="Absolute Channel Number",
    valmin=min(perchannel.keys()),
    valmax=max(perchannel.keys()),
    valstep=1,
)


def update(val):
    if val in perchannel:
        heatmap.set_visible(True)
        heatmap.set_data(perchannel[val])
    else:
        heatmap.set_visible(False)
    fig.canvas.draw_idle()


slider.on_changed(update)

plt.show()
