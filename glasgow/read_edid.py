# Code from https://codeberg.org/ral/glasgow-script-i2c-edid/src/branch/master/read_edid.py
# Usage: glasgow script read_edid.py i2c-initiator --port A --pin-scl 0 --pin-sda 1 -V 3.3 --pulls output.bin -b 1
# KX: I have modified it to remove the 2 block limit. You will need to calculate how many blocks to request. 
#     For instance, a chip supporting '32,768 words × 8 bits' needs 256 blocks (256*128bytes = 32,768 bytes)

import argparse
import pathlib
import sys

# Parse arguments
parser = argparse.ArgumentParser(
            prog='read_edid.py',
            description='Read EDID data via an i2c bus.')

parser.add_argument('filename', type=pathlib.Path)
parser.add_argument('-b', '--blocks', type=int, default=1)

try:
    args = parser.parse_args(args.script_args)
except:
    # Power down the device
    await device.set_voltage("AB", 0)
    sys.exit()

# Prepare output buffer for data
blocksize = 128
datalen = args.blocks * blocksize
data = bytes()

# Read EDID data via i2c
addrs = await iface.scan()

if len(addrs) > 0:
    addr = list(addrs)[0]

    # Memory offset
    offset = 0x00
    # Specifiy offset to read from
    ack = await iface.write(addr, [offset])
    if ack is True:
        # Read data from chip
        data = await iface.read(addr, datalen, stop=True)

# Write data to file specified
args.filename.write_bytes(data)

# Power down the device
await device.set_voltage("AB", 0)
