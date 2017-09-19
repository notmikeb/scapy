#python3
import time

t1 = time.time()
import scapy
import scapy.arch
import scapy.layers
import scapy.layers.bluetooth
import scapy.layers.usbhci
t2 = time.time()
print("take {} seconds".format( int(t2-t1) ))

from scapy.layers.usbhci import *
devs = find_bt_adapters()
print("bluetooth adapters len:{}".format(len(devs)))
for dev in devs:
    print("bluetooth '{}'".format(repr(dev)))
