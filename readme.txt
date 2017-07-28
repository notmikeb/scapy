20170728
use python3 and pyusb to create a usbhci object
and we could send data and read data from a instance of it
we could use usbhci to check the devices of bluetooth of pyusb


### fix need to 'import scapy.arch' before 'import scapy.layers.bluetooth'

pybluetooth for pebble
https://github.com/pebble/pybluetooth/blob/master/pybluetooth/pyusb_bt_sockets.py	

## relay on https://github.com/pebble/scapy

## use zadig to replace winusb to libusb


## from python2 chr to python3  byes
            #p = p[:2]+chr(l&0xff)+chr((l>>8)&0xff)+p[4:]
            p = p[:2]+bytes([(l&0xff),((l>>8)&0xff)])+p[4:]