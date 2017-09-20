import binascii
import errno
import logging

import sys

import usb.core
import usb.util

from scapy.layers.bluetooth import *
from scapy.supersocket import SuperSocket


# See BT 4.2 Spec, Vol 4, Part B, "USB Transport Layer".

# Used for "Single Function Primary Controller" devices:
USB_DEVICE_CLASS_WIRELESS_CONTROLLER = 0xFF
USB_DEVICE_SUB_CLASS_RF_CONTROLLER = 0xBB
USB_DEVICE_PROTOCOL_BLUETOOTH = 0xBB

# Used for composite devices:
USB_DEVICE_CLASS_MISCELLANEOUS = 0xEF
USB_DEVICE_SUB_CLASS_COMMON_CLASS = 0x02
USB_DEVICE_PROTOCOL_IAD = 0x01

USB_ENDPOINT_HCI_CMD = 0x00
USB_ENDPOINT_HCI_EVT = 0x81
USB_HCI_CMD_REQUEST_PARAMS = {
    "bmRequestType": 0x20, "bRequest": 0x00, "wValue": 0x00, "wIndex": 0x00
}

LOG = logging.getLogger("usbhci")

LOG.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
LOG.addHandler(ch)


class PyUSBBluetoothUserSocketException(Exception):
    pass


class PyUSBBluetoothL2CAPSocket(SuperSocket):
    desc = "Read/write Bluetooth L2CAP with pyUSB"

    def __init__(self, pyusb_dev):
        raise Exception("NYI")


class PyUSBBluetoothHCISocket(SuperSocket):
    desc = "Read/write Bluetooth HCI with pyUSB"

    def __init__(self, pyusb_dev):
        self.pyusb_dev = pyusb_dev

        # Drain any data that was already pending:
        while self.recv(timeout_secs=0.001):
            pass

    def __del__(self):
        # Always try to do a HCI Reset to stop any on-going
        # Bluetooth activity:
        try:
            self.hci_reset()
        except:
            pass
        # Release the device, so it can be claimed again immediately when
        # this object gets free'd.
        try:
            usb.util.dispose_resources(self.pyusb_dev)
        except:
            LOG.warn("Couldn't dispose %s" % self.pyusb_dev)
            pass

    def hci_reset(self):
        self.send(HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Reset())

    def recv(self, x=512, timeout_secs=10.0):
        # FIXME: Don't know how many bytes to expect here,
        # using 512 bytes -- will this fly if there's another event right
        # after it? Or is each event guaranteed to be put in a USB packet of
        # its own?
        try:
            data_array = self.pyusb_dev.read(
                USB_ENDPOINT_HCI_EVT, 512, int(timeout_secs * 1000.0))
        except usb.core.USBError as e:
            if e.errno == errno.ETIMEDOUT:
                return None
            else:
                raise e

        #data = ''.join([chr(c) for c in data_array])  # Ugh.. array return val
        #data = "\4" + data  # Prepend H4 'Event' packet indicator
        
        data = b'\x04' + bytes(data_array)
        scapy_packet = HCI_Hdr(data) # ex.recv bytes: b'0e0401030c00'
        LOG.debug("recv %s" % scapy_packet.lastlayer().summary())
        LOG.debug("recv bytes: {}".format( binascii.hexlify(data)))
        return scapy_packet

    def send(self, scapy_packet):
        #data = str(scapy_packet)
        data = bytes(scapy_packet) # python3 use bytes(), not str()
        LOG.debug("send %s" % scapy_packet.lastlayer().summary())
        LOG.debug("send bytes: '{}'".format(binascii.hexlify(data)) )
        data = data[1:]  # Cut off the H4 'Command' packet indicator (0x02)
        sent_len = self.pyusb_dev.ctrl_transfer(
            data_or_wLength=data, **USB_HCI_CMD_REQUEST_PARAMS)
        l = len(data)
        if sent_len != l:
            raise PyUSBBluetoothUserSocketException(
                "Send failure. Sent %u instead of %u bytes" % (sent_len, l))
    def sendcmd(self, scapy_packet):
        self.send(HCI_Hdr()/HCI_Command_Hdr()/scapy_packet)



class PyUSBBluetoothNoAdapterFoundException(Exception):
    pass


def find_first_bt_adapter_pyusb_device_or_raise():
    pyusb_devs = find_all_bt_adapters()
    if len(pyusb_devs) == 0:
        raise PyUSBBluetoothNoAdapterFoundException(
            "No Bluetooth adapters found!")

    def _is_usable_device(pyusb_dev):
        try:
            pyusb_dev.set_configuration()
            PyUSBBluetoothHCISocket(pyusb_dev).hci_reset()
            return True
        except:
            return False

    pyusb_devs = filter(_is_usable_device, pyusb_devs)

    if len(pyusb_devs) == 0:
        raise PyUSBBluetoothNoAdapterFoundException(
            "No Bluetooth *usable* adapters found!")

    if len(pyusb_devs) > 1:
        LOG.warn("More than 1 Bluetooth adapters found, "
                 "using the first one...")
    pyusb_dev = pyusb_devs[0]

    return pyusb_dev

def find_bt_adapters(idVendor = 0x0a12, idProduct = 0x01):
    #devs = set()

    devs = set(usb.core.find(find_all=True))

    # Unfortunately, usb.core.Device doesn't implement __eq__(),
    # see https://github.com/walac/pyusb/issues/147.
    # So filter out dupes here:
    devs_deduped = set(devs)
    for d in devs:
        for dd in devs:
            if d == dd:
                continue
            if d not in devs_deduped:
                continue
            if d.bus == dd.bus and d.address == dd.address:
                devs_deduped.remove(dd)
    for d in devs:
        if d.idVendor != idVendor:
            if d in devs_deduped:
                devs_deduped.remove(d)
        elif d.idProduct != idProduct:
            if d in devs_deduped:
                devs_deduped.remove(d)
    return list(devs_deduped)            

def has_bt_adapter():
    pyusb_dev = find_first_bt_adapter_pyusb_device()
    if pyusb_dev is None:
        return False
    return True


