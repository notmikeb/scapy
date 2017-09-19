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
a = find_bt_adapters()

p1 = PyUSBBluetoothHCISocket(a[0])

p2 = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Reset()
p2.do_build()

p1.hci_reset()
b = p1.recv()

# read address
p1.send(HCI_Hdr()/HCI_Command_Hdr()/ HCI_Cmd_Read_BD_Addr())
b = p1.recv()

# enable
p1.send(HCI_Hdr()/HCI_Command_Hdr()/ HCI_Write_Scan_Enable(enable=1))
b = p1.recv()

# inquiry
p1.send(HCI_Hdr()/HCI_Command_Hdr()/ HCI_Inquiry())
b = p1.recv()