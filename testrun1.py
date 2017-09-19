#python3
import time

t1 = time.time()
import scapy
import scapy.arch
import scapy.layers
import scapy.layers.bluetooth
import scapy.layers.usbhci
import scapy.layers.hci_event_mask as hci_event_mask

t2 = time.time()
print("take {} seconds".format( int(t2-t1) ))

from scapy.layers.usbhci import *
a = find_bt_adapters()

p1 = PyUSBBluetoothHCISocket(a[0])

def showevent(b):
    print(b.summary())
    try:
        print (hex(b.opcode))
    except:
        pass

p2 = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Reset()
p2.do_build()

p1.hci_reset()
b = p1.recv()
showevent(b)

# read address
p1.send(HCI_Hdr()/HCI_Command_Hdr()/ HCI_Cmd_Read_BD_Addr())
b = p1.recv()
showevent(b)

mask = hci_event_mask.all_enabled_str()
p1.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Set_Event_Mask(mask=mask))
b = p1.recv()
showevent(b)

p1.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Set_Event_Filter())
b = p1.recv()
showevent(b)

p1.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Host_Supported( supported=1, simultaneous=0))
b = p1.recv()
showevent(b)

p1.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Read_Buffer_Size())
b = p1.recv()
showevent(b)

scan_type = 1
interval_ms=10
window_ms=10
p1.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Parameters(
            type=scan_type, interval=int(interval_ms * 0.625),
            window= int(window_ms * 0.625)))
b = p1.recv()
showevent(b)

# LE scan enable
p1.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Enable(
            enable=True, filter_dups=True))
b = p1.recv()
showevent(b)

# wait for at least a report
b = p1.recv()
showevent(b)

p1.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Enable(
            enable=False, filter_dups=True))
b = p1.recv()
showevent(b)

# enable
p1.send(HCI_Hdr()/HCI_Command_Hdr()/ HCI_Write_Scan_Enable(enable=1))
b = p1.recv()
showevent(b)

p1.send(HCI_Hdr()/HCI_Command_Hdr()/ HCI_Write_Inquiry_Mode())
b = p1.recv()
showevent(b)

# inquiry
p1.send(HCI_Hdr()/HCI_Command_Hdr()/ HCI_Inquiry())
b = p1.recv()
showevent(b)

# iphone "F4:31:C3:53:D0:AB"
# modify scapy.layers.bluetooth
import imp
def btreload():
  imp.reload(scapy.layers.bluetooth)
  print("please run 'from scapy.layers.bluetooth import *   '")
from scapy.layers.bluetooth import *
print("btreload() to reload bluetooth module")
btreload()
