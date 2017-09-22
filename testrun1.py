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
  if b != None:
    print(b.summary())
    print( repr(b) )
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

p1.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Enable(
            enable=False, filter_dups=True))
b = p1.recv()
showevent(b)

# enable
p1.send(HCI_Hdr()/HCI_Command_Hdr()/ HCI_Cmd_Write_Scan_Enable(scan_enable=1))
b = p1.recv()
showevent(b)

p1.send(HCI_Hdr()/HCI_Command_Hdr()/ HCI_Cmd_Write_Inquiry_Mode())
b = p1.recv()
showevent(b)


time.sleep(1)
#p1.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Create_Connection(bd_addr="80:a5:89:12:fd:92"))
#b = p1.recv()
#showevent(b)

#p1.sendcmd(HCI_Cmd_Write_Page_Timeout() )
#b = p1.recv()
#showevent(b)

handle = 0
bd_addr="F4:31:C3:53:D0:AB"
bd_addr="20:54:76:99:4d:2d" # sony
bd_addr="00:18:60:f9:50:7a" # acer
p1.sendcmd(HCI_Cmd_Create_Connection(bd_addr = bd_addr))
b = p1.recv()
showevent(b)
try:
   while b != None:
       if hasattr(b, "handle"):
           handle = b.handle
           break
       else:
           b = p1.recv()
           showevent(b)
except:
   pass

if handle != 0:   
    print( "handle is {}".format(handle) )
    # HCI_Cmd_Authentication_Requested
    p1.sendcmd(HCI_Cmd_Authentication_Requested(handle = handle) )
    # <- Event: Link Key Request 0x1b
    b = p1.recv()
    showevent(b)

    # HCI_Cmd_Link_Key_Request_Negative_Reply
    p1.sendcmd(HCI_Cmd_Link_Key_Request_Negative_Reply(bd_addr = bd_addr) )
    # <- Event: HCI IO Capability Request
    b = p1.recv()
    showevent(b)

    # HCI_Cmd_IO_Capability_Request_Reply
    p1.sendcmd(HCI_Cmd_IO_Capability_Request_Reply(bd_addr = bd_addr, io_capability=1) )
    # <- Event: HCI User Confirmation Request
    b = p1.recv()
    showevent(b)

    # HCI_Cmd_User_Confirmation_Request_Reply
    p1.sendcmd(HCI_Cmd_User_Confirmation_Request_Reply(bd_addr = bd_addr) )
    # <- Event: HCI Simple Pairing Complete
    b = p1.recv()
    showevent(b)
    
    p1.sendcmd( HCI_Cmd_PIN_Code_Request_Reply(bd_addr = bd_addr, pin_code_length=4, pin_code = '0000') )
    b = p1.recv();b

    # inquiry
    #p1.send(HCI_Hdr()/HCI_Command_Hdr()/ HCI_Cmd_Inquiry())
    #b = p1.recv()
    #showevent(b)

# iphone "F4:31:C3:53:D0:AB"
# modify scapy.layers.bluetooth
import imp
def btreload():
  imp.reload(scapy.layers.bluetooth)
  print("please run 'from scapy.layers.bluetooth import *   '")
from scapy.layers.bluetooth import *
print("btreload() to reload bluetooth module")
btreload()
