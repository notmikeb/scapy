#python3
import time

t1 = time.time()
import scapy
import scapy.arch
import scapy.layers
import scapy.layers.bluetooth
import scapy.layers.usbhci
import scapy.layers.hci_event_mask as hci_event_mask

import threading
import traceback

import tracelogging
log = tracelogging.logging.getLogger()
def myprint(*ls):
    log.info(*ls)

t2 = time.time()
myprint("take {} seconds".format( int(t2-t1) ))
from scapy.layers.usbhci import *
a = find_bt_adapters()


def gettid():
    return "["+ str(threading.get_ident())+"] "

class User(threading.Thread):
    def __init__(self, name, opcode = None, device = None):
        threading.Thread.__init__(self)
        self._name = name + " user"
        self._opcode = opcode
        self._device = device
        self.start()
    def run(self):
        # send a command and wait its' complete
        time.sleep(3)
        
        myprint(gettid() + self._name + "befoe sendCmd")
        r = self._device.sendCmd(self._opcode)
        if self._device.isOpen() and r != None:
            myprint(gettid() +self._name + "after sendCmd")
            r.wait_status()
            myprint(gettid() +self._name + "after status-ed")
            r.wait_complete()
            myprint(gettid() +self._name + "after complete-ed")
        else:
            myprint(gettid() + self._name + "no device.isOpen to send")
    def close(self):
        myprint("user close")

        
class HciCmdSession():
    def __init__(self, cmder = None, opcode = 0, packet = None):
        self.cmder = cmder
        self.event = threading.Condition()
        self._status = threading.Event()
        self._complete = threading.Event()
        self._state = 0 # 0 -> 1 -> 2
        self._opcode = opcode
        self._packet = packet
    def __del__(self):
        # release waiting
        myprint( gettid() + "hcicmdsession __del__ {}".format(hex(self._opcode)) )
        self.cancel()
    def cancel(self):
        self._state = 3
        self._status.set()
        self._complete.set()
    def wait_status(self):
        cv = self._status
        cv.wait()
        myprint(gettid() + " {} ".format(hex(self._opcode)) + "end of wait_status()")
        return self._rsp1        
    def wait_complete(self, check_func = None, timeout = 0):
        # Consume one item
        cv = self._complete
        cv.wait()
        myprint(gettid() + " {} ".format(hex(self._opcode)) + "end of wait_complete()")
        return self._rsp2
    def state(self):
        return self._state
    def build(self):
        return self._packet.build()
    def handle_send(self):
        cv = self.event
        cv.acquire()
        if self._state != 0:
            raise Exception("wrong state")
        self._state = 1
        cv.release()
    def handle_status(self, rsp = None):
        # Produce one item
        cv = self.event
        cv.acquire()
        self._status.set()
        if self._state != 1:
            myprint("stauts {}".format(self._state))
            raise Exception("wrong state")
        self._state = 2
        self._rsp1 = rsp
        myprint(gettid() + "{} is status-ed!".format( hex(self._opcode) ))
        cv.release()
    def handle_complete(self, rsp = None):
        cv = self.event
        cv.acquire()
        self._complete.set()
        if self._state == 0:
            raise Exception("wrong state")
        self._state = 3
        self._rsp2 = rsp
        myprint(gettid() + "{} is completed!".format(hex(self._opcode)))
        cv.release()

class HciDataSesson():
    def __init__(self, cmder, handle, packet):
        self._cmder = cmder
        self._handle = handle
        self._packet = packet
        
        self.state = 0
        self._event = threading.Condition()
        self._complete_event = threading.Event()
    def __del__(self):
        # release waiting
        myprint( gettid() + "HciDataSesson __del__ {}".format(hex(self._handle)) )
        self.cancel()
    def cancel(self):
        self._state = -1
        self._complete_event.set()
    def handle(self):
        return self._handle
    def len(self):
        return len(self._packet)
    def wait_complete(self, callback):
        self._complete.wait()
    def handle_complete(self, handle):
        with self.event:
            if self._state > 0:
                raise Exception("complete twice is abnormal!")
            if self._handle != handle:
                myprint(gettid() + "handle not match {} != {}".format(hex(self._handle), hex(handle))) 
            self._state = 3
        myprint(gettid() + "{} is completed!".format(self._opcode))
        
"""
Hci commands cannot send multiple times without wait-for status back (allow-command)
A session is about 
"""
class HciCmder(threading.Thread):
    def __init__(self, device, fakeRx = None):
        threading.Thread.__init__(self)
        self.device = device
        # only allow 1 cmd sent ! wait until release
        self.cmdLock = threading.Condition()
        self.runEvent = threading.Event()
        self._lock = threading.Condition()
        self.state = 0
        self.maxnoc = 1
        self.noc = 1
        self.aclslot = 4
        self.count = 0
        self.fakeRx = fakeRx
        self.sessions = []
        self.dataLock = threading.Lock()
        self.datalist = []
    def cancel(self):
        myprint(gettid() + "hcicmder cancel")
        for i in self.sessions:
            i.cancel()
        for i in self.datalist:
            i.cancel()
        self.sessions = []
        self.datalist = []
    def sendData(self, handle, packet):
        # put
        if self.state == 0:
            raise Exception("not open yet")
        r = None
        with self.dataLock:
            r = HciDataSesson(self, handle, packet)
            self.datalist.insert(0, r)
        return r
    def sendCmd(self, data):
        if self.state == 0:
            raise Exception("not open yet")    
        self.cmdLock.acquire()
        if not data.haslayer(HCI_Command_Hdr):
            data = HCI_Command_Hdr() / data
        if not data.haslayer(HCI_Hdr):
            data = HCI_Hdr() / data
        r = HciCmdSession(cmder = self, opcode = data.opcode, packet = data)
        self.sessions.insert(0, r)
        self.cmdLock.release()
        self.sendCmdNext()
        return r
    def sendCmdNext(self):
        self.dumpSessions()
        self.cmdLock.acquire()
        if self.noc > 0:
            for r in self.sessions:
                myprint("r.state {}".format(r.state()))
                if r.state() == 0:
                    myprint("send r {}".format( hex(r._opcode)))
                    self.device.tx(r._packet)
                    r.handle_send()
                    self.noc -= 1
                    break
        else:
            myprint("sendCmdNext {}".format(self.noc))
        self.cmdLock.release()
        
    def dumpDataList(self):
        myprint(gettid() +"=" * 10 + " noc " + str(self.noc))
        with self.dataLock:
            for i in range(len(self.datalist)):
                s1 = self.datalist[i]
                myprint(gettid() +"{}: handle:{} len:{}".format(i, hex(s1.handle()), s1.len() ))
        myprint(gettid() +"=" * 10)
    def dumpSessions(self):
        myprint(gettid() +"-" * 10+ " noc " + str(self.noc))
        self.cmdLock.acquire()
        for i in range(len(self.sessions)):
            s1 = self.sessions[i]
            myprint(gettid() +"{}: opcode:{} state:{}".format(i, hex(s1._opcode), s1.state()))
        self.cmdLock.release()
        myprint(gettid() +"-" * 10)
    def open(self):
        if self.state != 0:
            raise Exception("has open !")
        self.device.open()
        self.start()
        self._lock.acquire()
        self.state = 1
        self._lock.release()
    def isOpen(self):
        return self.state == 1
    def close(self):
        #todo: break the run loop
        self.cancel()
        self.stop()
        myprint(gettid() +"before join")
        self.join()
        myprint(gettid() +"after join")
        self.device.close()
    def stop(self):
        self.runEvent.set()
        self._lock.acquire()
        self.state = 0
        self._lock.release()
    def run(self):
        # read data from bus 
        myprint(gettid() +"HciCmder: run {}".format(self.device.name) )
        while not self.runEvent.is_set():
            # read data from bus until is is fail
            data = self.device.rx()
            if data == None:
                myprint(gettid() + "trigger None")
                self.runEvent.wait(3)
            else:
                myprint(gettid() + "trigger a previous hci-session")
                self.cmdLock.acquire()
                # self.sessions compare opcode 
                if hasattr(data, 'number') and data.number > 0:
                    if data.haslayer( HCI_Event_Command_Status):
                        self.noc += 1
                        myprint("cmd_status noc+1")
                    elif data.haslayer( HCI_Event_Command_Complete):
                        self.noc += 1
                        myprint("cmd_complete noc+1")
                    else:
                        self.noc += 1
                        myprint("cmd_unknown noc+1")
                    if self.noc > self.maxnoc:
                        self.noc = self.maxnoc
                        myprint("error! noc+1")
                if hasattr(data, 'opcode'):
                    for s in self.sessions:
                        p = s._packet
                        if hasattr(p, 'opcode') and data.opcode == p.opcode and s.state() == 1:
                            # match !
                            myprint("rsp is " + repr(data))
                            if data.haslayer( HCI_Event_Command_Status):
                                s.handle_status(data)
                                if data.status != 0:
                                    s.handle_complete(data)
                                    self.sessions.remove(s)
                            elif data.haslayer( HCI_Event_Command_Complete):
                                s.handle_complete(data)
                                self.sessions.remove(s)
                            else:
                                myprint("Not Found !!! {}".format(data) )
                                self.sessions.remove(data)
                self.cmdLock.release()
                myprint(gettid() +"trigger a previous hci-session - done")
                
            myprint(gettid() +"HciCmder: runEvent is not set yet. do recive " + str(self.count) )
            self.count += 1
            
            if self.noc > 0:
                self.sendCmdNext()
            #if self.fakeRx != None and random.Random().random() > 0.3: # 1/3 chance to fake a data
            #    self.device._fakeData("fake-" + str(self.count))
        myprint(gettid() +"HciCmder: run finished " + self.device.name )
        
class Device():
    def __init__(self, name = "unkown", config = None, adapter = None):
        self.name = name
        self.config = config
        self.bus = PyUSBBluetoothHCISocket(adapter)
    def __del__(self):
        myprint("Device __del__" + self.name)
    def rx(self):
        # // keep a loop to receive data form 
        data = self.bus.recv()
        return data
    def tx(self, data):
        self.bus.send(data)
        return None
    def open(self):
        return True
    def close(self):
        return False

a = find_bt_adapters()
        
d1 = Device("d1", adapter = a[0])
#d2 = Device("d2", bus = a[1])
cmder1 = HciCmder(d1)
cmder1.open()
myprint("open done")

#u1 = User('mike', 'm1', cmder1)

print (gettid() +"a1 to fake response")
print (gettid() +"b1 to send a command")
print (gettid() +"d to dump sessions")

mask = hci_event_mask.all_enabled_str()
scan_type = 1
interval_ms=10
window_ms=10

init_seq = [
HCI_Cmd_Set_Event_Mask(mask=mask),
HCI_Cmd_Set_Event_Filter(),
HCI_Cmd_LE_Host_Supported( supported=1, simultaneous=0),
HCI_Cmd_LE_Read_Buffer_Size(),
HCI_Cmd_LE_Set_Scan_Parameters(
            type=scan_type, interval=int(interval_ms * 0.625),
            window= int(window_ms * 0.625)),
HCI_Cmd_LE_Set_Scan_Enable(
            enable=True, filter_dups=True),
HCI_Cmd_LE_Set_Scan_Enable(
            enable=False, filter_dups=True),
HCI_Cmd_Write_Scan_Enable(scan_enable=1),
HCI_Cmd_Write_Inquiry_Mode(),
]

if True:
  try:
    myprint("print 'q' to exit ! ")
    i = ''
    while (i == None or len(i) == 0):
        i = input()
    while (i != "q"):
        if i[0] == 'a': # fake a hci-event
            d1.tx(HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Reset())
        if i[0] == 'b': # send a hcicmd
            cmder1.sendCmd(HCI_Cmd_Reset())
        if i[0] == 'd': # dump
            cmder1.dumpSessions()
        if i[0] == 'c': 
            myprint("start")
            cmder1.sendCmd(HCI_Cmd_Read_BD_Addr()).wait_complete()
            myprint("end")
        if i[0] == 's': 
            myprint("start")
            cmder1.sendCmd(HCI_Cmd_Reset()).wait_complete()
            myprint("end")
        if i[0] == 'i': 
            for e, p in enumerate(init_seq):
                myprint("start {}".format(e))
                cmder1.sendCmd(p).wait_complete()
                myprint("end")
                time.sleep(1)
        if i[0] == 'j': 
            for i, p in enumerate(init_seq):
                myprint("start {}".format(i))
                cmder1.sendCmd(p)
                myprint("end")
            
        myprint(gettid() +"print 'q' to exit ! ")
        myprint(gettid() +"input is: {}".format(i))
        time.sleep(1)
        i = None
        while (i == None or len(i) == 0):
            i = input()        
    myprint(gettid() +"exit interactive")
    cmder1.stop()
  except:
    e = sys.exc_info()
    myprint(e[0], e[1], e[2], traceback.print_exc(file=sys.stdout) )
cmder1.close()
cmder1 = None

#u1.close()    
