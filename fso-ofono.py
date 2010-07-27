#!/usr/bin/env python
# FSO-Ofono wrapper
# Code is mess due to strange Ofono API - it's impossible to implement it in Python using typical way :(
# 2010 Sebastian Krzyszkowiak <dos@dosowisko.net>
# GPLv2+

import dbus, dbus.service
import gobject

from dbus.mainloop.glib import DBusGMainLoop
from dbus.service import FallbackObject as DBusFBObject

def error_handler(*args, **kwargs):
  print "Error happened."
  print args
  print kwargs
  print "End of error."

DBusGMainLoop(set_as_default=True)
mainloop = gobject.MainLoop()
bus = dbus.SystemBus()

class FSO:

  usage = dbus.Interface(bus.get_object('org.freesmartphone.ousaged', '/org/freesmartphone/Usage'), dbus_interface='org.freesmartphone.Usage')

  class GSM:
    obj = bus.get_object('org.freesmartphone.ogsmd', '/org/freesmartphone/GSM/Device')
    sim = dbus.Interface(obj, dbus_interface='org.freesmartphone.GSM.SIM')
    network = dbus.Interface(obj, dbus_interface='org.freesmartphone.GSM.Network')
    sms = dbus.Interface(obj, dbus_interface='org.freesmartphone.GSM.SMS')
    device = dbus.Interface(obj, dbus_interface='org.freesmartphone.GSM.Device')
    call = dbus.Interface(obj, dbus_interface='org.freesmartphone.GSM.Call')
    info = dbus.Interface(obj, dbus_interface='org.freesmartphone.Info')

class VoiceCall(DBusFBObject):

  props = {}
  manager = None
  id = None
  number = None
  state = None

  def changeProp(self, name, value):
    if self.props.get(name)==value:
      return

    if isinstance(value, list) and len(value)==0:
        value = dbus.Array([], signature="s")

    self.props[name] = value
    self.PropertyChanged(name, value)

  @dbus.service.signal("org.ofono.VoiceCall", "sv")
  def PropertyChanged(self, name, value):
    pass

  @dbus.service.method("org.ofono.VoiceCall", "", "a{sv}")
  def GetProperties(self):
    for value in self.props:
      if isinstance(self.props[value], list) and len(self.props[value])==0:
        self.props[value] = dbus.Array([], signature="s")
    return self.props

  @dbus.service.method("org.ofono.VoiceCall", "sv", "")
  def SetProperty(self, name, value):
    self.changeProp(name, value)

  @dbus.service.signal("org.ofono.VoiceCall", "s")
  def DisconnectReason(self, reason):
    # local, remote, network
    pass

  def HandleCallStatus(self, state, properties):
    state=state.lower()
    if state=="outgoing":
      state="dialing"
    elif state=="release":
      state="disconnected"
      #if "reason" in properties: TODO
      self.DisconnectReason("remote")
    self.state = state
    self.changeProp("State", state)
    if state=="disconnected":
      self.manager.CallMan_DelCall(self)
  
  def __init__(self, id, num, number, state, manager):
    DBusFBObject.__init__( self, conn=bus, object_path="/fso0/voicecall"+str(num) )
    self.manager = manager
    self.id = id
    self.number = number
    self.state = state
    self.changeProp("LineIdentification", number)
    self.changeProp("State", state)
    #self.changeProp("StartTime", time) # TODO

  @dbus.service.method("org.ofono.VoiceCall", "s", "")
  def Deflect(self, number):
    FSO.GSM.call.Transfer(number)

  @dbus.service.method("org.ofono.VoiceCall", "", "")
  def Hangup(self):
    FSO.GSM.call.Release(self.id)

  @dbus.service.method("org.ofono.VoiceCall", "", "")
  def Answer(self):
    FSO.GSM.call.Activate(self.id)

class CallForwarding(DBusFBObject):

  cf_props = {}

  def CF_changeProp(self, name, value):
    if self.cf_props.get(name)==value:
      return

    if isinstance(value, list) and len(value)==0:
        value = dbus.Array([], signature="s")

    self.cf_props[name] = value
    dbus.service.signal("org.ofono.CallForwarding", "sv")(self.PropertyChanged)(self, name, value)

  def PropertyChanged(self, self2, name, *args):
    pass

  @dbus.service.method("org.ofono.CallForwarding", "", "a{sv}")
  def GetProperties(self):
    for value in self.cf_props:
      if isinstance(self.cf_props[value], list) and len(self.cf_props[value])==0:
        self.cf_props[value] = dbus.Array([], signature="s")
    return self.cf_props

  @dbus.service.method("org.ofono.CallForwarding", "sv", "")
  def SetProperty(self, name, value):
    # TODO
    self.CF_changeProp(name, value)

  @dbus.service.method("org.ofono.CallForwarding", "s", "")
  def DisableAll(self, type):
    if type=="conditional":
      type="all conditional"
    elif type=="busy":
      type="mobile busy"
    FSO.GSM.network.DisableCallForwarding(type, "voice")

  def CF_init(self):
    ''' ofono: VoiceUnconditional, VoiceBusy, VoiceNoReply, VoiceNoReplyTimeout, VoiceNotReachable '''
    ''' FSO: "unconditional",
      "mobile busy",
      "no reply",
      "not reachable",
      "all",
      "all conditional". '''
    ''' class: voice+data+fax '''
    dic = FSO.GSM.network.GetCallForwarding("unconditional")
    if dic['voice'][0]:
      Radio_changeProp("VoiceUnconfitional")=dic['voice'][1]

    dic = FSO.GSM.network.GetCallForwarding("mobile busy")
    if dic['voice'][0]:
      Radio_changeProp("VoiceBusy")=dic['voice'][1]

    dic = FSO.GSM.network.GetCallForwarding("no reply")
    if dic['voice'][0]:
      Radio_changeProp("VoiceNoReply")=dic['voice'][1]
      Radio_changeProp("VoiceNoReplyTimeout")=dic['voice'][2]

    dic = FSO.GSM.network.GetCallForwarding("not reachable")
    if dic['voice'][0]:
      Radio_changeProp("VoiceNotReachable")=dic['voice'][1]


#FSO.GSM.network.GetCallForwarding

  #FSO.GSM.network.GetCallForwarding(type)
  #                EnableCallForwarding(type, class, number, timeout)
  #                DisableCallForwarding(type, class)
#    pass

class RadioSettings(DBusFBObject):

  radio_props = {}

  def Radio_changeProp(self, name, value):
    if self.radio_props.get(name)==value:
      return

    if isinstance(value, list) and len(value)==0:
        value = dbus.Array([], signature="s")

    self.radio_props[name] = value
    dbus.service.signal("org.ofono.RadioSettings", "sv")(self.PropertyChanged)(self, name, value)

  def PropertyChanged(self, self2, name, *args):
    pass

  @dbus.service.method("org.ofono.RadioSettings", "", "a{sv}")
  def GetProperties(self):
    for value in self.radio_props:
      if isinstance(self.radio_props[value], list) and len(self.radio_props[value])==0:
        self.radio_props[value] = dbus.Array([], signature="s")
    return self.radio_props

  @dbus.service.method("org.ofono.RadioSettings", "sv", "")
  def SetProperty(self, name, value):
    self.Radio_changeProp(name, value)

  def Radio_init(self):
    self.radio_props["TechnologyPreference"] = "any" # any, gsm, umts, lte

class SupplementaryServices(DBusFBObject):

  # SupplementaryServices is a fancy name for USSD :P

  ss_props = {}
  ss_inited = None

  def SS_changeProp(self, name, value):
    if self.ss_props.get(name)==value:
      return

    if isinstance(value, list) and len(value)==0:
        value = dbus.Array([], signature="s")

    self.ss_props[name] = value
    dbus.service.signal("org.ofono.SupplementaryServices", "sv")(self.PropertyChanged)(self, name, value)

  def PropertyChanged(self, self2, name, *args):
    pass

  @dbus.service.method("org.ofono.SupplementaryServices", "", "a{sv}")
  def GetProperties(self):
    for value in self.ss_props:
      if isinstance(self.ss_props[value], list) and len(self.ss_props[value])==0:
        self.ss_props[value] = dbus.Array([], signature="s")
    return self.ss_props

  @dbus.service.method("org.ofono.SupplementaryServices", "sv", "")
  def SetProperty(self, name, value):
    self.SS_changeProp(name, value)

  @dbus.service.method("org.ofono.SupplementaryServices", "s", "s")
  def Initiate(self, command):
    self.SS_changeProp("State", "active")
    FSO.GSM.network.SendUssdRequest(command)
    # TODO

  @dbus.service.method("org.ofono.SupplementaryServices", "s", "s")
  def Respond(self, command): 
    self.SS_changeProp("State", "active")
    FSO.GSM.network.SendUssdRequest(command)

  @dbus.service.method("org.ofono.SupplementaryServices", "", "")
  def Cancel(self): 
    pass

  def SS_HandleUSSD(self, type, msg):
    if type=="completed":
      self.NotificationReceived(msg)
    elif type=="useraction":
      self.RequestReceived(msg)
    elif type=="terminated":
      self.SS_changeProp('State','idle')
    else:
      print "FIXME: unhandled USSD type!"    

  @dbus.service.signal("org.ofono.SupplementaryServices", "s")
  def NotificationReceived(self, message):
    self.SS_changeProp('State','idle')

  @dbus.service.signal("org.ofono.SupplementaryServices", "s")
  def RequestReceived(self, message):
    self.SS_changeProp('State','user-response')

  def SS_init(self):
    self.ss_props['State']='idle'
    FSO.GSM.network.connect_to_signal("IncomingUssd", self.SS_HandleUSSD)

class VoiceCallManager(DBusFBObject):

  callman_props = {}
  num = 0

  def CallMan_changeProp(self, name, value):
    if self.callman_props.get(name)==value:
      return

    if isinstance(value, list) and len(value)==0:
        value = dbus.Array([], signature="s")

    self.callman_props[name] = value
    dbus.service.signal("org.ofono.VoiceCallManager", "sv")(self.PropertyChanged)(self, name, value)

  def PropertyChanged(self, self2, name, *args):
    pass

  @dbus.service.method("org.ofono.VoiceCallManager", "", "a{sv}")
  def GetProperties(self):
    for value in self.callman_props:
      if isinstance(self.callman_props[value], list) and len(self.callman_props[value])==0:
        self.callman_props[value] = dbus.Array([], signature="s")
    return self.callman_props

  @dbus.service.method("org.ofono.VoiceCallManager", "sv", "")
  def SetProperty(self, name, value):
    self.CallMan_changeProp(name, value)

  def CallMan_AddCall(self, call):
    self.callman_props["Calls"].append(call)
    dbus.service.signal("org.ofono.VoiceCallManager", "sv")(self.PropertyChanged)(self, "Calls", self.callman_props["Calls"])

  def CallMan_DelCall(self, call):
    self.callman_props["Calls"].remove(call)

    value = self.callman_props["Calls"]

    if isinstance(self.callman_props["Calls"], list) and len(self.callman_props["Calls"])==0:
        value = dbus.Array([], signature="s")

    dbus.service.signal("org.ofono.VoiceCallManager", "sv")(self.PropertyChanged)(self, "Calls", value)
    del call
 
  @dbus.service.method("org.ofono.VoiceCallManager", "ss", "o")
  def Dial(self, number, callerid):
    # TODO: callerid: "" or "default", "enabled", "disabled"
    id = FSO.GSM.call.Initiate(number, "voice")
    call = VoiceCall(id, self.num, number, "dialing", self)
    self.num = self.num + 1
    self.CallMan_AddCall(call)
    return call

  def CallMan_CallExists(self, id):
    for call in self.callman_props["Calls"]:
      if call.id==id:
        return True
    return False

  def CallMan_HandleCallStatus(self, id, status, properties):
    if status=="INCOMING" and not self.CallMan_CallExists(id):
      peer = properties.get("peer")
      if not peer:
        peer = ""
      call = VoiceCall(id, self.num, peer, "incoming", self)
      self.num = self.num + 1
      self.CallMan_AddCall(call)
    else:
      for call in self.callman_props["Calls"]:
        if call.id==id:
          call.HandleCallStatus(status, properties)

  @dbus.service.method("org.ofono.VoiceCallManager", "", "")
  def Transfer(self):
    FSO.GSM.call.Join()

  @dbus.service.method("org.ofono.VoiceCallManager", "", "")
  def SwapCalls(self):
    pass

  @dbus.service.method("org.ofono.VoiceCallManager", "", "")
  def ReleaseAndAnswer(self):
    pass

  @dbus.service.method("org.ofono.VoiceCallManager", "", "")
  def HoldAndAnswer(self):
    pass

  @dbus.service.method("org.ofono.VoiceCallManager", "", "")
  def HangupAll(self):
    FSO.GSM.call.ReleaseAll()

  @dbus.service.method("org.ofono.VoiceCallManager", "o", "ao")
  def PrivateChat(self, object):
    pass

  @dbus.service.method("org.ofono.VoiceCallManager", "", "ao")
  def CreateMultiparty(self):
    pass

  @dbus.service.method("org.ofono.VoiceCallManager", "", "")
  def HangupMultiparty(self):
    pass

  @dbus.service.method("org.ofono.VoiceCallManager", "s", "")
  def SendTones(self, tones):
    FSO.GSM.call.SendDtmf(tones)

  def CallMan_init(self):
    self.callman_props["Calls"]=[]
    self.callman_props["MultipartyCalls"]=[] 
    FSO.GSM.call.connect_to_signal("CallStatus", self.CallMan_HandleCallStatus)

class Phonebook(DBusFBObject):

  @dbus.service.method("org.ofono.Phonebook", "", "s")
  def Import(self):
    #FSO.GSM.sim.GetPhonebookInfo("contacts")
    return "not implemented yet" #TODO

class SmsManager(DBusFBObject):

  sms_props = {}

  def SMS_changeProp(self, name, value):
    if self.sms_props.get(name)==value:
      return

    if isinstance(value, list) and len(value)==0:
        value = dbus.Array([], signature="s")

    self.sms_props[name] = value
    dbus.service.signal("org.ofono.SmsManager", "sv")(self.PropertyChanged)(self, name, value)

  def PropertyChanged(self, self2, name, *args):
    pass

  @dbus.service.method("org.ofono.SmsManager", "", "a{sv}")
  def GetProperties(self):
    for value in self.sms_props:
      if isinstance(self.sms_props[value], list) and len(self.sms_props[value])==0:
        self.sms_props[value] = dbus.Array([], signature="s")
    return self.sms_props

  @dbus.service.method("org.ofono.SmsManager", "sv", "")
  def SetProperty(self, name, value):
    if name=="ServiceCenterAddress":
      FSO.GSM.sim.SetServiceCenterNumber(value)
    self.SMS_changeProp(name, value)

  @dbus.service.method("org.ofono.SmsManager", "ss", "")
  def SendMessage(self, to, text):
    FSO.GSM.sms.SendTextMessage(to, text, self.sms_props["UseDeliveryReports"])

  @dbus.service.signal("org.ofono.SmsManager", "sa{ss}")
  def ImmediateMessage(self, message, info):
    pass

  @dbus.service.signal("org.ofono.SmsManager", "sa{ss}")
  def IncomingMessage(self, message, info):
    pass

  def SMS_HandleIncoming(self, sender, timestamp, content):
    info = {'Sender': sender, 'SentTime':timestamp, 'LocalSentTime':timestamp} #TODO: check, if timestamp is ISO8601    
    self.IncomingMessage(content, info)
    #TODO: what about class 0?

  def SMS_init(self):
    self.sms_props["UseDeliveryReports"] = False
    self.sms_props["Bearer"] = "cs-preferred" #TODO: WTF?
    self.sms_props["ServiceCenterAddress"] = FSO.GSM.sim.GetServiceCenterNumber()
    FSO.GSM.sms.connect_to_signal("IncomingTextMessage", self.SMS_HandleIncoming)

class NetworkRegistration(DBusFBObject):

  network_props = {}

  def Network_changeProp(self, name, value):
    if self.network_props.get(name)==value:
      return

    if isinstance(value, list) and len(value)==0:
        value = dbus.Array([], signature="s")

    self.network_props[name] = value
    dbus.service.signal("org.ofono.NetworkRegistration", "sv")(self.PropertyChanged)(self, name, value)

  def PropertyChanged(self, self2, name, *args):
    pass
  
  @dbus.service.method("org.ofono.NetworkRegistration", "", "a{sv}")
  def GetProperties(self):
    for value in self.network_props:
      if isinstance(self.network_props[value], list) and len(self.network_props[value])==0:
        self.network_props[value] = dbus.Array([], signature="s")
    return self.network_props

  @dbus.service.method("org.ofono.NetworkRegistration", "sv", "")
  def SetProperty(self, name, value):
    self.Network_changeProp(name, value)

  def Register(self):
    FSO.GSM.network.Register()

  def Deregister(self):
    FSO.GSM.network.Unregister()

  def ProposeScan(self):
    pass # TODO

  def Network_HandleStatus(self, status):
    if "registration" in status:
      if status['registration']=="home":
        status['registration']="registered"
      elif status['registration']=="busy":
        status['registration']="searching"
      self.Network_changeProp("Status", status['registration'])

    if "mode" in status:
      if status['mode']=="automatic" or status['mode']=="manual;automatic":
        status['mode']="auto"
      elif status['mode']=="unregister":
        status['mode']="off"
      self.Network_changeProp("Mode", status['mode'])

    if "act" in status:
      if status['act']=="GSM" or status['act']=="Compact GSM":
        status['act']="gsm"
      elif status['act']=="UMTS":
        status['act']="umts"
      elif status['act']=="EDGE":
        status['act']="edge"
      elif status['act']=="HSDPA" or status['act']=="HSUPA" or status['act']=="HSDPA/HSUPA":
        status['act']="hspa"
      self.Network_changeProp("Technology", status['act'])

    if "lac" in status:
      self.Network_changeProp("LocationAreaCode", status['lac'])
    if "cid" in status:
      self.Network_changeProp("CellId", status['cid'])

    if "display" in status:
      self.Network_changeProp("Name", status['display'])
    elif "provider" in status:
      self.Network_changeProp("Name", status['provider'])

    if "strength" in status:
      self.Network_HandleStrength(status['strength'])

  def Network_HandleStrength(self, strength):
     self.Network_changeProp("Strength", strength)  

  def Network_init(self):
    FSO.GSM.network.GetStatus(reply_handler=self.Network_HandleStatus, error_handler=error_handler)
    FSO.GSM.network.connect_to_signal("Status", self.Network_HandleStatus)
    FSO.GSM.network.connect_to_signal("SignalStrength", self.Network_HandleStrength)

class SimManager(DBusFBObject):

  sim_props = {} 

  def Sim_changeProp(self, name, value):
    if self.sim_props.get(name)==value:
      return

    if isinstance(value, list) and len(value)==0:
        value = dbus.Array([], signature="s")

    self.sim_props[name] = value
    dbus.service.signal("org.ofono.SimManager", "sv")(self.PropertyChanged)(self, name, value)

  def PropertyChanged(self, self2, name, *args):
    pass

  @dbus.service.method("org.ofono.SimManager", "", "a{sv}")
  def GetProperties(self):
    for value in self.sim_props:
      if isinstance(self.sim_props[value], list) and len(self.sim_props[value])==0:
        self.sim_props[value] = dbus.Array([], signature="s")
    return self.sim_props

  @dbus.service.method("org.ofono.SimManager", "sv", "")
  def SetProperty(self, name, value):
    self.Sim_changeProp(name, value)

  @dbus.service.method("org.ofono.SimManager", "sss", "")
  def ChangePin(self, type, oldpin, newpin):
    if type=="pin":
      FSO.GSM.sim.ChangeAuthCode(oldpin, newpin)

  @dbus.service.method("org.ofono.SimManager", "ss", "")
  def EnterPin(self, type, pin):
    if type=="pin":
      FSO.GSM.sim.SendAuthCode(pin)

  @dbus.service.method("org.ofono.SimManager", "sss", "")
  def ResetPin(self, type, puk, newpin):
    if type=="pin" or type=="puk": # TODO: which one?
      FSO.GSM.sim.Unlock(puk, newpin)

  @dbus.service.method("org.ofono.SimManager", "ss", "")
  def LockPin(self, type, pin):
    if type=="pin":
      FSO.GSM.sim.SetAuthCodeRequired(True, pin)

  @dbus.service.method("org.ofono.SimManager", "ss", "")
  def UnlockPin(self, type, pin):
    if type=="pin":
      FSO.GSM.sim.SetAuthCodeRequired(False, pin)

  def Sim_HandleInfo(self, info):
    if "imsi" in info:
      self.Sim_changeProp("SubscriberIdentity", info["imsi"])
    if "phonebooks" in info:
      pb = info["phonebooks"].split(" ")
      if "own" in pb:
        num = FSO.GSM.sim.GetPhonebookInfo('own')
        nums = FSO.GSM.sim.RetrievePhonebook('own', 1, num[0])
        prop = []
        for num in nums:
          prop.append(num[2])
        self.Sim_changeProp("SubscriberNumbers", prop)
      if "fixed" in pb:
        num = FSO.GSM.sim.GetPhonebookInfo('fixed')
        nums = FSO.GSM.sim.RetrievePhonebook('fixed', 1, num[0])
        prop = {}
        for num in nums:
          prop[num[1]]=num[2]
        self.Sim_changeProp("ServiceNumbers", prop)

  def Sim_init(self, present):
    self.Sim_changeProp("Present", present)
    FSO.GSM.sim.GetSimInfo(reply_handler=self.Sim_HandleInfo, error_handler=error_handler)
    # TODO:
    # MobileCountryCode (MCC)
    # MobileNetworkCode (MNC)
    # LockedPins (as) 
    # CardIdentifier (ICCID)

class Modem(RadioSettings, CallForwarding, SupplementaryServices, VoiceCallManager, SmsManager, Phonebook, NetworkRegistration, SimManager, DBusFBObject):

  modem_props = {}
  sim_inited = None
  modem_inited = None

  def __init__(self):
    DBusFBObject.__init__( self, conn=bus, object_path="/fso0" )
    self.Modem_init()

  def Modem_changeProp(self, name, value):
    if self.modem_props.get(name)==value:
      return

    if isinstance(value, list) and len(value)==0:
        value = dbus.Array([], signature="s")

    self.modem_props[name] = value
    dbus.service.signal("org.ofono.Modem", "sv")(self.PropertyChanged)(self, name, value)

  def PropertyChanged(self, self2, name, *args):
    pass

  @dbus.service.method("org.ofono.Modem", "", "a{sv}")
  def GetProperties(self):
    for value in self.modem_props:
      if isinstance(self.modem_props[value], list) and len(self.modem_props[value])==0:
        self.modem_props[value] = dbus.Array([], signature="s")
    return self.modem_props

  @dbus.service.method("org.ofono.Modem", "sv", "")
  def SetProperty(self, name, value):
    if name=="Powered":
      self.Modem_SetPowered(value)
      if value:
        self.Modem_GoOnline(value)
        self.Modem_changeProp(name, value)
    if name=="Online":
      self.Modem_GoOnline(value)
    self.Modem_changeProp(name, value)

  def Modem_AddInterface(self, iface):
    if "Interfaces" in self.modem_props:
      self.modem_props["Interfaces"].append(iface)
    else:
      self.modem_props["Interfaces"] = [iface]
    dbus.service.signal("org.ofono.Modem", "sv")(self.PropertyChanged)(self, "Interfaces", self.modem_props["Interfaces"])

  def Modem_DelInterface(self, iface):
    if "Interfaces" in self.modem_props:
      if iface in self.modem_props["Interfaces"]:
        self.modem_props["Interfaces"].remove(iface)

        value = self.modem_props["Interfaces"]

        if isinstance(value, list) and len(value)==0:
          value = dbus.Array([], signature="s")

        dbus.service.signal("org.ofono.Modem", "sv")(self.PropertyChanged)(self, "Interfaces", value)


  def Modem_init(self):
    self.modem_props['Powered'] = False
    self.modem_props['Online'] = False
    self.modem_props['Interfaces'] = []
    self.sim_inited = False
    self.modem_inited = False
    # TODO: install signal handlers
    # so we can update ofono apps with GSM status changed by FSO apps
    if FSO.usage.GetResourceState:
      self.Modem_PoweredOn()
      self.Modem_changeProp("Powered", True)
      (fun, reg, pin) = FSO.GSM.device.GetFunctionality()
      if fun=="full":
        self.Modem_AddInterface("org.ofono.NetworkRegistration")
        self.Network_init()
        self.Modem_changeProp("Online", True)

  def Modem_ParseInfo(self, info):
    if "imei" in info:
      self.Modem_changeProp("Serial",info['imei'])
    if "model" in info:
      self.Modem_changeProp("Model",info['model'])
    if "manufacturer" in info:
      self.Modem_changeProp("Manufacturer",info['manufacturer'])
    if "revision" in info:
      self.Modem_changeProp("Revision",info['revision'])

  def Modem_HandleDeviceStatus(self, status):
    if not self.sim_inited and (status=="alive-sim-locked" or status=="alive-sim-ready" or status=="alive-sim-unlocked"):
      self.Modem_AddInterface("org.ofono.SimManager")
      self.Sim_init(True)
      self.sim_inited = True
      FSO.GSM.info.GetInfo(reply_handler=self.Modem_ParseInfo, error_handler=error_handler)
    if status=="alive-no-sim":
      self.sim_inited = True
      self.Modem_AddInterface("org.ofono.SimManager")
      self.Sim_init(False)

    if status=="alive-sim-locked":
      self.Sim_changeProp("PinRequired", "pin")
    if status=="alive-sim-ready" or status=="alive-sim-unlocked":
      self.Sim_changeProp("PinRequired", "none") #TODO: support PUK, use SIM.AuthStatus

    if not self.modem_inited and (status=="alive-sim-ready" or status=="alive-registered"): #TODO: add more
      if not self.sim_inited:
        self.Modem_AddInterface("org.ofono.SimManager")
        self.Sim_init(True)
        self.sim_inited = True
        FSO.GSM.info.GetInfo(reply_handler=self.Modem_ParseInfo, error_handler=error_handler)
      self.modem_inited = True
      self.Modem_AddInterface("org.ofono.Phonebook")
      self.Modem_AddInterface("org.ofono.SmsManager")
      self.Modem_AddInterface("org.ofono.VoiceCallManager")
      self.Modem_AddInterface("org.ofono.SupplementaryServices")
      self.Modem_AddInterface("org.ofono.CallForwarding")
      self.Modem_AddInterface("org.ofono.RadioSettings")
      self.SMS_init()
      self.CallMan_init()
      self.SS_init()
      self.CF_init()
      self.Radio_init()

  def Modem_GoOnline(self, value):
    if value:
      FSO.GSM.device.SetFunctionality("full", True, "")
      self.Modem_AddInterface("org.ofono.NetworkRegistration")
      self.Network_init()
    else:
      FSO.GSM.device.SetFunctionality("airplane", False, "") #FIXME: airplane or minimal here?
      self.Modem_DelInterface("org.ofono.NetworkRegistration")

  def Modem_PoweredOn(self):
    self.Modem_changeProp("Powered", True)
    FSO.GSM.device.GetDeviceStatus(reply_handler=self.Modem_HandleDeviceStatus, error_handler=error_handler)
    FSO.GSM.device.connect_to_signal("DeviceStatus", self.Modem_HandleDeviceStatus)

  def Modem_PoweredOff(self):
    self.sim_inited = False
    self.modem_inited = False
    self.Modem_changeProp("Powered", False)
    self.Modem_changeProp("Online", False)
    self.Modem_changeProp("Interfaces", [])

  def Modem_SetPowered(self, value):
    if value:
      FSO.usage.RequestResource("GSM", reply_handler=self.Modem_PoweredOn, error_handler=error_handler)
    else:
      FSO.usage.ReleaseResource("GSM", reply_handler=self.Modem_PoweredOff, error_handler=error_handler)


class Manager(DBusFBObject):

  props = {}

  def changeProp(self, name, value):
    if self.props.get(name)==value:
      return

    if isinstance(value, list) and len(value)==0:
        value = dbus.Array([], signature="s")

    self.props[name] = value
    self.PropertyChanged(name, value)

  modem = None

  def __init__(self):
    DBusFBObject.__init__( self, conn=bus, object_path="/" )
    self.modem = Modem()
    self.changeProp("Modems", [self.modem])

  @dbus.service.method("org.ofono.Manager", "", "a{sv}")
  def GetProperties(self):
    for value in self.props:
      if isinstance(self.props[value], list) and len(self.props[value])==0:
        self.props[value] = dbus.Array([], signature="s")
    return self.props

  @dbus.service.signal("org.ofono.Manager", "sv")
  def PropertyChanged(self, name, value):
    return None

try:
    busname = dbus.service.BusName( 'org.ofono', bus )
except dbus.DBusException:
    print( "Can't claim dbus bus name, check configuration!" )
    exit(1)
 
manager = Manager()
try:
  mainloop.run()
except KeyboardInterrupt:
  mainloop.quit()

