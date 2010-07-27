#!/usr/bin/env python
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

class OfonoClass():

  props = {}

  def changeProp(self, name, value):
    self.props[name] = value
    self.PropertyChanged(name, value)


class Modem(OfonoClass):

  props = {}
  interface = None

  def changeProp(self, name, value):
    self.props[name] = value
    self.PropertyChanged(name, value)

  def __init__(self, iface):
#    DBusFBObject.__init__( self, conn=bus, object_path="/fso" )
    self.interface = iface
    self.props['Powered'] = False
    self.props['Online'] = False
    self.props['Features'] = []
    self.props['Interfaces'] = []

class DbusInterface(DBusFBObject):

  props = {}

  def changeProp(self, name, value):
    self.props[name] = value
    self.PropertyChanged(name, value)

  ###################################

  def __init__(self):
    DBusFBObject.__init__( self, conn=bus, object_path="/" )

  @dbus.service.method("org.ofono.Modem", "", "a{sv}")
  def GetProperties(self):
    return self.props

  @dbus.service.method("org.ofono.Modem", "sv", "")
  def SetProperty(self, name, value):
    if name=="Powered":
      self.iface.modem.SetPowered(value)
    self.changeProp(name, value)

  @dbus.service.signal("org.ofono.Modem", "sv")
  def PropertyChanged(self, name, value):
    return None

class Manager(OfonoClass, DBusFBObject):

  interface = None

  def __init__(self):
    DBusFBObject.__init__( self, conn=bus, object_path="/" )
    self.interface = DbusInterface()
    self.changeProp("Modems", self.interface)

  @dbus.service.method("org.ofono.Manager", "", "a{sv}")
  def GetProperties(self):
    return self.props

  @dbus.service.method("org.ofono.Manager", "", "a{sv}")
  def GetProperties(self):
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

