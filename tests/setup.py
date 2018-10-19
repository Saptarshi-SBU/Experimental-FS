#!/usr/bin/env python
#
# Setup.py will initiliaze luci kernel module with necessary debug settings
#

import abc
import argparse
import subprocess

from time import sleep
from sysctl import Sysctl
from psutil import virtual_memory, disk_io_counters

def procFsSettings(enable):
    ''' Set procfs '''

    obj = Sysctl.factory('proc')
    value = int(enable)
    obj.write('sys.kernel.panic_on_oops', value)
    obj.write('sys.kernel.softlockup_panic', value)
    obj.printSettings()

def sysFsSettings(enable):
    ''' Set sysfs '''

    obj = Sysctl.factory('sys')
    value = int(enable)
    obj.write('kernel.debug.luci.log', value)
    obj.printSettings()

def RunCommand(cmd, strict = True):
    ''' Executes an OS command '''

    print('Executing cmd :', cmd)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, shell=True)
    out, err = process.communicate()
    if process.returncode is not 0:
        raise Exception("error executing " + cmd + ". " + out)
    else:
        return 0

class DevManager(object):
    '''
        Product for managing all devops
    '''
    def __init__(self, dev):
        self.device = dev
        self.SetupAction = None
        self.CleanupAction = None
        self.MonitorAction = None

    def RunSetup(self):
        print ('Running Setup...')
        self.SetupAction(self.device)

    def RunCleanup(self):
        print ('Running cleanup...')
        self.CleanupAction()

    def RunMonitor(self):
        print ('Running monitor...')
        while True:
            self.MonitorAction()
            sleep(1)

    def print_device(self):
        print ('managing device : {dev}'.format(dev=self.device))

class Director:
    '''
        Controls the construction process
    '''

    def setBuilder(self, builder):
        self._builder = builder

    def createDevManager(self, dev):
        devMgr = DevManager(dev)
        devMgr.SetupAction = self._builder.getSetupMethod()
        devMgr.CleanupAction = self._builder.getCleanupMethod()
        devMgr.MonitorAction = self._builder.getMonitorMethod()
        return devMgr

class Builder(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def getSetupMethod(self):
        pass

    @abc.abstractmethod
    def getCleanupMethod(self):
        pass

    @abc.abstractmethod
    def getMonitorMethod(self):
        pass

class LUCIBuilder(Builder):
    '''
        concrete builder implementation
    '''
    @staticmethod
    def setupModule(dev):
        print ('Setting up Module')
        cmd = 'mkfs.ext2 -b {bsize} {dev}'.format (bsize='4096', dev=dev)
        RunCommand(cmd)
        cmd = 'insmod {module}'.format(module='fs/luci.ko')
        RunCommand(cmd)
        cmd = 'mount -t {fs} {dev} {point}'. \
            format(fs='luci', dev=dev, point='/mnt')
        RunCommand(cmd)
        procFsSettings(True)
        #sysFsSettings(False)

    @staticmethod
    def cleanupModule():
        cmd = 'umount /mnt/'
        RunCommand(cmd)
        cmd = 'rmmod luci'
        RunCommand(cmd)

    @staticmethod
    def memStats():
        ''' print counters '''
        print ('Mem Stats :')
        print(virtual_memory())

    @staticmethod
    def IOStats():
        ''' print counters '''
        print ("****luci internal stats***")
        with open('/sys/kernel/debug/luci/nrbatches') as f:
            nr_batches = int(f.read())
        with open('/sys/kernel/debug/luci/nrwrites') as f:
            nr_writes = int(f.read())
        with open('/sys/kernel/debug/luci/rlsebsy') as f:
            nr_rlsebsy = int(f.read())
        with open('/sys/kernel/debug/luci/avg_balloc_lat') as f:
            balloc_latency = int(f.read())
        with open('/sys/kernel/debug/luci/avg_deflate_lat') as f:
            deflate_latency = int(f.read())
        with open('/sys/kernel/debug/luci/avg_inflate_lat') as f:
            inflate_latency = int(f.read())
        with open('/sys/kernel/debug/luci/avg_io_lat') as f:
            io_latency = int(f.read())
        print("nr_batches: {} nr_writes: {} nr_rlsebsy: {} "\
              "balloc latency: {} ns deflate latency: {} ns "
              "zlib latency: {} ns io latency {} ns".format \
              (str(nr_batches), str(nr_writes), str(nr_rlsebsy), \
              str(balloc_latency), str(deflate_latency), \
              str(inflate_latency), str(io_latency)))

    def getSetupMethod(self):
        return LUCIBuilder.setupModule

    def getCleanupMethod(self):
        return LUCIBuilder.cleanupModule

    def getMonitorMethod(self):
       #return LUCIBuilder.memStats
        return LUCIBuilder.IOStats

def Run(args):
    luciBuilder = LUCIBuilder()
    director = Director()
    director.setBuilder(luciBuilder)
    manager = director.createDevManager(args.device)
    if args.action == 'setup':
        manager.RunSetup()
    elif args.action == 'cleanup':
        manager.RunCleanup()
    elif args.action == 'monitor':
        manager.RunMonitor()

parser = argparse.ArgumentParser()
parser.add_argument("--device", help="device name")
parser.add_argument("--action", type=str, \
                    help="set up or clean up module or monitor", \
                    choices=["setup", "cleanup", "monitor"])
args = parser.parse_args()
Run(args)
