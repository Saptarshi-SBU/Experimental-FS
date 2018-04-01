#! /usr/bin/python
# -*-python-*-
# -*-coding : utf-8 -*-
# 
# Copyright (C) Saptarshi Sen, 2018
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import os

class Sysctl(object):

    def __init__(self):
        self.sysctlRoot__ = None
        self.keys_ = dict()

    @staticmethod
    def factory(fsType):
        if fsType is 'proc':
            return ProcFs()
        else :
            return SysFs()

    def _addSettings(self, key, value): 
        self.keys_[key] = value

    def _getPath(self, key):    
        ''' get full path to param '''

        _key = key.replace('.', '/')
        _path = '{root}/{key}'.format(root=self.sysctlRoot_, key=_key)
        if os.path.exists(_path):
            return _path
        else:
            raise IOError("file not found %s" % _path)

    def write(self, key, value):
        ''' echo value to param '''

        _path = self._getPath(key)
        _file = file(_path, 'w')
        _bytesObj = bytes(value)
        _file.write(_bytesObj)
        _file.close()
        self._addSettings(key, _bytesObj)
        return

    def read(self, key):    
        ''' read value from param '''

        _path = self._getPath(key)
        _file = file(_path, 'r')
        _value = _file.readline().strip()
        _file.close()
        self._addSettings(key, _value)
        return _value

    def printSettings(self):
        ''' display sysctl cached parameters '''

        print ('settings :')
        for key, value in self.keys_.items():
            print ('{key} : {value}'.format(key=key, value=value))

class ProcFs(Sysctl):

    def __init__(self):
        super(ProcFs, self).__init__()
        self.sysctlRoot_ = '/proc'
        
class SysFs(Sysctl):

    def __init__(self):
        super(SysFs, self).__init__()
        self.sysctlRoot_ = '/sys'

def UnitTest():
    #Usage
    SET = 1
    obj = Sysctl.factory('sys')
    obj.write('kernel.debug.luci.debug', SET)
    value = obj.read('kernel.debug.luci.debug')
    assert int(value) == SET
    obj.printSettings()

    obj = Sysctl.factory('proc')
    obj.write('sys.kernel.panic_on_oops', SET)
    value = obj.read('sys.kernel.panic_on_oops')
    assert int(value) == SET
    obj.printSettings()
