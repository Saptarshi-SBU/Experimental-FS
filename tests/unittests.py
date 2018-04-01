"""
 Luci Unit Tests
 (C) 2017-2018, Saptarshi Sen

 This module contains unit tests for Luci
"""
import os
import time
import random
import unittest

from setup import RunCommand

TESTDIR='/mnt'
HOMEDIR='/home'
SAMPLEFILE='core-sig-11'

def GetSourceFile():
    return '{path}/{srcfile}'.format(path=HOMEDIR, srcfile=SAMPLEFILE)

def GetTestFile():
    return '{path}/test-{id}'.format(path=TESTDIR, id=random.randint(1, 100))

class LuciUnitTests(unittest.TestCase):

    def setUp(self):
        """
            Initialize
        """
        path = GetSourceFile()
        if not os.path.exists(path):
            raise Exception('Source file not found :%s' % path)

    def tearDown(self):
        """
            TearDown
        """
        pass

    def test_CopyFile(self):
        """
            Unit test for insert operations on arep tables
        """
        cmd = 'cp {srcpath} {destpath}'.format\
            (srcpath=GetSourceFile(), destpath=GetTestFile())
        rc = RunCommand(cmd)
        self.assertEqual(rc, 0)

    def test_DDFile(self):
        """
            Unit test for insert operations on arep tables
        """
        blockSize = '4k'
        total_blocks = 2000000
        cmd = 'dd if={srcpath} of={destpath} bs={bs} count={count}'.format\
            (srcpath=GetSourceFile(), destpath=GetTestFile(), bs=blockSize, \
             count=total_blocks)
        rc = RunCommand(cmd)
        self.assertEqual(rc, 0)

def TestDriver():
    suite = unittest.TestLoader().loadTestsFromTestCase(LuciUnitTests)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == "__main__":
    TestDriver()
