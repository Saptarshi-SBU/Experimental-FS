"""
 Luci Unit Tests
 (C) 2017-2018, Saptarshi Sen

 This module contains unit tests for Luci
"""
import os
import time
import random
import unittest
import hashlib
from shutil import copyfile

from setup import RunCommand

TESTDIR='/mnt'
#HOMEDIR='/home'
HOMEDIR="/run/media/ssen/NIKON D3200/DCIM/100D3200"
#SAMPLEFILE='core-sig-11'
SAMPLEFILE='DSC_0727.JPG'

def GetSourceFile():
    return '{path}/{srcfile}'.format(path=HOMEDIR, srcfile=SAMPLEFILE)

def GetTestFile():
    return '{path}/test-{id}'.format(path=TESTDIR, id=random.randint(1, 100))

def GetMD5(filename):
    m = hashlib.md5()
    with open(filename, 'r') as f:
        while True:
            chunk = f.read(4096)
            if chunk == '':
                break
            m.update(chunk)
    return m.hexdigest()

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

    @unittest.skip('skip test')
    def test_CopyFile(self):
        """
            Unit test for insert operations on arep tables
        """
        cmd = 'cp {srcpath} {destpath}'.format\
            (srcpath=GetSourceFile(), destpath=GetTestFile())
        rc = RunCommand(cmd)
        self.assertEqual(rc, 0)

    @unittest.skip('skip test')
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

    @unittest.skip('skip test')
    def test_CopyDir(self):
        """
          Unit test to copy directory
        """
        for root, dirs, files in os.walk(HOMEDIR):
            nr = len(files)
            for filename in files:
                srcFile = (os.path.join(root, filename))
                dstFile = (os.path.join(TESTDIR, filename))
                copyfile(srcFile, dstFile)
                nr = nr - 1
                print ("Pending files :" + str(nr))

    #@unittest.skip('skip test')
    def test_Validation(self):
        """
          Unit test to validate data by running md5 checksumming
        """
        for root, dirs, files in os.walk(HOMEDIR):
            for filename in files:
                srcFile = (os.path.join(root, filename))
                srcMd5 = GetMD5(srcFile)
                dstFile = (os.path.join(TESTDIR, filename))
                dstMd5 = GetMD5(dstFile)
                print ('{} {} : {}'.format(filename, srcMd5, dstMd5))
                self.assertEqual(srcMd5, dstMd5)

def TestDriver():
    suite = unittest.TestLoader().loadTestsFromTestCase(LuciUnitTests)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == "__main__":
    TestDriver()
