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
HOMEDIR="/run/media/ssen/NIKON D3200/DCIM/100D3200"
NRFILES=500

def GetLargeFile():
    files = os.listdir(HOMEDIR)
    return os.path.abspath(files[0])

def GetLuciFile():
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
        os.chdir(HOMEDIR)

    def tearDown(self):
        """
            TearDown
        """
        pass

    @unittest.skip('skip test')
    def test_CopyLargeFile(self):
        """
            Unit test to copy a large file
        """
        cmd = 'cp {srcpath} {destpath}'.format\
            (srcpath=GetLargeFile(), destpath=GetLuciFile())
        rc = RunCommand(cmd)
        self.assertEqual(rc, 0)

    @unittest.skip('skip test')
    def test_DDLargeFile(self):
        """
            Unit test to copy large file using dd
        """
        blockSize = '4k'
        total_blocks = 2000000
        cmd = 'dd if={srcpath} of={destpath} bs={bs} count={count}'.format\
            (srcpath=GetLargeFile(), destpath=GetLuciFile(), bs=blockSize, \
             count=total_blocks)
        rc = RunCommand(cmd)
        self.assertEqual(rc, 0)

    @unittest.skip('skip test')
    def test_CopyDir(self):
        """
          Unit test to copy directory
        """
        count = 0
        files = os.listdir(HOMEDIR)
        nr = min(NRFILES, len(files))
        for filename in files:
            srcFile = os.path.abspath(filename)
            dstFile = (os.path.join(TESTDIR, filename))
            copyfile(srcFile, dstFile)
            count = count + 1;
            print ('Copied [{}-{}] {}'.format(count, nr, dstFile))
            if count >= nr:
                break

    #@unittest.skip('skip test')
    def test_Validation(self):
        """
          Unit test to validate data by running md5 checksumming
        """
        count = 0
        files = os.listdir(HOMEDIR)
        nr = min(NRFILES, len(files))
        for filename in files:
            srcFile = os.path.abspath(filename)
            srcMd5 = GetMD5(srcFile)
            dstFile = (os.path.join(TESTDIR, filename))
            dstMd5 = GetMD5(dstFile)
            print ('[{} {}] {} {} : {}'.format(count, nr, filename, srcMd5, dstMd5))
            self.assertEqual(srcMd5, dstMd5)
            count = count + 1;
            if count >= nr:
                break

def TestDriver():
    suite = unittest.TestLoader().loadTestsFromTestCase(LuciUnitTests)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == "__main__":
    TestDriver()
