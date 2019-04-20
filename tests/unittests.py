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

NRRUNS=10
NRFILES=100
LARGEFILE='/dev/sda'
LARGEFILE_ORG="/home/ssen/Downloads/projects/linux-disk-Fedora26.qcow2"
LARGEFILE_TST="/mnt/linux-disk-Fedora26_test_02.qcow2"
HOMEDIR="/home/ssen/Downloads/pics_bakup"
TESTDIR="/mnt/pics_bakup"

def GetLargeFile():
    return LARGEFILE

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
        for i in range(0, NRRUNS):
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
        for i in range(0, NRRUNS):
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

    @unittest.skip('skip test')
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

    #@unittest.skip('skip test')
    def test_Validation_LargeFile(self):
        m1 = hashlib.md5()
        m2 = hashlib.md5()

        f1 = open(LARGEFILE_ORG, 'r')
        f2 = open(LARGEFILE_TST, 'r')

        count       = 0
        totalblocks = (os.path.getsize(LARGEFILE_ORG) + 4096 - 1) / 4096
        while True:
            chunk1 = f1.read(4096)
            if chunk1 == '':
                break
            m1.update(chunk1)
            md5sum1 = m1.hexdigest()

            chunk2 = f2.read(4096)
            if chunk2 == '':
                break
            m2.update(chunk2)
            md5sum2 = m2.hexdigest()
            count = count + 1
            print '[{}/{}] {} {}'.format(count, totalblocks, md5sum1, md5sum2)
            if md5sum1 != md5sum2:
                    print 'chunk 1 {}'.format(chunk1)
                    print 'chunk 2 {}'.format(chunk2)
            self.assertEqual(md5sum1, md5sum2)

def TestDriver():
    suite = unittest.TestLoader().loadTestsFromTestCase(LuciUnitTests)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == "__main__":
    TestDriver()
