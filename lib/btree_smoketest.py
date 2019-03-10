"""
 btree lib unit tests
 (C) 2019, Saptarshi Sen

 This module contains unit tests for btree
"""
import os
import csv
import time
import random
import unittest
import hashlib
import subprocess

#MAX_KEYS = 128

MAX_KEYS = 1000000

REPLAY_FILE = 'btree.replay'

def RunCommand(cmd, strict = True):
    ''' Executes an OS command '''

    #print('Executing cmd :', cmd)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, shell=True)
    out, err = process.communicate()
    if process.returncode is not 0:
        raise Exception("error executing " + cmd + ". " + out)
    else:
        return 0

class BTreeUnitTests(unittest.TestCase):

    def setUp(self):
        """
            Initialize
        """
        cmd = 'insmod lib/linux-btree.ko'
        #RunCommand(cmd)

    def tearDown(self):
        """
            TearDown
        """
        cmd = 'rmmod linux-btree'
        #RunCommand(cmd)

    @unittest.skip('skip test')
    def test_insert(self):
        """
            insert seq btree key
        """
        for key in range(0, MAX_KEYS):
            cmd = 'echo {} > {}'.format\
                        (key, '/sys/kernel/debug/btree/insert')
            rc = RunCommand(cmd)
            self.assertEqual(rc, 0)

    @unittest.skip('skip test')
    def test_delete(self):
        """
            delete btree key
        """
        for key in range(0, MAX_KEYS):
            cmd = 'echo {} > {}'.format\
                        (key, '/sys/kernel/debug/btree/delete')
            rc = RunCommand(cmd)
            self.assertEqual(rc, 0)

    #@unittest.skip('skip test')
    def test_randinsert(self):
        """
            insert/delete random btree key
        """
        keys = []
        csvfile = open(REPLAY_FILE, 'w')
        writer = csv.writer(csvfile, delimiter=' ')

        for i in range(0, MAX_KEYS):
            r = random.randint(0, 20000000)
            if r not in keys: #keys must be unique
                writer.writerow(['KEY', r])
                cmd = 'echo {} > {}'.format\
                        (r, '/sys/kernel/debug/btree/insert')
                rc = RunCommand(cmd)
                self.assertEqual(rc, 0)
                print("Key inserted :{}".format(i))
            #time.sleep(0.5)
        csvfile.close()
        
    @unittest.skip('skip test')
    def test_replayinsert(self):
        csvfile = open(REPLAY_FILE, 'r')
        reader = csv.reader(csvfile, delimiter=' ')
        for row in reader:
                key = row[1]
                cmd = 'echo {} > {}'.format\
                        (key, '/sys/kernel/debug/btree/insert')
                rc = RunCommand(cmd)
                self.assertEqual(rc, 0)
                #RunCommand('cat /sys/kernel/debug/btree/insert >> /tmp/dump')
                #time.sleep(1)
                print("Key inserted :{}".format(i))
        csvfile.close()

    @unittest.skip('skip test')
    def test_randdelete(self):
        csvfile = open(REPLAY_FILE, 'r')
        reader = csv.reader(csvfile, delimiter=' ')
        for row in reader:
                key = row[1]
                cmd = 'echo {} > {}'.format\
                        (key, '/sys/kernel/debug/btree/delete')
                rc = RunCommand(cmd)
                self.assertEqual(rc, 0)
                #RunCommand('cat /sys/kernel/debug/btree/delete >> /tmp/a')
                #time.sleep(0.5)
                print("Key deleted :{}".format(i))
        csvfile.close()

    @unittest.skip('skip test')
    def test_randinsertdelete(self):
        """
            insert/delete random btree key
        """
        keys = []
        csvfile = open(REPLAY_FILE, 'w')
        writer = csv.writer(csvfile, delimiter=' ')

        for i in range(0, MAX_KEYS):
            r = random.randint(0, 2000000)
            if r not in keys: #keys must be unique
                writer.writerow(['KEY', r])
                cmd = 'echo {} > {}'.format\
                        (r, '/sys/kernel/debug/btree/insert')
                rc = RunCommand(cmd)
                self.assertEqual(rc, 0)
                print("Key inserted :{}".format(i)) 
            #time.sleep(0.5)
        csvfile.close()

        csvfile = open(REPLAY_FILE, 'r')
        reader = csv.reader(csvfile, delimiter=' ')
        for row in reader:
                key = row[1]
                cmd = 'echo {} > {}'.format\
                        (key, '/sys/kernel/debug/btree/delete')
                rc = RunCommand(cmd)
                self.assertEqual(rc, 0)
                #RunCommand('cat /sys/kernel/debug/btree/delete >> /tmp/a')
                #time.sleep(0.5)
                print("Key deleted :{}".format(i))
        csvfile.close()

def TestDriver():
    suite = unittest.TestLoader().loadTestsFromTestCase(BTreeUnitTests)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == "__main__":
    TestDriver()
