#
# Statistical compression estimation of a DataSet
#
# -Also includes a set of statistical heuristics to determine compressibility of a file
#
#Sample Test Results:
#
#fio --directory=/mnt/fio --direct=0 --rw=write --refill_buffers
#--buffer_compress_percentage=10 --ioengine=libaio --bs=8k --iodepth=16
#--numjobs=4 --size=512M --time_based --runtime=30 --group_reporting --name=fs -o /tmp/log
#
#python3 cest.py --file norvig.txt --ci 0.01 --cf 0.999
#Symbol-Set        31
#Core-Set          31(0.9999999999999998)
#ShannonEntropy    4.312032249296582
#L2Norm            1.099745595141958e-07
#CR                0.5956488100545467 (samples=38005 ci=0.01 cf=0.999)
#

import os
import zlib
import math
import random
import argparse
import pylogger
from itertools import combinations

cestlogger = None

useEstimate = True
                             
#z scores with confidence
z_table = { 0.70 : 1.04,
            0.75 : 1.15,
            0.80 : 1.28,
            0.85 : 1.44,
            0.90 : 1.645,
            0.92 : 1.75,
            0.95 : 1.96,
            0.96 : 2.05,
            0.98 : 2.33,
            0.99 : 2.58,
}

def z_statistic_sample_size(sigma, confidence_interval, confidence):
    '''
       confidence interval = (z * sigma/ sqrt (n))
    '''
    z = z_table[confidence]
    n = pow(((z * sigma) / confidence_interval), 2)
    return n

def test_z_table_sample_size(sigma, ci):
    '''
      given variance of a distribution and confidence interval.
      Compute confidence vs sample size

      1.0       70.0    0.1(+/-)        108
      1.0       75.0    0.1(+/-)        132
      1.0       80.0    0.1(+/-)        164
      1.0       85.0    0.1(+/-)        207
      1.0       90.0    0.1(+/-)        271
      1.0       92.0    0.1(+/-)        306
      1.0       95.0    0.1(+/-)        384
      1.0       96.0    0.1(+/-)        420
      1.0       98.0    0.1(+/-)        543
      1.0       99.0    0.1(+/-)        666

    '''
    global z_table

    if (ci > sigma):
        raise Exception("invalid interval")

    print ('Z_table :')
    for cf in sorted(z_table.keys()):
        n = round(z_statistic_sample_size(sigma, ci, cf))
        print ('{}\t{}\t{}(+/-)\t{}'.format(sigma, cf * 100, ci, n))

def Hoeffding_sample_size(ci, confidence):
    '''
        This is a lower bound on sample size for cases, where we
        do not have a given distribution.

        We require at least {{frac{log(2/alpha )}{2t^{2}}}}
        samples to acquire (1-alpha) confidence interval E[X] (+/-) t
    '''
    alpha = 1 - confidence
    n = (1 / (2 * pow (ci, 2))) * math.log(2/float(alpha))
    return n

def test_hoeffding_sample_size(ci):
    '''
        Hoefdding inequality :
        70.0            0.01(+/-)       9486
        75.0            0.01(+/-)       10397
        80.0            0.01(+/-)       11513
        85.0            0.01(+/-)       12951
        90.0            0.01(+/-)       14979
        92.0            0.01(+/-)       16094
        95.0            0.01(+/-)       18444
        96.0            0.01(+/-)       19560
        98.0            0.01(+/-)       23026
        99.0            0.01(+/-)       26492
    '''
    global z_table

    print ('Hoefdding inequality :')
    for cf in sorted(z_table.keys()):
        n = round(Hoeffding_sample_size(ci, cf))
        print ('{}\t\t{}(+/-)\t{}'.format(cf * 100, ci, n))

buckets = dict()

#initialize symbols
for i in range(255):
    key = i.to_bytes(1,  byteorder='little')
    buckets[key] = 0

def symbolset_size(buckets):
    count = 0
    for i in buckets:
            if buckets[i]:
                    count = count + 1
    return count

def coredataset_size(prob_list):
    coreset = []
    psum = 0
    i = -1
    prob_list = sorted(prob_list)
    for p in prob_list:
            i = i + 1
            if p == 0:
                    continue
            psum = psum + p
            coreset.append(i)
            if p > 0.9:
                    break
    return coreset, psum

def shanon_entropy(prob_list):
    summation = 0
    for p in prob_list:
            if p:
                summation += -p * math.log2(p)
                cestlogger.debug('{} : {}'.format(round(p, 5), math.log2(p)))
    return summation

def L2_norm(buckets, coreset):
    l2 = 0
    uxy = float (1) / (255 * 255)
    sampleSize = sum(buckets.values())
    pairs = [",".join(map(str, comb)) for comb in combinations(coreset, 2)]
    for p in pairs:
            p   = p.replace(',', ' ').split()
            x   = int(p[0]).to_bytes(1,  byteorder='little')
            y   = int(p[1]).to_bytes(1,  byteorder='little')
            px  = float(buckets[x])/sampleSize
            py  = float(buckets[y])/sampleSize
            pxy = px * py
            l2  = l2 + ((pxy - uxy) * (pxy - uxy))
    return l2

def get_next_offset(off, size, blockSize, rand):
    if rand:
        off = random.randrange(1, size - blockSize, blockSize)
    else:
        off = off + blockSize
        if off > size - blockSize:
            off = 0 #wrap

    return off

def compute_compression_ratio(filename, blockSize=32 * 1024):
    '''
        does an exhaustive scan
    '''
    global buckets

    off = 0
    bytes = 0
    compRatio_list = []
    size = os.path.getsize(filename)
    if size < blockSize:
            raise Exception("file size less than block Size")
    fp = open(filename, 'rb')
    while bytes < size/100:
        b = fp.read(1)
        if b in buckets:
            buckets[b]  = buckets[b] + 1
        bytes = bytes + 1
        if bytes % blockSize == 0:
            cestlogger.debug('{} bytes read'.format(bytes))

    fp.seek(off)
    while off <= size - blockSize:
        orgData   = fp.read(blockSize)
        compData  = zlib.compress(orgData, zlib.Z_BEST_COMPRESSION)
        compRatio = (float(len(orgData)) - float(len(compData)))/float(len(orgData))
        compRatio_list.append(compRatio)
        off = off + blockSize

    for i in sorted(buckets):
        pc = (buckets[i] * 100) / bytes
        cestlogger.debug('{}\t\t{}\t\t\t{}'.format(int.from_bytes(i, byteorder='little'), \
                buckets[i], round(pc, 8)))

    avg_compression_ratio = sum(compRatio_list)/(len(compRatio_list))
    print('Compression Ratio (exhaustive) {}'.format(avg_compression_ratio))
    fp.close()

def estimate_compression_ratio(filename, norandom=True, ci=0.02, cf=0.99, blockSize=32*1024):
    '''
        calculates estimate based on samples
    '''
    global buckets

    off = 0
    bytes = 0
    off_list = []
    compRatio_list = []
    probability_list = []
    size = os.path.getsize(filename)
    if size < blockSize:
            raise Exception("file size less than block Size")

    random.random()
    fp = open(filename, 'rb')
    samples = round(Hoeffding_sample_size(float(ci), float(cf)))
    while bytes < samples:
        off = get_next_offset(off, size, blockSize, not norandom)
        fp.seek(off)
        b = fp.read(1)
        if b in buckets:
            buckets[b] = buckets[b] + 1
        bytes = bytes + 1
        if bytes % (1024 * 1024) == 0:
            cestlogger.debug('{} bytes read'.format(bytes))
        off_list.append(off)
    
    for off in off_list:
        fp.seek(off)
        orgData   = fp.read(blockSize)
        compData  = zlib.compress(orgData, zlib.Z_BEST_COMPRESSION)
        compRatio = (float(len(orgData)) - float(len(compData)))/float(len(orgData))
        compRatio_list.append(compRatio)

    #debugging
    for i in sorted(buckets):
        bar = ''
        pc = (buckets[i] * 100) / bytes
        for k in range(0, round(math.ceil(pc))):
                bar = bar + '+'
        probability_list.append(buckets[i]/bytes)
        cestlogger.debug('{}\t\t{}\t\t\t{}\t{}'.format\
                (int.from_bytes(i, byteorder='little'), buckets[i], round(pc, 4), bar))

    symbolset             = symbolset_size(buckets)
    coreset, psum         = coredataset_size(probability_list)
    entropy               = shanon_entropy(probability_list)
    norm                  = L2_norm(buckets, coreset)
    avg_compression_ratio = sum(compRatio_list)/(len(compRatio_list))

    print ('Symbol-Set\t:{}\nCore-Set\t:{}({})\nByteEntropy\t:{}\n'
           'L2Norm\t\t:{}\nCR\t\t:{} (samples={} ci={} cf={})'. \
            format(symbolset, len(coreset), psum, entropy, norm,
                   avg_compression_ratio, samples, ci, cf))
    fp.close()

if __name__ == "__main__":
    cestlogger = pylogger.GetPyLogger(__name__, log_file='cest.log')
    parser = argparse.ArgumentParser()
    parser.add_argument('--file')
    parser.add_argument('--ci')
    parser.add_argument('--cf')
    args = parser.parse_args()
    #test_z_table_sample_size(sigma=1.0, ci=0.01)
    #test_hoeffding_sample_size(ci=0.01)
    if useEstimate:
        if args.ci:
                estimate_compression_ratio(args.file, norandom=True, ci=args.ci, cf=args.cf)
        else:
                estimate_compression_ratio(args.file, norandom=True)
    else:
        compute_compression_ratio(args.file, blockSize=32768)
