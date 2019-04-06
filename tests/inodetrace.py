#
# Module to extract inode block map from captured ftraces
# trace-cmd record -e luci_get_block
#
# Usage : python <module_name> <tracefile>
#
import argparse

def ExtractKeyValue(trace, key):
        for string in trace:
                if key in string:
                        return string
        return None

def ParseTrace(trace_text):
        trace_text = trace_text.replace(':', ' ')
        trace = trace_text.split()

        inum  = ExtractKeyValue(trace, "inum")
        inum  = inum.replace("inum", ' ').replace('=', ' ').split()[0]

        off   = ExtractKeyValue(trace, "off")
        off   = off.replace("off", ' ').replace('=', ' ').replace(',', '\
                        ').split()[0]

        lba_0 = ExtractKeyValue(trace, "0-lba")
        lba_0 = lba_0.replace("0-lba", ' ').replace('=', ' ').replace('-', ' \
                        ').split()[0]

        lba_1 = ExtractKeyValue(trace, "1-lba")
        lba_1 = lba_1.replace("1-lba", ' ').replace('=', ' ').replace('-', ' \
                        ').split()[0]

        lba_2 = ExtractKeyValue(trace, "2-lba")
        lba_2 = lba_2.replace("2-lba", ' ').replace('=', ' ').replace('-', ' \
                        ').split()[0]

        lba_3 = ExtractKeyValue(trace, "3-lba")
        lba_3 = lba_3.replace("3-lba", ' ').replace('=', ' ').replace('-', ' \
                        ').split()[0]

        return inum, off, [lba_0, lba_1, lba_2, lba_3];

def TraceConvert(trace_file):
        inode_map = dict()
        with open(trace_file, 'r') as f:
                for trace_text in f.readlines():
                        inum, off, lba_list = ParseTrace(trace_text)
                        if inum not in inode_map:
                                inode_map[inum] = dict()
                        inode_map[inum][int(off)] = lba_list
        return inode_map

def PrintColums(inode_map, inum):
        for off in sorted(inode_map[inum]):
                print '{}\t{}'.format(off, '\t'.join(inode_map[inum][off]))

'''
You created a positional argument (no -- option in front of the name).
Positional arguments are always required. You can't use required=True for such
options, just drop the required. Drop the default too; a required argument can't
have a default value (it would never be used anyway):
'''
if __name__ ==  '__main__':
        parser = argparse.ArgumentParser()
        parser.add_argument('filename')
        parser.add_argument('--inum')
        args = parser.parse_args()
        inode_map = TraceConvert(args.filename)
        print 'file : {}, inum : {}'.format(args.filename, args.inum)
        print (inode_map.keys())
        if args.inum:
                PrintColums(inode_map, args.inum)
