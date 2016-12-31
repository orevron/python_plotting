import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import matplotlib.pyplot as plt


class pcap_parser:
    _res = []

    def __init__(self, path):
        self._res = rdpcap(path).res

    def plot_source_and_destination_count(self):
        src = {}
        dst = {}
        for pkt in self._res:
            if (hasattr(pkt.payload, 'src') and hasattr(pkt.payload, 'dst')):
                src.update({pkt.payload.src: 0})
                dst.update({pkt.payload.dst: 0})
        for pkt in self._res:
            if (hasattr(pkt.payload, 'src') and hasattr(pkt.payload, 'dst')):
                src[pkt.payload.src] += 1
                dst[pkt.payload.dst] += 1
        s = []
        d = []
        for k in sorted(src):
            s.append(src[k])
        for k in sorted(dst):
            d.append(dst[k])
        plt.bar(range(len(src)), s, align='center', label='Source', color='green')
        plt.xticks(range(len(src)), sorted(src.keys()))
        plt.bar(range(len(dst)), d, align='center', label='Destination', color='red')
        plt.xticks(range(len(dst)), sorted(dst.keys()))
        plt.title('Sources and Destinations Count')
        plt.legend()
        plt.show()

    def plot_protocol_count(self):
        map = {}
        for pkt in self._res:
            if (hasattr(pkt.payload, 'proto')):
                map.update({pkt.payload.payload.name: 0})
        for pkt in self._res:
            if (hasattr(pkt.payload, 'proto')):
                map[pkt.payload.payload.name] += 1
        s = []
        for k in sorted(map):
            s.append(map[k])
        plt.bar(range(len(map)), s, color='purple', width=0.1)
        plt.xticks(range(len(map)), sorted(map.keys()))
        plt.title('Protocol Count')
        plt.show()


def main():
    while (True):
        num = input('Enter file number or q to exit: ')
        if (num == 'q'): return 0
        print('\tLoading ' + num + '.cap file, please wait . . . ')
        parser = pcap_parser('/home/orevron/Downloads/pcap/' + num + '.cap')
        while (True):
            print('Main Menu:')
            print('\t1. Source and destination count. \n\t2. Protocol count. \n\tq to exit')
            choose = input('Enter Option: ')
            if (choose == '1'):
                parser.plot_source_and_destination_count()
            elif (choose == '2'):
                parser.plot_protocol_count()

            elif (choose == 'q'):
                return 0
            else:
                print('Wrong entry. Please try again, or \'q\' to exit')
            num = input('Press enter to continue,\n \'n\' to load new file\n \'q\' to exit: ')
            if (num == 'n'):
                break


main()
