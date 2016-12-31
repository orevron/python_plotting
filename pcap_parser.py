import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import matplotlib.pyplot as plt


# from sets import Set
# class bcolors:
#     HEADER = '\033[95m'
#     OKBLUE = '\033[94m'
#     OKGREEN = '\033[92m'
#     WARNING = '\033[93m'
#     FAIL = '\033[91m'
#     ENDC = '\033[0m'
#     BOLD = '\033[1m'
#     UNDERLINE = '\033[4m'


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
        sorted_src = []
        sorted_dst = []
        for k in sorted(src):
            sorted_src.append(src[k])
        for k in sorted(dst):
            sorted_dst.append(dst[k])
        plt.bar(range(len(src)), sorted_src, align='center', label='Source', color='green')
        plt.xticks(range(len(src)), sorted(src.keys()))
        plt.bar(range(len(dst)), sorted_dst, align='center', label='Destination', color='red')
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
        sorted_keys = []
        sorted_vals = []
        for k in sorted(map):
            sorted_keys.append(k)
            sorted_vals.append(map[k])
        plt.pie(sorted_vals, labels=sorted_keys, startangle=90, shadow=True, autopct='1.1f%%')
        plt.title('Protocol Count')
        plt.show()

    #       color = 'purple', width = 0.1
    #       sorted_map = []
    #         for k in sorted(map):
    #             sorted_map.append(map[k])
    #         plt.bar(range(len(map)), sorted_map, color='purple', width=0.1)
    #         plt.xticks(range(len(map)), sorted(map.keys()))
    #         plt.title('Protocol Count')
    #         plt.show()

    def plot_source_users_count(self):
        users = {}
        for current in self._res:
            if (hasattr(current, 'src')):
                users.update({current.src: 0})
                for pkt in self._res:
                    if (hasattr(pkt, 'src') and (current.src == pkt.src)):
                        users[current.src] += 1
        total = 0
        for k, v in users.items():
            total += v
        users.update({'Total': total})
        sorted_users = []
        for user in sorted(users):
            sorted_users.append(users[user])
        plt.bar(range(len(users)), sorted_users, color='green', width=0.1)
        plt.xticks(range(len(users)), sorted(users.keys()))
        plt.title('Packets Per Source Count')
        plt.show()


def main():
    while (True):
        file_num = input('Enter file number or q to exit: ')
        if (file_num == 'q'): return 0
        print('\tLoading ' + file_num + '.cap file, please wait . . . ')
        parser = pcap_parser('/home/orevron/Downloads/pcap/' + file_num + '.cap')
        print('\t\033[92mDone!\033[0m')
        while (True):
            print('Main Menu:')
            print('\t1. Source and destination count. \n\t2. Protocol count. \n\t3. Source user count. \n\tq to exit')
            choose = input('Enter Option: ')
            if (choose == '1'):
                parser.plot_source_and_destination_count()
            elif (choose == '2'):
                parser.plot_protocol_count()
            elif (choose == '3'):
                parser.plot_source_users_count()
            elif (choose == 'q'):
                return 0
            else:
                print('\t\033[91mWrong entry. Please try again, or [q] to exit\033[0m')
            file_num = input(
                '\t\033[94m[enter]\033[0m to continue, \033[92m[n]\033[0m to load new file \033[91m[q]\033[0m to exit: ')
            print('\n')
            if (file_num == 'n'):
                break
            elif (file_num == 'q'):
                return 0


main()
