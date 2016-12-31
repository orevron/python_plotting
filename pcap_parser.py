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
#     END = '\033[0m'


class pcap_parser:
    id = 0
    _res = []
    _used_func = {}
    _values = {1: 'source', 2: 'protocol', 3: 'user'}

    def __init__(self, path):
        self._res = rdpcap(path).res

    def __getID__(self):
        self.id += 1
        return self.id

    def __export_pdf__(self, key):
        try:
            filename = key + str(self.__getID__()) + '.pdf'
            self._used_func[self._values[key]].savefig(filename, format='pdf')
            print('\033[92mSucceed! PDF created.\033[0m')
        except ValueError:
            print('\033[91mError occurred PDF not created.\033[0m')

    def plot_source_and_destination_count(self):
        if self._values[1] in self._used_func:
            self._used_func[self._values[1]].show()
        else:
            src = {}
            dst = {}
            for pkt in self._res:
                if hasattr(pkt.payload, 'src') and hasattr(pkt.payload, 'dst'):
                    src.update({pkt.payload.src: 0})
                    dst.update({pkt.payload.dst: 0})
            for pkt in self._res:
                if hasattr(pkt.payload, 'src') and hasattr(pkt.payload, 'dst'):
                    src[pkt.payload.src] += 1
                    dst[pkt.payload.dst] += 1
            sorted_src = []
            sorted_dst = []
            for k in sorted(src):
                sorted_src.append(src[k])
            for k in sorted(dst):
                sorted_dst.append(dst[k])
            p = plt
            p.bar(range(len(src)), sorted_src, align='center', label='Source', color='green')
            p.xticks(range(len(src)), sorted(src.keys()))
            p.bar(range(len(dst)), sorted_dst, align='center', label='Destination', color='red')
            p.xticks(range(len(dst)), sorted(dst.keys()))
            p.title('Sources and Destinations Count')
            p.legend()
            self._used_func.update({self._values[1]: p})
            print(self._used_func)
            p.show()
            # ans = 'z'
            # while ans != 'y' and ans != 'n':
            #     ans = input("\tExport PDF [y/n]? ")
            # if ans == 'y':
            #     self.__export_pdf__(self._values[1])

    def plot_protocol_count(self):
        if hasattr(self._used_func, self._values[2]):
            self._used_func[self._values[2]].show()
        else:
            protocol_map = {}
            for pkt in self._res:
                if hasattr(pkt.payload, 'proto'):
                    protocol_map.update({pkt.payload.payload.name: 0})
            for pkt in self._res:
                if hasattr(pkt.payload, 'proto'):
                    protocol_map[pkt.payload.payload.name] += 1
            sorted_keys = []
            sorted_vals = []
            for k in sorted(protocol_map):
                sorted_keys.append(k)
                sorted_vals.append(protocol_map[k])
            p = plt
            p.pie(sorted_vals, labels=sorted_keys, startangle=90, shadow=True, autopct='1.1f%%')
            p.title('Protocol Count')
            p.show()
            self._used_func.update({self._values[2]: p})

    def plot_source_users_count(self):
        if hasattr(self._used_func, self._values[3]):
            self._used_func[self._values[3]].show()
        else:
            users = {}
            for current in self._res:
                if hasattr(current, 'src'):
                    users.update({current.src: 0})
                    for pkt in self._res:
                        if hasattr(pkt, 'src') and (current.src == pkt.src):
                            users[current.src] += 1
            total = 0
            for k, v in users.items():
                total += v
            users.update({'Total': total})
            sorted_users = []
            for user in sorted(users):
                sorted_users.append(users[user])
            p = plt
            p.bar(range(len(users)), sorted_users, color='green', width=0.1)
            p.xticks(range(len(users)), sorted(users.keys()))
            p.title('Packets Per Source Count')
            p.show()
            self._used_func.update({self._values[3]: p})

    def clear(self):
        self._used_func = {}
        self._res = []


def main():
    while True:
        file_num = input('Enter file number or q to exit: ')
        if file_num == 'q': return 0
        print('\tLoading ' + file_num + '.cap file, please wait . . . ')
        parser = pcap_parser('/home/orevron/Downloads/pcap/' + file_num + '.cap')
        print('\t\033[92mDone!\033[0m')
        while True:
            print('Main Menu:')
            print('\t1. Source and destination count. \n\t2. Protocol count. \n\t3. Source user count. \n\tq to exit')
            choose = input('Enter Option: ')
            if choose == '1':
                parser.plot_source_and_destination_count()
            elif choose == '2':
                parser.plot_protocol_count()
            elif choose == '3':
                parser.plot_source_users_count()
            elif choose == 'q':
                return 0
            else:
                print('\t\033[91mWrong entry. Please try again, or [q] to exit\033[0m')
            end_message1 = '\t\033[94m[enter]\033[0m to continue, \033[92m[n]'
            end_message2 = '\033[0m to load new file \033[91m[q]\033[0m to exit: '
            file_num = input(end_message1 + end_message2)
            print('\n')
            if file_num == 'n':
                parser.clear()
                break
            elif file_num == 'q':
                return 0


main()
