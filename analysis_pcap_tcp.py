# pcap library in python
import dpkt
import struct

# Global variables
import pandas as pd

SENDER = '172.24.22.15'  # '20.110.105.179'  # '172.31.240.217'
RECEIVER = '172.24.19.87'

pd.options.display.float_format = "{:,.6f}".format


class Packet:
    def __init__(self, data, timestamp):
        """ initialize the packet structure """

        self.data = data
        self.timestamp = timestamp
        self.source_ip_address = ''
        self.destination_ip_address = ''
        self.source_port = 0
        self.destination_port = 0
        self.length = 0
        self.protocol = ''
        self.sequence_number = 0
        self.acknowledge_number = 0
        self.window_size = 0
        self.mss = 0
        self.flag = ''
        self.additional = ''
        self.size = len(data)
        self.flag_syn = False  # to establish three way handshake
        self.flag_ack = False  # to acknowledge the successful receipt of a packet
        self.flag_fin = False  # to end the connection

    def parse(self):
        """ parses each packet information """

        self.set_source_ip_address()
        self.set_destination_ip_address()
        self.set_source_port()
        self.set_destination_port()
        self.set_length()
        self.set_protocol()

        # print("Protocol: ", self.protocol)

        if self.protocol == 'TCP':
            self.set_sequence_number()
            self.set_acknowledge_number()
            self.set_window_size()
            self.set_max_segment_size()
            self.set_flag()
            self.set_flags()

    def print_packet_information(self, ctr):

        # print("\n")
        print("------------------------------------------------------------------------------------------------")
        print("Packet "+ str(ctr) + ": ")
        print("------------------------------------------------------------------------------------------------")
        print("Timestamp: ", self.timestamp)
        print("Source Ip address: ", self.source_ip_address)
        print("Destination Ip address: ", self.destination_ip_address)
        print("Source Port: ", self.source_port)
        print("Destination Port: ", self.destination_port)
        print("Length: ", self.length)
        print("Protocol: ", self.protocol)

        if self.protocol == 'TCP':
            print("Sequence number: ", self.sequence_number)
            print("Acknowledge number: ", self.acknowledge_number)
            print("Window Size: ", self.window_size)
            print("Maximum Segment Size (MSS): ", self.mss)
            print("Flags: ", self.flag)
            print("SYN Flag: ", self.flag_syn)
            print("ACK Flag: ", self.flag_ack)
            print("FIN Flag: ", self.flag_fin)

    def unpack_info(self, start_index, last_index, _format=">B", _str=True):
        """ unpacks the binary data in the specified format """

        info = struct.unpack(_format, self.data[start_index:last_index])[0]
        if _str:
            info = str(info)
        return info

    def set_source_ip_address(self):
        """ parse and set source ip address """

        # IP address consists of four parts
        self.source_ip_address += self.unpack_info(26, 27)
        self.source_ip_address += "." + self.unpack_info(27, 28)
        self.source_ip_address += "." + self.unpack_info(28, 29)
        self.source_ip_address += "." + self.unpack_info(29, 30)

    def set_destination_ip_address(self):
        """ parse and set destination ip address """

        # IP address consists of four parts
        self.destination_ip_address += self.unpack_info(30, 31)
        self.destination_ip_address += "." + self.unpack_info(31, 32)
        self.destination_ip_address += "." + self.unpack_info(32, 33)
        self.destination_ip_address += "." + self.unpack_info(33, 34)

    def set_source_port(self):
        """ parse and set source port """

        # Format is Unsigned short integer - H
        self.source_port = int(self.unpack_info(34, 36, _format=">H"))

    def set_destination_port(self):
        """ parse and set source destination """

        # Format is Unsigned short integer - H
        self.destination_port = int(self.unpack_info(36, 38, _format=">H"))

    def set_length(self):
        """ parse and set length """

        self.length = self.size  # # int(self.unpack_info(38, 40, _format=">I"))

    def set_protocol(self):
        """ parse and set protocol """

        protocol_value = int(self.unpack_info(23, 24))

        if protocol_value == 17:
            self.protocol = 'UDP'
        elif protocol_value == 6:
            self.protocol = 'TCP'

    def set_sequence_number(self):
        """ parse and set sequence number """

        # Format is Unsigned integer - I
        self.sequence_number = self.unpack_info(38, 42, _format=">I")

    def set_acknowledge_number(self):
        """ parse and set acknowledge number """

        # Format is Unsigned integer - I
        self.acknowledge_number = self.unpack_info(42, 46, _format=">I")

    def set_window_size(self):
        """ parse and set window size """

        # Format is Unsigned short integer - H
        self.window_size = self.unpack_info(48, 50, _format=">H")

    def set_max_segment_size(self):
        """ parse and set window size """

        # Format is Unsigned short integer - H
        try:
            self.mss = self.unpack_info(56, 58, _format=">H")
        except:
            self.mss = 0

    def set_flag(self):
        """ parse and set flag """

        # Format is Unsigned integer - I
        self.flag = bin(self.unpack_info(46, 48, _format=">H", _str=False))[2:]

    def set_flags(self):
        """ identify if the packets are SYN, ACK and FIN """

        self.flag_ack = (int(self.flag) & 16 != 0)  # 11
        self.flag_syn = (int(self.flag) & 2 != 0)  # 14
        self.flag_fin = (int(self.flag) & 1 != 0)  # None


def process_one_packet(packet, timestamp):
    """ parse the information in one packet """

    pkt = Packet(packet, timestamp)
    pkt.parse()
    # pkt.print_packet_information()
    return pkt


def process_packets(packets, csv_file_name, src_ip, dst_ip, src_port, dst_port):
    """ parse the information of every packet in pcap data """

    total_number_of_packets = 0
    number_of_udp_packets = 0
    number_of_tcp_packets = 0
    number_of_flashes_detected = 0

    count = 1356

    packets_list = []

    for timestamp, packet_data in packets:
        pkt = process_one_packet(packet_data, timestamp)
        total_number_of_packets += 1
        if pkt.protocol == 'UDP':
            number_of_udp_packets += 1
        elif pkt.protocol == 'TCP':
            number_of_tcp_packets += 1

        # if count in [6573, 6702, 6635, 6743, 7737, 9173, 1297, 1351, 1406, 1459]:
        #     pkt.print_packet_information(count)

        flag = 0

        if pkt.source_ip_address == src_ip and pkt.destination_ip_address == dst_ip and \
           pkt.source_port == src_port and pkt.destination_port == dst_port:

            if 405 <= pkt.size <= 870 and pkt.protocol == 'UDP':  # [353, 318 (set6), ] # # pkt.size <= 870 and
                number_of_flashes_detected += 1
                flag = 1

            packet_info = [pkt.timestamp,
                           pkt.source_ip_address,
                           pkt.destination_ip_address,
                           pkt.source_port,
                           pkt.destination_port,
                           pkt.length,
                           pkt.protocol,
                           flag]

            packets_list.append(packet_info)

        count += 1

    columns_list = ['Timestamp', 'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort',
                    'Length', 'Protocol', 'isFlash']

    df = pd.DataFrame(packets_list, columns=columns_list)
    print(df)
    df.to_csv(csv_file_name)

    print("Total number of packets: ", total_number_of_packets)
    print("Number of UDP packets: ", number_of_udp_packets)
    print("Number of TCP packets: ", number_of_tcp_packets)
    print("Number of flashes detected: ", number_of_flashes_detected)

    return df


if __name__ == '__main__':
    # Given pcap file
    pcap_file_name_sender = 'Input/BandwidthChange/zoom_flashes_150kbps_20loss_20delay_sender_set7.pcap'
    pcap_file_name_receiver = 'Input/BandwidthChange/Zoom-flashes-150kbps_20loss_20delay-Receiver_set_7.pcap'

    csv_file1 = 'OutputCsvs/sender_sania_Zoom-flashes-150kbps_20loss_20delay_set7.csv'
    csv_file2 = 'OutputCsvs/receiver_vanessa_Zoom-flashes-150kbps_20loss_20delay_set7.csv'

    SENDER_IP = '172.24.22.15'  # '20.110.105.179'  # '172.31.240.217'
    RECEIVER_IP = '172.24.19.87'

    SENDER_PORT = 56416
    RECEIVER_PORT = 10961

    # Open the pcap file and read the bytes
    with open(pcap_file_name_sender, 'rb') as pcap_file1:
        pcap1 = dpkt.pcap.Reader(pcap_file1)
        df1 = process_packets(pcap1, csv_file1, SENDER_IP, RECEIVER_IP, SENDER_PORT, RECEIVER_PORT)

    # Open the pcap file and read the bytes
    with open(pcap_file_name_receiver, 'rb') as pcap_file2:
        pcap2 = dpkt.pcap.Reader(pcap_file2)
        df2 = process_packets(pcap2, csv_file2, SENDER_IP, RECEIVER_IP, SENDER_PORT, RECEIVER_PORT)

    # df1['']
