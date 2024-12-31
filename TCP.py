import random
import socket
import struct
import time

from checksum import calculate_checksum


def calculate_tcp_checksum(src_ip, dst_ip, tcp_header, data=b''):
    """
    计算TCP校验和，包含TCP伪头部
    伪头部包含: 源IP、目标IP、协议号、TCP长度
    """
    # 创建伪头部
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(data)

    # 将IP地址转换为二进制
    src_ip = socket.inet_aton(src_ip)
    dst_ip = socket.inet_aton(dst_ip)

    # 构建伪头部
    pseudo_header = struct.pack('!4s4sBBH',
                                src_ip,  # 源IP
                                dst_ip,  # 目标IP
                                0,  # 占位符
                                protocol,  # 协议号
                                tcp_length  # TCP长度
                                )

    # 计算校验和
    checksum = 0

    # 处理伪头部
    for i in range(0, len(pseudo_header), 2):
        word = (pseudo_header[i] << 8) + pseudo_header[i + 1]
        checksum += word
        checksum = (checksum >> 16) + (checksum & 0xFFFF)

    # 处理TCP头部和数据
    msg = tcp_header + data
    for i in range(0, len(msg), 2):
        if i + 1 < len(msg):
            word = (msg[i] << 8) + msg[i + 1]
        else:
            word = msg[i] << 8
        checksum += word
        checksum = (checksum >> 16) + (checksum & 0xFFFF)

    # 返回校验和的反码
    return ~checksum & 0xFFFF


def send_tcp_syn(src_ip, src_port, dst_ip, dst_port):
    """发送TCP SYN包并接收SYN-ACK响应"""
    try:
        # IPPROTO_RAW 表示我们将提供IP头部
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # 设置 IP_HDRINCL 选项，告诉内核我们将自己构建IP头
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.settimeout(5)
    except socket.error as e:
        print(f'Socket 创建失败: {e}')
        return

    # 修改IP头部构建方式，参考IP.py的实现
    ip_version = 4
    ip_ihl = 5
    ip_ver_ihl = (ip_version << 4) + ip_ihl
    ip_tos = 0
    ip_tot_len = 20 + 32  # IP头部(20字节) + TCP头部(32字节)
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    # 将IP地址转换为32位整数
    ip_saddr = struct.unpack("!L", socket.inet_aton(src_ip))[0]
    ip_daddr = struct.unpack("!L", socket.inet_aton(dst_ip))[0]

    # 打包IP头部
    ip_header = struct.pack('!BBHHHBBHLL',
                            ip_ver_ihl,  # B: 版本和头部长度
                            ip_tos,  # B: 服务类型
                            ip_tot_len,  # H: 总长度
                            ip_id,  # H: 标识
                            ip_frag_off,  # H: 标志和片偏移
                            ip_ttl,  # B: 生存时间
                            ip_proto,  # B: 协议
                            ip_check,  # H: 校验和
                            ip_saddr,  # L: 源IP地址
                            ip_daddr  # L: 目标IP地址
                            )

    # 计算IP头部校验和
    ip_check = calculate_checksum(ip_header)

    # 重新打包IP头部（包含校验和）
    ip_header = struct.pack('!BBHHHBBHLL',
                            ip_ver_ihl,
                            ip_tos,
                            ip_tot_len,
                            ip_id,
                            ip_frag_off,
                            ip_ttl,
                            ip_proto,
                            ip_check,
                            ip_saddr,
                            ip_daddr)

    # TCP头部字段
    seq_num = random.randint(0, 2 ** 32 - 1)  # 随机序列号
    ack_num = 0  # SYN包中ACK为0

    # 数据偏移（4位）
    tcp_offset = 8
    flags = 0x002

    # 窗口大小和紧急指针
    tcp_window = socket.htons(5840)  # 标准窗口大小
    tcp_urgent = 0

    # 构建TCP头部（不含校验和）
    tcp_header = struct.pack('!HHLLHHHHLLL',
                             int(src_port),  # 源端口
                             int(dst_port),  # 目标端口
                             seq_num,  # 序列号
                             ack_num,  # 确认号
                             0x8002,  # 数据偏移和标志位
                             tcp_window,  # 窗口大小
                             0,  # 校验和（先设为0）
                             tcp_urgent,  # 紧急指针（先设为0）
                             0x020405b4,
                             0x01030308,
                             0x01010402
                             )
    # 计算TCP校验和
    tcp_checksum = calculate_tcp_checksum(src_ip, dst_ip, tcp_header)

    # 重新打包TCP头部（包含校验和）
    tcp_header = struct.pack('!HHLLHHHHLLL',
                             int(src_port),  # 源端口
                             int(dst_port),  # 目标端口
                             seq_num,  # 序列号
                             ack_num,  # 确认号
                             0x8002,  # 数据偏移和标志位
                             tcp_window,  # 窗口大小
                             tcp_checksum,  # 校验和（先设为0）
                             tcp_urgent,  # 紧急指针（先设为0）
                             0x020405b4,
                             0x01030308,
                             0x01010402
                             )

    # 修改：发送完整的IP+TCP数据包
    packet = ip_header + tcp_header
    try:
        s.sendto(packet, (dst_ip, 0))
        
        # 由于不需要发送第三次握手报文，这里可以直接关闭socket
        s.close()
        return f'成功发送TCP SYN包到 {dst_ip}:{dst_port}\n  源端口: {src_port}\n  序列号: {seq_num}'

    except socket.error as e:
        s.close()
        return f'发送失败: {e}'


if __name__ == "__main__":
    # 测试参数
    src_ip = "192.168.31.109"  # 确保这是你的本机IP
    src_port = 12292
    dst_ip = "192.168.31.1"
    dst_port = 80

    # 需要以管理员权限运行
    send_tcp_syn(src_ip, src_port, dst_ip, dst_port)

