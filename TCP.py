import random
import socket
import struct
import time

from checksum import calculate_checksum
from IP import build_ip_header


# TCP选项常量定义
class TCPOption:
    KIND_END = 0         # 结束选项
    KIND_NOP = 1         # 无操作选项
    KIND_MSS = 2         # 最大报文段长度
    KIND_WINDOW = 3      # 窗口扩大因子
    KIND_SACK_PERMITTED = 4  # SACK许可
    KIND_TIMESTAMP = 8   # 时间戳

# TCP选项值
MSS_VALUE = 1460        # 最大报文段长度值 (0x05b4)


def build_tcp_options():
    """构建TCP选项字段"""
    # 第一个选项字段 (0x020405b4):
    # - KIND_MSS(2) = 0x02
    # - Length(4) = 0x04
    # - MSS Value(1460) = 0x05b4
    mss_option = (TCPOption.KIND_MSS << 24) | (4 << 16) | MSS_VALUE

    # 第二个选项字段 (0x01030308):
    # - KIND_NOP(1) = 0x01
    # - KIND_WINDOW(3) = 0x03
    # - Length(3) = 0x03
    # - Shift count(8) = 0x08
    window_scale_option = (TCPOption.KIND_NOP << 24) | (TCPOption.KIND_WINDOW << 16) | (3 << 8) | 8

    # 第三个选项字段 (0x01010402):
    # - KIND_NOP(1) = 0x01
    # - KIND_NOP(1) = 0x01
    # - KIND_SACK_PERMITTED(4) = 0x04
    # - Length(2) = 0x02
    sack_option = (TCPOption.KIND_NOP << 24) | (TCPOption.KIND_NOP << 16) | (TCPOption.KIND_SACK_PERMITTED << 8) | 2

    return mss_option, window_scale_option, sack_option


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

    # 使用通用的calculate_checksum函数来计算伪头部和TCP数据的校验和
    checksum_data = pseudo_header + tcp_header + data
    return calculate_checksum(checksum_data)


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

    ip_header = build_ip_header(src_ip, dst_ip, socket.IPPROTO_TCP, 32)

    # TCP头部字段
    seq_num = random.randint(0, 2 ** 32 - 1)  # 随机序列号
    ack_num = 0  # SYN包中ACK为0

    # 数据偏移（4位）
    tcp_offset = 8
    flags = 0x002

    # 窗口大小和紧急指针
    tcp_window = socket.htons(5840)  # 标准窗口大小
    tcp_urgent = 0
    # tcp选项
    tcp_options = build_tcp_options()
    
    # 构建TCP头部（不含校验和）
    tcp_header = struct.pack('!HHLLHHHHLLL',
                           int(src_port),    # 源端口
                           int(dst_port),    # 目标端口
                           seq_num,          # 序列号
                           ack_num,          # 确认号
                           0x8002,           # 数据偏移和标志位
                           tcp_window,       # 窗口大小
                           0,                # 校验和（先设为0）
                           tcp_urgent,       # 紧急指针
                           *tcp_options      # TCP选项
                           )
    # 计算TCP校验和
    tcp_checksum = calculate_tcp_checksum(src_ip, dst_ip, tcp_header)

    tcp_header = struct.pack('!HHLLHHHHLLL',
                           int(src_port),    # 源端口
                           int(dst_port),    # 目标端口
                           seq_num,          # 序列号
                           ack_num,          # 确认号
                           0x8002,           # 数据偏移和标志位
                           tcp_window,       # 窗口大小
                           tcp_checksum,     # 校验和（先设为0）
                           tcp_urgent,       # 紧急指针
                           *tcp_options      # TCP选项
                           )

    # 修改：发送完整的IP+TCP数据包
    packet = ip_header + tcp_header
    try:
        s.sendto(packet, (dst_ip, int(dst_port)))
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

