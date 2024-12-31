import socket
import struct

from checksum import calculate_checksum


def send_ip_packet(src_ip, dst_ip, data=b'Hello, Raw IP!'):
    # 创建原始套接字
    try:
        # IPPROTO_RAW 表示我们将提供IP头部
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # 设置 IP_HDRINCL 选项，告诉内核我们将自己构建IP头
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except socket.error as e:
        print(f'Socket 创建失败: {e}')
        return

    # IP 头部字段
    ip_version = 4  # IPv4
    ip_ihl = 5  # Internet Header Length (5 * 4 = 20 bytes)
    ip_ver_ihl = (ip_version << 4) + ip_ihl
    ip_tos = 0  # Type of Service
    ip_total_len = 20 + len(data)  # 头部长度 + 数据长度
    ip_id = 54321  # ID字段
    ip_frag_off = 0  # Fragment offset
    ip_ttl = 64  # Time to Live
    ip_proto = socket.IPPROTO_RAW  # Protocol
    ip_check = 0  # 校验和初始值为0
    # 将点分十进制IP地址转换为32位整数
    ip_saddr = struct.unpack("!L", socket.inet_aton(src_ip))[0]
    ip_daddr = struct.unpack("!L", socket.inet_aton(dst_ip))[0]

    # 打包IP头部
    ip_header = struct.pack('!BBHHHBBHLL',
                            ip_ver_ihl,  # B: 版本和头部长度
                            ip_tos,  # B: 服务类型
                            ip_total_len,  # H: 总长度
                            ip_id,  # H: 标识
                            ip_frag_off,  # H: 标志和片偏移
                            ip_ttl,  # B: 生存时间
                            ip_proto,  # B: 协议
                            ip_check,  # H: 校验和
                            ip_saddr,  # L: 源IP地址
                            ip_daddr  # L: 目标IP地址
                            )
    ip_check = calculate_checksum(ip_header)
    # 重新打包IP头部（包含计算好的校验和）
    ip_header = struct.pack('!BBHHHBBHLL',
                            ip_ver_ihl, ip_tos, ip_total_len,
                            ip_id, ip_frag_off, ip_ttl, ip_proto,
                            ip_check, ip_saddr, ip_daddr
                            )

    # 发送数据包
    packet = ip_header + data
    try:
        s.sendto(packet, (dst_ip, 80))
        return f'成功发送IP包到 {dst_ip}'
    except socket.error as e:
        return f'发送失败: {e}'
    finally:
        s.close()

