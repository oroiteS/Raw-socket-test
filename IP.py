import random
import socket
import struct

from checksum import calculate_checksum


def build_ip_header(src_ip, dst_ip, protocol, len_data):
    """
    构建IP头部并计算校验和
    """
    ip_version = 4  # IPv4
    ip_ihl = 5  # 头部长度，5 * 4 = 20字节
    ip_ver_ihl = (ip_version << 4) + ip_ihl
    ip_tos = 0  # 服务类型
    ip_total_len = 20+len_data  # IP头部的长度
    ip_id = random.randint(1, 65535)  # 随机生成标识符
    ip_frag_off = 0  # 分段偏移
    ip_ttl = 64  # 生存时间
    ip_proto = protocol  # 协议类型
    ip_check = 0  # 校验和初始值为0
    ip_saddr = struct.unpack("!L", socket.inet_aton(src_ip))[0]  # 源IP地址
    ip_daddr = struct.unpack("!L", socket.inet_aton(dst_ip))[0]  # 目标IP地址

    # 打包IP头部
    ip_header = struct.pack('!BBHHHBBHLL',
                            ip_ver_ihl,  # 版本和头部长度
                            ip_tos,  # 服务类型
                            ip_total_len,  # 总长度
                            ip_id,  # 标识
                            ip_frag_off,  # 标志和片偏移
                            ip_ttl,  # 生存时间
                            ip_proto,  # 协议
                            ip_check,  # 校验和
                            ip_saddr,  # 源IP地址
                            ip_daddr  # 目标IP地址
                            )

    # 计算校验和
    ip_check = calculate_checksum(ip_header)

    # 重新打包IP头部（包含校验和）
    ip_header = struct.pack('!BBHHHBBHLL',
                            ip_ver_ihl, ip_tos, ip_total_len,
                            ip_id, ip_frag_off, ip_ttl, ip_proto,
                            ip_check, ip_saddr, ip_daddr)

    return ip_header


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

    ip_header = build_ip_header(src_ip, dst_ip, socket.IPPROTO_RAW, len(data));

    # 发送数据包
    packet = ip_header + data
    try:
        s.sendto(packet, (dst_ip, 80))
        return f'成功发送IP包到 {dst_ip}'
    except socket.error as e:
        return f'发送失败: {e}'
    finally:
        s.close()

