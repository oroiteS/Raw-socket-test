import socket
import struct


def send_udp_packet(src_port, dst_ip, dst_port, data=b'Hello UDP!'):
    try:
        # 创建原始套接字
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    except socket.error as e:
        return f'Socket 创建失败: {e}'

    # UDP 头部字段
    src_port = int(src_port)  # 源端口
    dst_port = int(dst_port)  # 目标端口
    udp_length = 8 + len(data)  # UDP头部长度(8) + 数据长度
    udp_checksum = 0  # 校验和初始值为0

    # 打包UDP头部（不含校验和）
    udp_header = struct.pack('!HHHH',
                             src_port,  # 源端口
                             dst_port,  # 目标端口
                             udp_length,  # UDP总长度
                             udp_checksum  # 校验和
                             )

    # 完整的UDP数据包
    packet = udp_header + data

    try:
        # 发送数据包
        s.sendto(packet, (dst_ip, 0))
        return (f'成功发送UDP包到 {dst_ip}:{dst_port}\n  源端口: {src_port}\n  目标端口: {dst_port}\n  数据长度: {len(data)} 字节'
                f'\n  数据: {data}')
    except socket.error as e:
        return f'发送失败: {e}'
    finally:
        s.close()
