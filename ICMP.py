import socket
import struct
import time

from checksum import calculate_checksum


def send_icmp_ping(dest_addr, count=4, timeout=2):
    lost_count = 0
    rtts = []
    string = f"正在 Ping {dest_addr} 具有 32 字节的数据:"
    for i in range(count):
        try:
            # 创建原始套接字，使用ICMP协议
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_socket.settimeout(timeout)
        except socket.error as e:
            string += f"\n套接字创建失败: {e}"
            return string

        # ICMP报文内容
        icmp_type = 8  # Echo Request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = 12345  # 进程ID
        icmp_seq = 1  # 序列号
        payload = b'abcdefghijklmnopqrstuvwabcdefghi'

        # 打包ICMP头部和数据
        icmp_header = struct.pack('!BBHHH',
                                  icmp_type,  # B: ICMP类型
                                  icmp_code,  # B: ICMP代码
                                  icmp_checksum,  # H: 校验和
                                  icmp_id,  # H: 标识符
                                  icmp_seq  # H: 序列号
                                  )

        # 计算校验和
        icmp_packet = icmp_header + payload
        icmp_checksum = calculate_checksum(icmp_packet)

        # 重新打包带校验和的ICMP头部
        icmp_header = struct.pack('!BBHHH',
                                  icmp_type,
                                  icmp_code,
                                  icmp_checksum,
                                  icmp_id,
                                  icmp_seq
                                  )

        # 最终的ICMP数据包
        icmp_packet = icmp_header + payload

        try:
            # 记录发送时间
            send_time = time.time()

            # 发送ICMP包
            icmp_socket.sendto(icmp_packet, (dest_addr, 0))

            # 接收响应
            recv_packet, addr = icmp_socket.recvfrom(1024)
            recv_time = time.time()

            # 计算RTT（往返时间）
            rtt = (recv_time - send_time) * 1000  # 转换为毫秒
            rtts.append(rtt)

            # 解析接收到的数据包
            # ip_header = recv_packet[:20]  # IP头部20字节
            icmp_reply = recv_packet[20:28]  # ICMP头部8字节
            icmp_type, icmp_code, _, _, _ = struct.unpack('!BBHHH', icmp_reply)

            if icmp_type == 0:  # ICMP Echo Reply
                string += f"\n来自 {addr[0]} 的回复: 字节=32 时间={int(rtt)}ms TTL=64"
            else:
                string += f"收到非Echo Reply的ICMP包: 类型={icmp_type}, 代码={icmp_code}"
                lost_count += 1
        except socket.timeout:
            string += f"请求超时"
            lost_count += 1
        except socket.error as e:
            string += f"发送/接收出错: {e}"
            lost_count += 1
        finally:
            icmp_socket.close()
            time.sleep(1)

    # 输出统计信息
    received = count - lost_count
    loss_rate = (lost_count / count) * 100

    string += f"\n{dest_addr} 的 Ping 统计信息:"
    string += f"\n    数据包: 已发送 = {count}, 已接收 = {received}, 丢失 = {lost_count} ({int(loss_rate)}% 丢失)"

    if rtts:
        min_rtt = min(rtts)
        max_rtt = max(rtts)
        avg_rtt = sum(rtts) / len(rtts)
        string += f"\n往返行程的估计时间(以毫秒为单位):"
        string += f"\n    最短 = {int(min_rtt)}ms，最长 = {int(max_rtt)}ms，平均 = {int(avg_rtt)}ms"
    return string
