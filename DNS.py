import random
import socket
import struct


def build_dns_query(domain):
    """构建DNS查询报文"""
    # 随机生成一个查询ID
    transaction_id = random.randint(0, 65535)

    # DNS头部标志
    flags = 0x0100  # 标准查询，期望递归
    questions = 1  # 问题数
    answers = 0  # 回答数
    authority = 0  # 授权记录数
    additional = 0  # 附加记录数

    # 构建DNS头部
    dns_header = struct.pack('!HHHHHH',
                             transaction_id,  # 事务ID
                             flags,  # 标志
                             questions,  # 问题数
                             answers,  # 回答数
                             authority,  # 授权记录数
                             additional  # 附加记录数
                             )

    # 构建查询部分
    query = b''
    # 将域名分段并添加长度
    for part in domain.split('.'):
        query += bytes([len(part)]) + part.encode()
    query += b'\x00'  # 域名结束符

    # 添加查询类型和类
    query_type = 1  # A记录
    query_class = 1  # IN (Internet)
    query += struct.pack('!HH', query_type, query_class)

    return dns_header + query, transaction_id


def parse_dns_response(data, transaction_id):
    """解析DNS响应"""
    # 解析DNS头部
    header = struct.unpack('!HHHHHH', data[:12])
    if header[0] != transaction_id:
        return "响应ID不匹配"

    # 跳过问题部分
    offset = 12
    # 跳过查询的域名
    while True:
        length = data[offset]
        if length == 0:
            break
        offset += length + 1
    offset += 5  # 跳过查询类型和类

    # 解析答案部分
    answers = []
    for _ in range(header[3]):  # header[3]是回答数量
        # 处理压缩指针
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            # 跳过名称
            while True:
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                offset += length + 1

        # 解析资源记录
        type_, class_, ttl, data_len = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10

        # 如果是A记录（IPv4地址）
        if type_ == 1 and data_len == 4:
            ip = '.'.join(str(x) for x in data[offset:offset + 4])
            answers.append(ip)

        offset += data_len

    return answers


def dns_query(domain, dns_server="8.8.8.8"):
    """发送DNS查询并接收响应"""
    # 创建UDP套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    string = ""
    try:
        # 构建DNS查询报文
        query_packet, transaction_id = build_dns_query(domain)

        # 发送查询
        sock.sendto(query_packet, (dns_server, 53))
        string += f"已发送DNS查询到 {dns_server} 查询域名: {domain}"

        # 接收响应
        response, _ = sock.recvfrom(1024)

        # 解析响应
        answers = parse_dns_response(response, transaction_id)

        if isinstance(answers, list):
            string += f"\n查询结果:"
            string += f"\n域名: {domain}"
            string += f"\nIP地址:"
            for ip in answers:
                string += f"\n  {ip}"
        else:
            string += f"\n解析错误: {answers}"

    except socket.timeout:
        string += f"\n查询超时"
    except Exception as e:
        string += f"\n发生错误: {e}"
    finally:
        sock.close()
        return string
