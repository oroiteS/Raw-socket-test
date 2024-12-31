def calculate_checksum(data):
    checksum = 0
    # 每2个字节处理一次数据
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i + 1]
        else:
            word = data[i] << 8

        checksum += word
        # 处理进位
        while checksum > 0xFFFF:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # 返回校验和的反码
    return ~checksum & 0xFFFF

