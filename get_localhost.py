import socket
import subprocess


def get_mac():
    try:
        # 使用 ip link 命令获取网络接口信息
        output = subprocess.check_output(['ip', 'link'], universal_newlines=True)
        lines = output.split('\n')

        # 首先尝试找到活动的网络接口（状态为 UP 的接口）
        for line in lines:
            if 'state UP' in line:
                # 获取下一行，其中包含 MAC 地址
                interface_index = lines.index(line)
                if interface_index + 1 < len(lines):
                    mac_line = lines[interface_index + 1].strip()
                    if 'link/ether' in mac_line:
                        mac = mac_line.split()[1]
                        return mac.replace(':', '-').upper()

        # 如果没有找到活动接口，则尝试获取任何以太网接口的 MAC
        for line in lines:
            if 'link/ether' in line:
                mac = line.split()[1]
                return mac.replace(':', '-').upper()

    except Exception as e:
        print(f"获取MAC地址时出错: {e}")

    return None


def get_localhost():
    # 获取主机名
    hostname = socket.gethostname()

    # 获取IP地址
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip_address = s.getsockname()[0]
    except Exception as e:
        print(f"获取IP地址时出错: {e}")
        ip_address = socket.gethostbyname(hostname)
    finally:
        s.close()

    # 获取MAC地址
    mac_address = get_mac()

    return [hostname, ip_address, mac_address]


if __name__ == "__main__":
    result = get_localhost()
    print(f"主机名: {result[0]}")
    print(f"IP地址: {result[1]}")
    print(f"MAC地址: {result[2]}")