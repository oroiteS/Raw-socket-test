import tkinter as tk
from tkinter import ttk, messagebox

from get_localhost import get_localhost


def check_ip(ip: str) -> bool:
    """
    检查IP地址格式是否正确
    """
    try:
        # 移除首尾空格并分割
        parts = ip.strip().split(".")
        # 快速检查是否为4段 
        if len(parts) != 4:
            return False
        # 使用列表推导式和all函数简化检查
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    except:
        return False


def check_domain(domain: str) -> bool:
    """
    检查域名格式是否正确
    规则：
    1. 只允许字母、数字、点和连字符
    2. 不能以点或连字符开始/结束
    3. 点不能连续出现
    4. 每段长度在1-63之间
    5. 总长度不超过253字符
    """
    if not domain or len(domain) > 253:
        return False
    
    # 域名格式的正则表达式
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
    
    return bool(re.match(pattern, domain))
    

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("socket test")

        # 设置窗口大小并禁止调整大小
        window_width = 600
        window_height = 500
        self.root.geometry(f"{window_width}x{window_height}")
        self.root.resizable(False, False)  # 禁止调整窗口大小

        # 配置网格布局权重
        self.root.grid_columnconfigure(1, weight=1)

        # 创建和布局组件
        self._create_ip_port_section()
        self._create_protocol_section()
        self._create_buttons()
        self._create_text_area()

    def _create_ip_port_section(self):
        """创建IP和端口相关的输入区域"""
        # 标签统一样式
        label_width = 10
        # 左边距20，右边距5
        label_padx = (20, 5)  
        # 左边距5，右边距20
        entry_padx = (5, 20)  
        # 本机地址
        self.local_ip_label = tk.Label(self.root, text="本机地址", width=label_width, anchor='e')
        self.local_ip_label.grid(row=0, column=0, sticky=tk.E, padx=label_padx, pady=5)

        self.local_ip_combobox = ttk.Combobox(
            self.root,
            values=get_localhost()[1],
            state="readonly",
            width=50  # 增加宽度
        )
        self.local_ip_combobox.current(0)
        self.local_ip_combobox.grid(row=0, column=1, sticky=tk.EW, padx=entry_padx, pady=5)

        # 本机端口
        self.local_port_label = tk.Label(self.root, text="本机端口", width=label_width, anchor='e')
        self.local_port_label.grid(row=1, column=0, sticky=tk.E, padx=label_padx, pady=5)

        self.local_port_entry = tk.Entry(self.root)
        self.local_port_entry.grid(row=1, column=1, sticky=tk.EW, padx=entry_padx, pady=5)

        # 目的地址
        self.destination_ip_label = tk.Label(self.root, text="目的地址", width=label_width, anchor='e')
        self.destination_ip_label.grid(row=2, column=0, sticky=tk.E, padx=label_padx, pady=5)

        self.destination_ip_entry = tk.Entry(self.root)
        self.destination_ip_entry.grid(row=2, column=1, sticky=tk.EW, padx=entry_padx, pady=5)

        # 目的端口
        self.destination_port_label = tk.Label(self.root, text="目的端口", width=label_width, anchor='e')
        self.destination_port_label.grid(row=3, column=0, sticky=tk.E, padx=label_padx, pady=5)

        self.destination_port_entry = tk.Entry(self.root)
        self.destination_port_entry.grid(row=3, column=1, sticky=tk.EW, padx=entry_padx, pady=5)

    def _create_protocol_section(self):
        """创建协议选择区域"""
        self.option_frame = ttk.LabelFrame(self.root, text="协议类型")
        self.option_frame.grid(row=4, column=0, columnspan=2, sticky=tk.EW, padx=20, pady=10)

        # 配置option_frame的网格布局
        self.option_frame.grid_columnconfigure(0, weight=1)
        self.option_frame.grid_columnconfigure(1, weight=1)
        self.option_frame.grid_columnconfigure(2, weight=1)
        self.option_frame.grid_columnconfigure(3, weight=1)
        self.option_frame.grid_columnconfigure(4, weight=1)

        options = ["IP", "ICMP", "TCP", "UDP", "DNS"]
        self.option_var = tk.StringVar(value=options[0])

        # 平均分配单选按钮
        for i, option in enumerate(options):
            rb = tk.Radiobutton(
                self.option_frame,
                text=option,
                variable=self.option_var,
                value=option
            )
            rb.grid(row=0, column=i, padx=10, pady=5, sticky=tk.EW)

    def _create_buttons(self):
        """创建按钮区域"""
        button_frame = tk.Frame(self.root)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)

        # 统一按钮样式
        button_width = 15
        button_padx = 10

        self.send_button = tk.Button(
            button_frame,
            text="发送报文",
            command=self.send_packet,
            width=button_width
        )
        self.send_button.grid(row=0, column=0, padx=button_padx)

        self.info_button = tk.Button(
            button_frame,
            text="本机信息",
            command=self.show_local_info,
            width=button_width
        )
        self.info_button.grid(row=0, column=1, padx=button_padx)

    def _create_text_area(self):
        """创建文本显示区域"""
        # 创建Frame来容纳文本区域和滚动条
        text_frame = tk.Frame(self.root)
        text_frame.grid(row=6, column=0, columnspan=2, sticky=tk.NSEW, padx=20, pady=10)
        text_frame.grid_columnconfigure(0, weight=1)
        text_frame.grid_rowconfigure(0, weight=1)

        # 创建文本区域
        self.text_area = tk.Text(
            text_frame,
            height=12,
            width=50,  # 增加宽度
            wrap=tk.WORD  # 自动换行
        )
        self.text_area.grid(row=0, column=0, sticky=tk.NSEW)

        # 添加滚动条
        scrollbar = tk.Scrollbar(text_frame, command=self.text_area.yview)
        scrollbar.grid(row=0, column=1, sticky=tk.NS)
        self.text_area.config(yscrollcommand=scrollbar.set)

    def send_packet(self):
        # 获取本机地址
        local_ip = self.local_ip_combobox.get()
        # 获取选中的协议
        selected = self.option_var.get()
        # 获取本机端口，如果为空则提示用户输入
        local_port = self.local_port_entry.get()
        # 获取目的端口，如果为空则提示用户输入
        destination_port = self.destination_port_entry.get()

        # 只有这俩协议要求使用端口号
        if selected == 'TCP' or selected == 'UDP':
            if not local_port:
                messagebox.showerror(title="error", message="请输入本地端口号")
                return
            elif not local_port.isdigit():
                messagebox.showerror(title="error", message="本地端口号不是纯数字！")
                return

            if not destination_port:
                messagebox.showerror(title="error", message="请输入目标端口号")
                return
            if not destination_port.isdigit():
                messagebox.showerror(title="error", message="目标端口号不是纯数字！")
                return

        # 获取目的主机地址，如果为空则提示用户输入
        destination_ip = self.destination_ip_entry.get()
        if not destination_ip:
            messagebox.showerror(title="error", message="请输入目的主机地址")
            return
        elif selected == 'DNS':
            if not check_domain(destination_ip):
                messagebox.showerror(title="error", message="请输入正确的域名格式！")
                return
        elif not check_ip(destination_ip):
            messagebox.showerror(title="error", message="目标ip地址不正确！")
            return

        # 清空文本区域并插入新信息
        self.text_area.delete(1.0, tk.END)
        # 根据获取的协议来判断执行什么文件
        if selected == 'IP':
            from IP import send_ip_packet
            self.text_area.insert(tk.END, send_ip_packet(local_ip, destination_ip))
        elif selected == 'ICMP':
            from ICMP import send_icmp_ping
            self.text_area.insert(tk.END, send_icmp_ping(destination_ip))
        elif selected == 'TCP':
            from TCP import send_tcp_syn
            self.text_area.insert(tk.END, send_tcp_syn(local_ip, local_port, destination_ip, destination_port))
        elif selected == 'UDP':
            from UDP import send_udp_packet
            self.text_area.insert(tk.END, send_udp_packet(local_port, destination_ip, destination_port))
        else:
            from DNS import dns_query
            self.text_area.insert(tk.END, str(dns_query(destination_ip)))

    def show_local_info(self):
        # 显示本机信息的逻辑
        localhost = get_localhost()
        # 接下来更改combobox
        self.local_ip_combobox['values'] = localhost[1]
        self.local_ip_combobox.current(0)
        # 接下来实现更新text
        # 格式化信息为字符串
        info_str = f"本机主机号：{localhost[0]}\n本机ip地址：{localhost[1]}\n本机mac地址：{localhost[2]}"
        # 清空文本区域并插入新信息
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, info_str)

    def run(self):
        # 运行主循环
        self.root.mainloop()
