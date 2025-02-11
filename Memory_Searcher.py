import ctypes
import sys,psutil
from ctypes import wintypes
import tkinter as tk
from tkinter import *
from tkinter.ttk import *
import threading

# 定义必要的 Windows API 常量
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
# 定义查找结果保存的列表
results = []

class RedirectText:
    def __init__(self, text_widget):
        self.text_widget = text_widget
        # 创建用于不同颜色的标签
        self.text_widget.tag_configure("green", foreground="green")
        self.text_widget.tag_configure("red", foreground="red")
        self.text_widget.tag_configure("blue", foreground="blue")
    def write(self, string, color="black"):
        # 根据颜色插入带有标签的文本
        self.text_widget.insert(tk.END, string, (color,))
        self.text_widget.see(tk.END)  # 自动滚动到末尾    
    def flush(self):
        pass  # flush 方法通常需要定义，但在这里不需要做任何事情

# 定义结构体来存储内存信息
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

# 将字符串转换为十六进制字节数组
def string_to_hex_bytes(string):
    return string.encode("utf-8")

# 读取内存和搜索目标字符串的函数
def search_region(address, memory_info, process_handle, target_bytes, max_size, results_lock):
    # 读取内存
    buffer = ctypes.create_string_buffer(min(memory_info.RegionSize, max_size))
    bytes_read = ctypes.c_size_t(0)
    
    if ctypes.windll.kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        buffer,
        memory_info.RegionSize,
        ctypes.byref(bytes_read),
    ):
        region_data = buffer.raw[:bytes_read.value]
        index = region_data.find(target_bytes)
        if index != -1:
            with results_lock:  # 使用锁确保线程安全
                results.append(hex(address + index))

# 主搜索函数
def search_memory(pid: int, process_name: str, target_string:str):
    global results  # 确保我们使用全局 results
    results = []  # 清空上次的搜索结果

    target_bytes = string_to_hex_bytes(target_string)
    max_size = 1024 * 1024  # 1 MB

    # 打开进程
    process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not process_handle:
        redirected_text.write(f"无法打开进程 {process_name} (PID: {pid})，请确保以管理员权限运行。\n", color="red")
        return []

    # 初始化内存地址
    address = 0
    memory_info = MEMORY_BASIC_INFORMATION()

    results_lock = threading.Lock()  # 锁定搜索结果

    try:
        while ctypes.windll.kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(memory_info),
            ctypes.sizeof(memory_info),
        ):
            # 如果该区域是可读的
            if memory_info.State == 0x1000 and memory_info.Protect in (0x04, 0x20):
                # 使用线程池并行化搜索
                threading.Thread(target=search_region, args=(address, memory_info, process_handle, target_bytes, max_size, results_lock)).start()
            
            # 移动到下一内存区域
            address += memory_info.RegionSize

    finally:
        ctypes.windll.kernel32.CloseHandle(process_handle)

    return results

# 输出指定内存地址前后十个字节的数据
def print_memory_context(process_handle, address, region_size):
    buffer = ctypes.create_string_buffer(region_size)
    bytes_read = ctypes.c_size_t(0)

    # 读取内存数据
    if ctypes.windll.kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address-0x10),
        buffer,
        region_size,
        ctypes.byref(bytes_read)
    ):
        data = buffer.raw[:bytes_read.value]
        # 打印前十个字节和后十个字节
        redirected_text.write(f"原始数据: {data.hex()}\n", color="green")
        redirected_text.write(f"{data.decode('utf-8', errors='ignore')}\n", color="green")
    else:
        redirected_text.write(f"无法读取内存地址 {hex(address)}\n", color="red")

# 根据PID搜索
def search_memory_FromPID(pid: int, target_string:str):
    target_bytes = string_to_hex_bytes(target_string)
    results = []

    # 打开目标进程
    process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not process_handle:
        redirected_text.write(f"无法打开进程 (PID: {pid})，请确保以管理员权限运行。\n", color="red")
        return []

    # 初始化内存查询结构体
    address = 0
    memory_info = MEMORY_BASIC_INFORMATION()

    try:
        # 循环查询进程的内存区域
        while ctypes.windll.kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(memory_info),
            ctypes.sizeof(memory_info)
        ):
            # 只读取可用内存区域（已提交且具有读写权限）
            if memory_info.State == 0x1000 and memory_info.Protect in (0x04, 0x20):
                # 读取内存内容
                buffer = ctypes.create_string_buffer(memory_info.RegionSize)
                bytes_read = ctypes.c_size_t(0)

                # 执行内存读取
                if ctypes.windll.kernel32.ReadProcessMemory(
                    process_handle,
                    ctypes.c_void_p(address),
                    buffer,
                    memory_info.RegionSize,
                    ctypes.byref(bytes_read)
                ):
                    # 获取实际读取的内存内容
                    region_data = buffer.raw[:bytes_read.value]
                    # 在内存区域中查找目标字节
                    index = region_data.find(target_bytes)
                    if index != -1:
                        results.append(hex(address + index))
                        # 输出目标字符串所在位置前后10个字节的数据
                        redirected_text.write(f"找到目标字符串, 地址: {hex(address + index)}\n", color="red")
                        print_memory_context(process_handle, address + index, 0x40) 
                        redirected_text.write(f"——————————————————————————————————————————————————\n", color="blue")
            # 移动到下一个内存区域
            address += memory_info.RegionSize

    finally:
        # 关闭进程句柄
        ctypes.windll.kernel32.CloseHandle(process_handle)

    return results

def startSearch():
    text_box.delete(1.0, tk.END)
    text_box.config(state='normal')
    target_string = E_String.get()
    if not E_String.get():
        redirected_text.write(f"请输入目标字符串！\n",color="red")
    elif E_String.get() and E_PID.get():
        search_memory_FromPID(int(E_PID.get()), target_string)
    else:
        for proc in psutil.process_iter(['pid', 'name']):
            pid = proc.info['pid']
            process_name = proc.info['name']
            #print(f"正在搜索进程 {process_name} (PID: {pid})")
            matches = search_memory(pid, process_name,target_string)
            if matches:
                redirected_text.write(f"进程 {process_name} (PID: {pid})找到匹配地址: {matches}\n",color="green")
            text_box.update()
        redirected_text.write(f"搜索完成\n",color="blue")
        text_box.update()

if __name__ == "__main__":
    root = tk.Tk()
    # 获取屏幕尺寸计算参数，使窗口显示再屏幕中央
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    width = 1000
    height = 450
    root_size = f'{width}x{height}+{round((screen_width - width) / 2)}+{round((screen_height - height) / 2)}' 
    root.geometry(root_size)
    root.resizable(height=False, width=False)
    root.title('Memory Searcher')
    Label(root, text='').grid(row=0, column=0, padx=20, pady=30) 
    Label(root, text='需要查找的字符串：').grid(row=0, column=1)
    E_String = Entry(root, width=20)
    E_String.grid(row=0, column=2, columnspan=4)
    Label(root, text='指定PID（默认搜索所有进程）：').grid(row=1, column=1)
    E_PID = Entry(root, width=20)
    E_PID.grid(row=1, column=2, columnspan=4)
    btn = Button(root, text='开始', command=startSearch)
    btn.grid(row=1, column=6)

    Label(root, text='输出：').grid(row=2, column=1,rowspan=10)
    text_box = Text(root,width=100)
    text_box.config(state='disabled')
    text_box.grid(row=2, column=2,columnspan=16,rowspan=10)
    # 创建滚动条
    scrollbar = tk.Scrollbar(root, command=text_box.yview)
    scrollbar.grid(row=2, column=18, rowspan=10, sticky='ns')  # 将滚动条放在文本框右侧
    # 将滚动条与文本框关联
    text_box['yscrollcommand'] = scrollbar.set
    # 重定向 stdout 到 Text 组件
    redirected_text = RedirectText(text_box)
    sys.stdout = redirected_text

    root.mainloop()

