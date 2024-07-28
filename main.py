import json
import os
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, ttk
from tkinter import messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD

PASSWORD_FILE = 'passwords.json'


# 提取文件
def handle_output(stream, log_text_widget, stream_name):
    with stream:
        for line in stream:
            log_text_widget.insert(tk.END, f"{stream_name}: {line}")
            log_text_widget.see(tk.END)
            log_text_widget.update_idletasks()


def build_command(archive_path, extract_path, password=None):
    base_command = ['7z', 'x', archive_path, f'-o{extract_path}']
    if password:
        # 通过列表解析避免直接字符串拼接，减少命令注入风险
        password_option = ['-p' + password]
        base_command.extend(password_option)
    return base_command


def extract_with_7zip(archive_path, extract_path, password=None, log_text_widget=None):
    command = build_command(archive_path, extract_path, password)

    try:
        # 使用 DEVNULL 来处理stdout和stderr，避免管道阻塞
        DEVNULL = open(os.devnull, 'w')
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ,
        )
        # 使用多线程同时读取stdout和stderr
        stdout_thread = threading.Thread(target=handle_output, args=(process.stdout, log_text_widget, "stdout"))
        stderr_thread = threading.Thread(target=handle_output, args=(process.stderr, log_text_widget, "stderr"))
        stdout_thread.start()
        stderr_thread.start()
        stdout_thread.join()
        stderr_thread.join()
        process.wait()
        DEVNULL.close()

        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, command)
        # 解压成功后，获取解压出的所有文件路径
        extracted_files = []
        for root, dirs, files in os.walk(extract_path):
            for file in files:
                extracted_files.append(os.path.join(root, file))
        return extracted_files

    except subprocess.CalledProcessError as e:
        log_text_widget.insert(tk.END, f"错误: {e.stderr}\n")
        return False
    except UnicodeDecodeError as e:
        log_text_widget.insert(tk.END, f"编码错误: {e}\n")
        return False
    finally:
        log_text_widget.insert(tk.END, "解压成功.\n")


def extract_all(input_path, output_path, password=None, log_text_widget=None):
    if not os.path.exists(output_path):  # 检查输出路径是否存在，如果不存在，则创建该路径
        os.makedirs(output_path)

    extracted_files = set()  # 用于存储已解压文件的集合
    dirs_to_process = queue.Queue()   # 创建一个队列，用于存储待处理的目录
    for root, dirs, files in os.walk(input_path):  # 遍历输入目录中的所有文件和子目录
        for file in files:
            file_path = os.path.join(root, file)  # 获取当前文件的完整路径
            if is_compressed_or_no_extension(file_path):
                dirs_to_process.put(file_path)  # 将输入目录中的压缩包的完整路径加入队列

    while not dirs_to_process.empty():  # 循环遍历队列，直到为空
        do_file = dirs_to_process.get()  # 从队列中取出一个文件路径
        if do_file not in extracted_files:  # 检查文件是否已经被解压过
            if is_compressed_or_no_extension(do_file):  # 检查文件扩展名是否在压缩文件扩展名列表中，或文件名无后缀
                try:
                    result = extract_with_7zip(do_file, output_path, password, log_text_widget)  # 调用解压缩函数
                    if isinstance(result, list):  # 如果解压成功并返回了文件列表
                        log_text_widget.insert(tk.END, f"已解压文件: {result}\n")  # 在日志中记录解压的文件
                        extracted_files.add(do_file)  # 将解压过的文件添加到集合中
                        # 遍历第一次解压路径下的所有压缩包
                        for root, dirs, files in os.walk(output_path):   # 遍历解压路径下的所有文件
                            for file in files:
                                output_file_path = os.path.join(root, file)
                                if is_compressed_or_no_extension(output_file_path):
                                    dirs_to_process.put(output_file_path)
                except UnicodeDecodeError as e:
                    messagebox.showwarning("编码警告", f"文件名编码错误: {do_file}\n{e}")
                    continue
                except Exception as e:
                    messagebox.showwarning("警告", f"解压缩时出错: {e}")
                    continue
            else:
                log_text_widget.insert(tk.END, f"非压缩文件或无后缀名文件，跳过文件: {do_file}\n")
        else:
            log_text_widget.insert(tk.END, f"文件已解压过，跳过文件: {do_file}\n")
    user_choice = messagebox.askquestion("提示", "解压完成，是否删除压缩文件？")
    if user_choice == 'yes':
        remove_compress(extracted_files)
    else:
        pass


def remove_compress(extracted_files, log_text_widget=None):
    for file_path in extracted_files:
        try:
            os.remove(file_path)
            if log_text_widget:
                log_text_widget.insert(tk.END, f"已删除文件: {file_path}\n")
        except OSError as e:
            if log_text_widget:
                log_text_widget.insert(tk.END, f"删除文件失败: {file_path} - {e}\n")


def is_compressed_or_no_extension(input_path):
    if not os.path.isfile(input_path):  # 判断路径是否为文件
        return True
    filename, file_extension = os.path.splitext(input_path)
    # 定义压缩文件扩展名
    compression_extensions = ['.7z', '.zip', '.rar', '.tar', '.gz', '.bz2', '.xz']
    if file_extension == '' or (file_extension.lower() in compression_extensions):
        return True
    else:
        return False


# 选择输入目录
def select_input_directory():
    path = filedialog.askdirectory()
    input_dir_var.set(path)


# 选择输出目录
def select_output_directory():
    path = filedialog.askdirectory()
    output_dir_var.set(path)


# 选择zip路径
def select_zip_directory():
    path = filedialog.askdirectory()
    zip_dir_var.set(path)


# 开始解压
def start_extraction():
    input_path = input_dir_var.get()
    output_path = output_dir_var.get()
    password = password_var.get()

    if not find_7zip_path():
        messagebox.showerror("错误", "未找到7-Zip程序，请手动输入7-Zip程序路径")
        return

    if not input_path or not output_path:
        messagebox.showwarning("警告", "请填写所有必要的字段。")
        return

    log_window = tk.Toplevel(root)
    log_window.title("解压日志")
    log_text = tk.Text(log_window, wrap='word')
    log_text.pack(expand=True, fill='both')

    extraction_thread = threading.Thread(target=extract_all, args=(input_path, output_path, password, log_text))
    extraction_thread.start()


def find_7zip_path():
    # 常见的7-Zip安装位置
    common_paths = [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe"
    ]

    # 检查每个可能的位置
    for path in common_paths:
        if os.path.isfile(path):
            return path

    # 如果没有找到，尝试从系统环境变量中查找
    for path in os.environ['PATH'].split(os.pathsep):
        exe_file = os.path.join(path.strip('"'), '7z.exe')
        if os.path.isfile(exe_file):
            return exe_file

    # 如果所有方法都失败了，返回False
    return False


# 加载密码
def load_passwords():
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r') as file:
            return json.load(file)
    return []


# 保存密码
def save_passwords(passwords):
    with open(PASSWORD_FILE, 'w') as file:
        json.dump(passwords, file)


# 保存新密码
def save_new_password(password):
    if password and password not in passwords:
        passwords.append(password)
        save_passwords(passwords)
        password_combobox['values'] = passwords


# 处理拖放事件
def on_drop_7zip(event):
    # 移除大括号
    cleaned_data = event.data.replace('{', '').replace('}', '')
    zip_dir_var.set(cleaned_data)


def on_drop(event):
    # 移除大括号
    cleaned_data = event.data.replace('{', '').replace('}', '')
    input_dir_var.set(cleaned_data)


def on_drop_2(event):
    # 移除大括号
    cleaned_data = event.data.replace('{', '').replace('}', '')
    output_dir_var.set(cleaned_data)


# 创建主窗口
root = TkinterDnD.Tk()
root.title("套娃解压工具")

# 解压软件路径
tk.Label(root, text="7zip路径:").grid(row=0, column=0, padx=10, pady=10)
zip_dir_var = tk.StringVar()
zip_path = zip_dir_var.get()
if not zip_path:
    zip_path = [r"C:\Program Files\7-Zip\7z.exe"]
zip_entry = tk.Entry(root, textvariable=zip_dir_var, width=50)
zip_entry.grid(row=0, column=1, padx=10, pady=10)
tk.Button(root, text="选择", command=select_zip_directory).grid(row=0, column=2, padx=10, pady=10)
zip_entry.drop_target_register(DND_FILES)
zip_entry.dnd_bind('<<Drop>>', on_drop_7zip)

# 输入目录
tk.Label(root, text="输入目录:").grid(row=1, column=0, padx=10, pady=10)
input_dir_var = tk.StringVar()
input_entry = tk.Entry(root, textvariable=input_dir_var, width=50)
input_entry.grid(row=1, column=1, padx=10, pady=10)
tk.Button(root, text="选择", command=select_input_directory).grid(row=1, column=2, padx=10, pady=10)
input_entry.drop_target_register(DND_FILES)
input_entry.dnd_bind('<<Drop>>', on_drop)

# 输出目录
tk.Label(root, text="输出目录:").grid(row=2, column=0, padx=10, pady=10)
output_dir_var = tk.StringVar()
output_entry = tk.Entry(root, textvariable=output_dir_var, width=50)
output_entry.grid(row=2, column=1, padx=10, pady=10)
tk.Button(root, text="选择", command=select_output_directory).grid(row=2, column=2, padx=10, pady=10)
output_entry.drop_target_register(DND_FILES)
output_entry.dnd_bind('<<Drop>>', on_drop_2)

# 密码输入框和下拉菜单组合
password_frame = tk.Frame(root)
password_frame.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

tk.Label(password_frame, text="解压密码:").grid(row=0, column=0)
passwords = load_passwords()
if not passwords:
    passwords = ["请输入密码"]
password_var = tk.StringVar(value=passwords[0])
password_combobox = ttk.Combobox(password_frame, textvariable=password_var, values=passwords, width=47)
password_combobox.grid(row=0, column=1, padx=20, pady=10)

# 保存密码按钮
tk.Button(password_frame, text="保存", command=lambda: save_new_password(password_var.get())).grid(row=0, column=2,
                                                                                                   padx=10, pady=10)

# 开始按钮
tk.Button(root, text="开始解压", command=start_extraction).grid(row=4, columnspan=3, pady=20)

root.mainloop()
