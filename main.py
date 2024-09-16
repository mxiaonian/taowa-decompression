# code = utf-8
import json
import os
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, ttk
from tkinter import messagebox
from concurrent.futures import ThreadPoolExecutor

from tkinterdnd2 import *

PASSWORD_FILE = 'passwords.json'
lock = threading.Lock()
# 全局日志队列
log_queue = queue.Queue()


def log_message(message):
    log_queue.put(message)


def update_log(log_text_widget):
    while not log_queue.empty():
        message = log_queue.get()
        log_text_widget.insert(tk.END, message)
        log_text_widget.see(tk.END)
    # 定时调用自身
    log_text_widget.after(100, update_log, log_text_widget)


# 提取文件
def handle_output(stream, log_text_widget, stream_name):
    with stream:
        # 使用utf-8编码并忽略非法序列
        for line in stream.read().decode('utf-8', errors='ignore').splitlines():
            log_text_widget.insert(tk.END, f"{stream_name}: {line}\n")
            log_text_widget.see(tk.END)
            log_text_widget.update_idletasks()


def build_command(archive_path, extract_path, password=None):
    # 获取当前脚本目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    seven_zip_path = os.path.join(script_dir, '7z.exe')
    base_command = [seven_zip_path, 'x', archive_path, f'-o{extract_path}']
    if password:
        # 通过列表解析避免直接字符串拼接，减少命令注入风险
        password_option = ['-p' + password]
        base_command.extend(password_option)
    return base_command


def extract_with_7zip(archive_path, extract_path, password=None):
    command = build_command(archive_path, extract_path, password)
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ,
        )
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, command, output=stdout, stderr=stderr)
        # 解压成功后，获取解压出的所有文件路径
        extracted_files = []
        for root, _, files in os.walk(extract_path):
            for file in files:
                file_path = os.path.join(root, file)
                extracted_files.append(file_path)
        return extracted_files
    except subprocess.CalledProcessError as e:
        log_message(f"解压失败: {e.stderr}\n")
        return False
    except Exception as e:
        log_message(f"发生异常: {e}\n")
        return False


def remove_compress(extracted_files, log_text_widget=None):
    for file_path in extracted_files:
        try:
            os.remove(file_path)
            if log_text_widget:
                log_text_widget.insert(tk.END, f"已删除文件: {file_path}\n")
        except OSError as e:
            if log_text_widget:
                log_text_widget.insert(tk.END, f"删除文件失败: {file_path} - {e}\n")


def extract_all(input_path, output_path, password=None):
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    extracted_files = set()
    queued_files = queue.Queue()

    # 初始添加输入路径到队列
    if os.path.isfile(input_path):
        queued_files.put(input_path)
    else:
        # 遍历输入路径，添加所有文件到队列
        for root, _, files in os.walk(input_path):
            for file in files:
                file_path = os.path.join(root, file)
                queued_files.put(file_path)

    def process_file():
        while True:
            try:
                do_file = queued_files.get(timeout=1)
            except queue.Empty:
                break

            with lock:
                if do_file in extracted_files:
                    log_message(f"文件已处理过，跳过: {do_file}\n")
                    continue
                extracted_files.add(do_file)

            if is_compressed_file(do_file):
                try:
                    result = extract_with_7zip(do_file, output_path, password)
                    if isinstance(result, list):
                        log_message(f"已解压文件: {do_file}\n")
                        # 将新解压出的文件添加到队列
                        for file_path in result:
                            if is_compressed_file(file_path):
                                queued_files.put(file_path)
                    else:
                        log_message(f"解压失败: {do_file}\n")
                except UnicodeDecodeError as e:
                    log_message(f"编码错误: {do_file}\n{e}\n")
                except Exception as e:
                    log_message(f"解压缩时出错: {do_file}\n{e}\n")
            else:
                log_message(f"非压缩文件，跳过: {do_file}\n")

            queued_files.task_done()

    # 使用线程池控制并发
    max_workers = 5  # 根据需要调整线程数量
    threads = []
    for _ in range(max_workers):
        t = threading.Thread(target=process_file)
        t.start()
        threads.append(t)

    # 等待所有队列中的任务完成
    queued_files.join()

    # 等待所有线程结束
    for t in threads:
        t.join()

    user_choice = messagebox.askquestion("提示", "解压完成，是否删除压缩文件？")
    if user_choice == 'yes':
        remove_compress(extracted_files)
    else:
        pass


def is_compressed_file(file_path):
    if not os.path.isfile(file_path):
        return False
    _, file_extension = os.path.splitext(file_path)
    # 定义压缩文件扩展名
    compression_extensions = ['.7z', '.zip', '.rar', '.tar', '.gz', '.bz2', '.xz', '', 'rarTH']
    return file_extension.lower() in compression_extensions


# 选择输入目录
def select_input_directory():
    path = filedialog.askdirectory()
    input_dir_var.set(path)


# 选择输出目录
def select_output_directory():
    path = filedialog.askdirectory()
    output_dir_var.set(path)


def select_clear_directory():
    path = filedialog.askdirectory()
    clear_dir_var.set(path)


# 开始解压
def start_extraction():
    input_path = input_dir_var.get()
    output_path = output_dir_var.get()
    password = password_var.get()

    if not input_path or not output_path:
        messagebox.showwarning("警告", "请填写所有必要的字段。")
        return

    log_window = tk.Toplevel(root)
    log_window.title("解压日志")
    log_text = tk.Text(log_window, wrap='word')
    log_text.pack(expand=True, fill='both')

    # 启动日志更新
    update_log(log_text)
    extraction_thread = threading.Thread(target=extract_all, args=(input_path, output_path, password))
    extraction_thread.start()


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


def save_new_password(password):
    if password and password not in passwords:
        passwords.append(password)
        save_passwords(passwords)
        password_combobox['values'] = passwords


def delete_promotion_files():
    files_to_delete = delete_input.get("1.0", "end-1c")  # 获取文本框内容
    # 获取用户选择的目录
    target_directory = output_dir_var.get()

    if not os.path.isdir(target_directory):
        messagebox.showerror("错误", "指定的目录无效")
        return

    # 遍历目标目录中的所有文件
    for root, dirs, files in os.walk(target_directory):
        for file in files:
            # 检查文件名是否在待删除列表中
            if file in files_to_delete:
                file_path = os.path.join(root, file)
                try:
                    os.remove(file_path)
                    print(f"已删除文件: {file_path}")
                except Exception as e:
                    print(f"删除文件失败: {file_path}, 错误: {str(e)}")

    messagebox.showinfo("完成", "删除操作已完成")


def on_drop(event):
    # 移除大括号
    cleaned_data = event.data.replace('{', '').replace('}', '')
    input_dir_var.set(cleaned_data)


def on_drop_2(event):
    # 移除大括号
    cleaned_data = event.data.replace('{', '').replace('}', '')
    output_dir_var.set(cleaned_data)


def on_drop_3(event):
    # 提取文件路径
    file_path = event.data
    # 提取文件名和扩展名
    file_name = os.path.basename(file_path).replace('{', '').replace('}', '') + '\n'
    # 插入文件名到 Text 控件
    delete_input.insert(tk.END, file_name)


def on_drop_4(event):
    # 移除大括号
    cleaned_data = event.data.replace('{', '').replace('}', '')
    clear_dir_var.set(cleaned_data)


# 创建主窗口
root = TkinterDnD.Tk()
root.title("套娃解压工具 v0.2.0")

# 配置窗口的列和行，使其可以随着窗口大小的变化而变化
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=3)
root.columnconfigure(2, weight=1)
root.columnconfigure(3, weight=1)
root.rowconfigure(1, weight=1)
root.rowconfigure(2, weight=1)
root.rowconfigure(3, weight=1)
root.rowconfigure(4, weight=1)
root.rowconfigure(5, weight=1)

# 输入目录
input_label = tk.Label(root, text="输入目录:")
input_label.grid(row=0, column=0, padx=10, pady=10, sticky="we")

input_dir_var = tk.StringVar()
input_entry = tk.Entry(root, textvariable=input_dir_var)
input_entry.grid(row=0, column=1, padx=10, pady=10, sticky="we")

input_select_button = tk.Button(root, text="选择", command=select_input_directory)
input_select_button.grid(row=0, column=2, padx=10, pady=10, sticky="we")
input_entry.drop_target_register(DND_FILES)
input_entry.dnd_bind('<<Drop>>', on_drop)

# 输出目录
output_label = tk.Label(root, text="输出目录:")
output_label.grid(row=1, column=0, padx=10, pady=10, sticky="we")

output_dir_var = tk.StringVar()
output_entry = tk.Entry(root, textvariable=output_dir_var)
output_entry.grid(row=1, column=1, padx=10, pady=10, sticky="we")

output_select_button = tk.Button(root, text="选择", command=select_output_directory)
output_select_button.grid(row=1, column=2, padx=10, pady=10, sticky="we")
output_entry.drop_target_register(DND_FILES)
output_entry.dnd_bind('<<Drop>>', on_drop_2)

password_label = tk.Label(root, text="解压密码:")
password_label.grid(row=2, column=0, padx=10, pady=10, sticky="we")
passwords = load_passwords()
if not passwords:
    passwords = ["请输入密码"]
password_var = tk.StringVar(value=passwords[0])
password_combobox = ttk.Combobox(root, textvariable=password_var, values=passwords)
password_combobox.grid(row=2, column=1, padx=10, pady=10, sticky="we")

# 保存密码按钮
save_password_button = tk.Button(root, text="保存密码", command=lambda: save_new_password(password_var.get()))
save_password_button.grid(row=2, column=2, padx=10, pady=10, sticky="we")

# 开始按钮
start_extraction_button = tk.Button(root, text="开始解压", command=start_extraction)
start_extraction_button.grid(row=3, columnspan=3, padx=10, pady=10, sticky="we")

# 清理目录
clear_label = tk.Label(root, text="清理目录:")
clear_label.grid(row=4, column=0, padx=10, pady=10, sticky="we")

clear_dir_var = tk.StringVar()
clear_entry = tk.Entry(root, textvariable=clear_dir_var)
clear_entry.grid(row=4, column=1, padx=10, pady=10, sticky="we")

clear_select_button = tk.Button(root, text="选择", command=select_clear_directory)
clear_select_button.grid(row=4, column=2, padx=10, pady=10, sticky="we")
clear_entry.drop_target_register(DND_FILES)
clear_entry.dnd_bind('<<Drop>>', on_drop_4)

# 删除推广文件
delete_label = tk.Label(root, text="删除推广文件:")
delete_label.grid(row=5, column=0, padx=10, pady=10, sticky="we")

delete_input = tk.Text(root, height=5)  # 修正高度参数名
delete_input.grid(row=5, column=1, padx=10, pady=10, sticky="we")
delete_input.drop_target_register(DND_FILES)
delete_input.dnd_bind('<<Drop>>', on_drop_3)

delete_button = tk.Button(root, text="删除", command=delete_promotion_files)
delete_button.grid(row=5, column=2, padx=10, pady=10, sticky="we")

root.mainloop()
