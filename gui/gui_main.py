import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ctypes
import os
import threading
import time
import datetime

# ===========================
# 1. 核心库加载
# ===========================
class CFilter(ctypes.Structure):
    _fields_ = [
        ("nameContains", ctypes.c_char_p),
        ("pathContains", ctypes.c_char_p),
        ("type", ctypes.c_int),
        ("_pad", ctypes.c_int), # <--- [新增] 必须与 C++ 对应
        ("minSize", ctypes.c_ulonglong),
        ("maxSize", ctypes.c_ulonglong),
        ("startTime", ctypes.c_longlong),
        ("targetUid", ctypes.c_int)
    ]

# 自动寻找库 (支持 gui 在子目录的情况)
lib_names = ["core.dll", "libcore.dll", "libcore.so", "libcore.dylib"]
search_paths = ["../cmake-build-debug", "../build_win", "../build", ".", os.path.dirname(__file__)]
lib_path = None
for p in search_paths:
    for name in lib_names:
        full_path = os.path.join(p, name)
        if os.path.exists(full_path):
            lib_path = os.path.abspath(full_path)
            break
    if lib_path: break

core = None
if lib_path:
    try:
        core = ctypes.cdll.LoadLibrary(lib_path)

        # 高级接口
        core.C_PackWithFilter.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(CFilter), ctypes.c_int]
        core.C_Unpack.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

        # 基础接口
        try:
            core.C_BackupSimple.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            core.C_RestoreSimple.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            core.C_VerifySimple.argtypes = [ctypes.c_char_p]
            core.C_VerifySimple.restype = ctypes.c_char_p
            print("✅ 全部接口加载成功")
        except:
            print("⚠️ 基础接口未加载，请检查 Bridge.cpp")

    except Exception as e:
        print(f"❌ 加载失败: {e}")

# ===========================
# 2. 最终演示版 GUI
# ===========================
class MiniBackupVideoDemo:
    def __init__(self, root):
        self.root = root
        self.root.title("MiniBackup 最终演示系统 (Video Demo)")
        self.root.geometry("1100x750") #稍微加高一点，容纳新选项

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Tab 1: 基础
        self.tab_basic = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_basic, text='  🔰 基础模式 (Basic)  ')
        self._init_basic_ui()

        # Tab 2: 高级打包
        self.tab_pack = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_pack, text='  📦 高级打包 (Pro Pack)  ')
        self._init_pack_ui()

        # Tab 3: 高级解包
        self.tab_unpack = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_unpack, text='  🔓 高级恢复 (Pro Unpack)  ')
        self._init_unpack_ui()

    # =========================================================================
    # 辅助功能
    # =========================================================================
    def _get_file_type(self, filename):
        ext = os.path.splitext(filename)[1].lower()
        type_map = {
            '.c': 'C_SRC', '.cpp': 'CPP', '.h': 'HEAD', '.py': 'PY',
            '.java': 'JAVA', '.html': 'WEB', '.css': 'WEB', '.js': 'WEB',
            '.txt': 'TEXT', '.md': 'MD', '.pdf': 'PDF',
            '.doc': 'DOC', '.docx': 'DOC', '.xls': 'XLS', '.xlsx': 'XLS',
            '.jpg': 'IMG', '.png': 'IMG', '.gif': 'IMG', '.bmp': 'IMG',
            '.zip': 'ZIP', '.rar': 'RAR', '.7z': '7Z',
            '.exe': 'APP', '.dll': 'LIB', '.so': 'LIB'
        }
        return type_map.get(ext, 'BIN')

    def _auto_fill_dest(self, src_path):
        current_dst = self.entry_dst.get()
        if not current_dst.strip():
            now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"Backup_{now_str}.pck"
            if os.path.isdir(src_path):
                base = os.path.dirname(src_path)
                if base == src_path: base = src_path
            else:
                base = os.path.dirname(src_path)

            auto_path = os.path.join(base, default_name)
            self.entry_dst.delete(0, tk.END)
            self.entry_dst.insert(0, auto_path)

    def _get_bytes(self, entry_widget, unit_widget):
        try:
            val = float(entry_widget.get())
            unit = unit_widget.get()
            if unit == "KB": return int(val * 1024)
            if unit == "MB": return int(val * 1024 * 1024)
            if unit == "GB": return int(val * 1024 * 1024 * 1024)
            return int(val)
        except:
            return 0

    # =========================================================================
    # Tab 1: 基础模式
    # =========================================================================
    def _init_basic_ui(self):
        frame = ttk.Frame(self.tab_basic)
        frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)

        # 区域 1: 备份
        lf1 = ttk.LabelFrame(frame, text=" 1. 普通复制备份 (Backup) "); lf1.pack(fill=tk.X, pady=10)
        f = ttk.Frame(lf1); f.pack(fill=tk.X, pady=5)
        ttk.Label(f, text="源数据:", width=8).pack(side=tk.LEFT)
        self.entry_bsrc = ttk.Entry(f); self.entry_bsrc.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(f, text="📂目录", width=6, command=lambda: self._sel_dir(self.entry_bsrc)).pack(side=tk.LEFT)
        ttk.Button(f, text="📄文件", width=6, command=lambda: self._sel_file(self.entry_bsrc)).pack(side=tk.LEFT, padx=2)

        f2 = ttk.Frame(lf1); f2.pack(fill=tk.X, pady=5)
        ttk.Label(f2, text="备份到:", width=8).pack(side=tk.LEFT)
        self.entry_bdst = ttk.Entry(f2); self.entry_bdst.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(f2, text="📂", width=4, command=lambda: self._sel_dir(self.entry_bdst)).pack(side=tk.LEFT)
        ttk.Button(lf1, text="执行备份", command=self.do_simple_backup).pack(fill=tk.X, padx=100, pady=5)

        # 区域 2: 恢复 (带自动校验)
        # [修改] 这里去掉了单独的“校验”区域，直接做恢复
        lf3 = ttk.LabelFrame(frame, text=" 2. 安全恢复 (Secure Restore) "); lf3.pack(fill=tk.X, pady=20)

        f4 = ttk.Frame(lf3); f4.pack(fill=tk.X, pady=5)
        ttk.Label(f4, text="备份源:", width=8).pack(side=tk.LEFT)
        self.entry_bres_src = ttk.Entry(f4); self.entry_bres_src.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(f4, text="📂", width=4, command=lambda: self._sel_dir(self.entry_bres_src)).pack(side=tk.LEFT)

        f5 = ttk.Frame(lf3); f5.pack(fill=tk.X, pady=5)
        ttk.Label(f5, text="恢复到:", width=8).pack(side=tk.LEFT)
        self.entry_bres_dst = ttk.Entry(f5); self.entry_bres_dst.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(f5, text="📂", width=4, command=lambda: self._sel_dir(self.entry_bres_dst)).pack(side=tk.LEFT)

        # 按钮文案改成“校验并恢复”
        ttk.Button(lf3, text="🔍 校验并执行恢复 (Verify & Restore)", command=self.do_simple_restore).pack(fill=tk.X, padx=100, pady=10)

        tk.Label(frame, text="提示：系统会在恢复前自动比对 CRC32 指纹，确保备份未被篡改。", fg="gray", font=("Arial", 9)).pack(side=tk.BOTTOM, pady=10)

    # =========================================================================
    # Tab 2: 高级打包
    # =========================================================================
    def _init_pack_ui(self):
        paned = ttk.PanedWindow(self.tab_pack, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        left = ttk.Frame(paned, width=420)
        right = ttk.Frame(paned, width=600)
        paned.add(left, weight=1); paned.add(right, weight=2)

        # --- 左侧: 控制面板 ---

        # 1. 数据源
        lf1 = ttk.LabelFrame(left, text=" 1. 数据源设置 "); lf1.pack(fill=tk.X, pady=5)
        self.entry_src = ttk.Entry(lf1); self.entry_src.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(lf1, text="📂目录", width=6, command=self._sel_pro_dir).pack(side=tk.LEFT)
        ttk.Button(lf1, text="📄文件", width=6, command=self._sel_pro_file).pack(side=tk.LEFT, padx=2)

        # 2. 输出位置
        lf2 = ttk.LabelFrame(left, text=" 2. 输出设置 (.pck) "); lf2.pack(fill=tk.X, pady=5)
        self.entry_dst = ttk.Entry(lf2); self.entry_dst.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(lf2, text="💾保存", width=6, command=self._sel_pro_save).pack(side=tk.LEFT, padx=2)

        # 3. 加密与压缩
        lf3 = ttk.LabelFrame(left, text=" 3. 安全与压缩 "); lf3.pack(fill=tk.X, pady=5)
        f_sec = ttk.Frame(lf3); f_sec.pack(fill=tk.X, pady=2)
        ttk.Label(f_sec, text="密码:").pack(side=tk.LEFT, padx=5)
        self.entry_pwd = ttk.Entry(f_sec, show="*", width=12); self.entry_pwd.pack(side=tk.LEFT)
        ttk.Label(f_sec, text="算法:").pack(side=tk.LEFT, padx=5)
        self.combo_algo = ttk.Combobox(f_sec, values=["无", "XOR", "RC4"], state="readonly", width=6)
        self.combo_algo.current(2); self.combo_algo.pack(side=tk.LEFT)

        self.var_compress = tk.BooleanVar(value=True)
        ttk.Checkbutton(lf3, text="启用 Huffman 压缩", variable=self.var_compress).pack(anchor="w", padx=5)

        # 4. 高级筛选 (Grid 布局重构)
        lf4 = ttk.LabelFrame(left, text=" 4. 智能筛选规则 "); lf4.pack(fill=tk.X, pady=5)

        # 定义 Grid 的列宽权重
        lf4.columnconfigure(1, weight=1); lf4.columnconfigure(3, weight=1)

        # Row 0: 文件名 & 路径
        ttk.Label(lf4, text="文件名:").grid(row=0, column=0, sticky="e", padx=2, pady=2)
        self.filter_name = ttk.Entry(lf4); self.filter_name.grid(row=0, column=1, sticky="ew", padx=2)
        self.filter_name.bind("<KeyRelease>", self._refresh_preview)

        ttk.Label(lf4, text="路径含:").grid(row=0, column=2, sticky="e", padx=2, pady=2)
        self.filter_path = ttk.Entry(lf4); self.filter_path.grid(row=0, column=3, sticky="ew", padx=2)
        self.filter_path.bind("<KeyRelease>", self._refresh_preview)

        # Row 1: 类型 & 时间
        ttk.Label(lf4, text="类  型:").grid(row=1, column=0, sticky="e", padx=2, pady=2)
        self.combo_type = ttk.Combobox(lf4, values=["全部", "仅文件", "仅目录"], state="readonly", width=8)
        self.combo_type.current(0); self.combo_type.grid(row=1, column=1, sticky="ew", padx=2)
        self.combo_type.bind("<<ComboboxSelected>>", self._refresh_preview)

        ttk.Label(lf4, text="最近(天):").grid(row=1, column=2, sticky="e", padx=2, pady=2)
        self.filter_days = ttk.Entry(lf4); self.filter_days.grid(row=1, column=3, sticky="ew", padx=2)
        self.filter_days.bind("<KeyRelease>", self._refresh_preview)

        # Row 2: 最小大小 + 单位
        ttk.Label(lf4, text="Min大小:").grid(row=2, column=0, sticky="e", padx=2, pady=2)
        f_min = ttk.Frame(lf4); f_min.grid(row=2, column=1, sticky="ew", padx=2)
        self.filter_min = ttk.Entry(f_min, width=6); self.filter_min.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.combo_unit_min = ttk.Combobox(f_min, values=["B", "KB", "MB"], state="readonly", width=3)
        self.combo_unit_min.current(0); self.combo_unit_min.pack(side=tk.RIGHT)
        self.filter_min.bind("<KeyRelease>", self._refresh_preview)
        self.combo_unit_min.bind("<<ComboboxSelected>>", self._refresh_preview)

        # Row 3: 最大大小 + 单位
        ttk.Label(lf4, text="Max大小:").grid(row=2, column=2, sticky="e", padx=2, pady=2)
        f_max = ttk.Frame(lf4); f_max.grid(row=2, column=3, sticky="ew", padx=2)
        self.filter_max = ttk.Entry(f_max, width=6); self.filter_max.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.combo_unit_max = ttk.Combobox(f_max, values=["B", "KB", "MB"], state="readonly", width=3)
        self.combo_unit_max.current(2); self.combo_unit_max.pack(side=tk.RIGHT) # 默认MB
        self.filter_max.bind("<KeyRelease>", self._refresh_preview)
        self.combo_unit_max.bind("<<ComboboxSelected>>", self._refresh_preview)

        # Action Button
        ttk.Button(left, text="🚀 开始高级打包 (Execute Pack)", command=self.do_pack).pack(fill=tk.X, pady=15, ipady=5)

        # --- 右侧: 预览列表 ---
        right_header = ttk.Frame(right); right_header.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(right_header, text="🔍 实时预览 (Real-time Preview)", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        ttk.Label(right_header, text="* 仅显示前 500 项", foreground="gray").pack(side=tk.RIGHT)

        cols = ("path", "type", "size", "mtime")
        self.tree = ttk.Treeview(right, columns=cols, show='headings')
        self.tree.heading("path", text="相对路径"); self.tree.column("path", width=250)
        self.tree.heading("type", text="类型"); self.tree.column("type", width=50, anchor="center")
        self.tree.heading("size", text="大小"); self.tree.column("size", width=70, anchor="e")
        self.tree.heading("mtime", text="修改时间"); self.tree.column("mtime", width=110, anchor="center")

        scroll = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); scroll.pack(side=tk.RIGHT, fill=tk.Y)

    # =========================================================================
    # Tab 3: 高级解包
    # =========================================================================
    def _init_unpack_ui(self):
        f = ttk.Frame(self.tab_unpack); f.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(f, text="选择 .pck 文件", font=("Arial", 11)).pack(anchor="w")
        self.entry_pck_in = ttk.Entry(f, width=50); self.entry_pck_in.pack(pady=(0,10))
        ttk.Button(f, text="浏览文件", command=lambda:self._sel_file(self.entry_pck_in)).pack(pady=(0,20))

        ttk.Label(f, text="解压到目录", font=("Arial", 11)).pack(anchor="w")
        self.entry_dst_in = ttk.Entry(f, width=50); self.entry_dst_in.pack(pady=(0,10))
        ttk.Button(f, text="浏览目录", command=lambda:self._sel_dir(self.entry_dst_in)).pack(pady=(0,20))

        ttk.Label(f, text="解密密码", font=("Arial", 11)).pack(anchor="w")
        self.entry_pwd_in = ttk.Entry(f, width=30, show="*"); self.entry_pwd_in.pack(pady=(0,20))

        ttk.Button(f, text="🔓 立即解包 (带校验)", command=self.do_unpack).pack(fill=tk.X, ipady=10)

    # =========================================================================
    # 逻辑处理
    # =========================================================================
    def _sel_dir(self, entry):
        p = filedialog.askdirectory()
        if p: entry.delete(0, tk.END); entry.insert(0, p)

    def _sel_file(self, entry):
        p = filedialog.askopenfilename()
        if p: entry.delete(0, tk.END); entry.insert(0, p)

    def _sel_pro_dir(self):
        p = filedialog.askdirectory()
        if p:
            self.entry_src.delete(0, tk.END); self.entry_src.insert(0, p)
            self._auto_fill_dest(p); self._refresh_preview()

    def _sel_pro_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.entry_src.delete(0, tk.END); self.entry_src.insert(0, p)
            self._auto_fill_dest(p); self._refresh_preview()

    def _sel_pro_save(self):
        p = filedialog.asksaveasfilename(defaultextension=".pck", filetypes=[("MiniBackup Pack", "*.pck"), ("All Files", "*.*")])
        if p: self.entry_dst.delete(0, tk.END); self.entry_dst.insert(0, p)

    # 列表刷新
    def _refresh_preview(self, event=None):
        for i in self.tree.get_children(): self.tree.delete(i)
        src = self.entry_src.get()
        if not src or not os.path.exists(src): return

        # 1. 获取所有筛选参数
        f_nm = self.filter_name.get()
        f_ph = self.filter_path.get()

        # 类型筛选映射
        type_idx = self.combo_type.current() # 0=All, 1=File, 2=Dir

        # 大小与时间
        limit_min = self._get_bytes(self.filter_min, self.combo_unit_min)
        limit_max = self._get_bytes(self.filter_max, self.combo_unit_max)

        try: days = int(self.filter_days.get())
        except: days = 0
        limit_time = time.time() - (days * 86400) if days > 0 else 0

        # 2. 遍历文件
        file_list = []
        if os.path.isfile(src): file_list.append(src)
        else:
            for root, dirs, files in os.walk(src):
                # 如果只看文件
                if type_idx != 2:
                    for f in files: file_list.append(os.path.join(root, f))
                # 如果只看目录
                if type_idx != 1:
                    for d in dirs: file_list.append(os.path.join(root, d))

        count = 0
        for full_path in file_list:
            try:
                stat = os.stat(full_path)
                size = stat.st_size
                mtime = stat.st_mtime
                name = os.path.basename(full_path)
                is_dir = os.path.isdir(full_path)
            except: continue

            # 相对路径
            rel = os.path.basename(full_path) if os.path.isfile(src) else os.path.relpath(full_path, src)

            # === 执行筛选 ===
            if f_nm and f_nm not in name: continue
            if f_ph and f_ph not in rel: continue

            # 类型细分 (Python walk 已经粗分了，这里确保一下)
            if type_idx == 1 and is_dir: continue
            if type_idx == 2 and not is_dir: continue

            # 大小筛选 (仅针对文件)
            if not is_dir:
                if limit_min > 0 and size < limit_min: continue
                if limit_max > 0 and size > limit_max: continue

            # 时间筛选
            if days > 0 and mtime < limit_time: continue

            # === 显示 ===
            ftype = "DIR" if is_dir else self._get_file_type(name)

            size_str = ""
            if not is_dir:
                if size < 1024: size_str = f"{size} B"
                elif size < 1024*1024: size_str = f"{size/1024:.1f} KB"
                else: size_str = f"{size/(1024*1024):.1f} MB"

            time_str = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
            self.tree.insert("", "end", values=(rel, ftype, size_str, time_str))

            count += 1
            if count > 500: break

    # 基础模式
    def do_simple_backup(self):
        s = self.entry_bsrc.get(); d = self.entry_bdst.get()
        if s and d: threading.Thread(target=lambda: messagebox.showinfo("结果", "备份成功") if core.C_BackupSimple(s.encode('utf-8'), d.encode('utf-8')) else messagebox.showerror("错误", "失败")).start()

    def do_simple_verify(self):
        d = self.entry_bver.get()
        if d:
            def run():
                if core.C_VerifySimple(d.encode('utf-8')): messagebox.showinfo("校验通过", "✅ 数据完整")
                else: messagebox.showwarning("校验失败", "❌ 发现数据被篡改！")
            threading.Thread(target=run).start()

    # 基础模式：恢复 (带 询问/强行恢复 逻辑)
    def do_simple_restore(self):
        s = self.entry_bres_src.get()
        d = self.entry_bres_dst.get()
        if not s or not d: return

        def run():
            self.root.title("🔍 正在校验完整性...")

            # 1. 先调用 Verify 获取错误信息
            err_bytes = core.C_VerifySimple(s.encode('utf-8'))
            err_msg = err_bytes.decode('utf-8', errors='ignore')

            should_restore = True # 默认为True (如果没错误)

            # 2. 如果发现错误，弹出“询问对话框”而不是“错误框”
            if err_msg:
                # 防止错误信息太长把屏幕撑爆
                display_msg = err_msg
                if len(display_msg) > 600:
                    display_msg = display_msg[:600] + "\n... (更多错误已隐藏)"

                # askyesno: 返回 True(是) 或 False(否)
                should_restore = messagebox.askyesno(
                    "⚠️ 完整性警告 (Integrity Warning)",
                    f"系统检测到备份源存在以下异常：\n\n{display_msg}\n\n"
                    "-----------------------------------\n"
                    "❓ 是否强行恢复？\n"
                    "• [是]：忽略警告，恢复所有文件 (包含可能被篡改的文件)。\n"
                    "• [否]：取消操作，什么都不做。"
                )

            # 3. 根据用户选择执行恢复
            if should_restore:
                self.root.title("♻️ 正在恢复数据...")
                res = core.C_RestoreSimple(s.encode('utf-8'), d.encode('utf-8'))

                self.root.title("MiniBackup 最终演示系统")

                if res:
                    if err_msg:
                        # 强行恢复成功的提示
                        messagebox.showwarning("恢复完成", "✅ 已强行恢复所有文件。\n请注意：部分文件可能与原始版本不一致。")
                    else:
                        # 完美恢复的提示
                        messagebox.showinfo("成功", "✅ 完整性校验通过！\n数据已完美还原。")
                else:
                    messagebox.showerror("错误", "恢复失败 (可能是磁盘写保护或路径错误)")
            else:
                self.root.title("MiniBackup 最终演示系统")
                # 用户点了“否”，取消操作

        threading.Thread(target=run).start()

    # 高级打包
    def do_pack(self):
        src = self.entry_src.get(); dst = self.entry_dst.get(); pwd = self.entry_pwd.get()
        if not src or not dst:
            messagebox.showwarning("提示", "请先选择源目录和输出文件")
            return

        enc = self.combo_algo.current()
        comp = 2 if self.var_compress.get() else 0

        # 构造 CFilter
        f = CFilter()
        nm = self.filter_name.get()
        ph = self.filter_path.get()

        f.nameContains = nm.encode('utf-8') if nm else None
        f.pathContains = ph.encode('utf-8') if ph else None

        # 获取类型: GUI索引 0=All(-1), 1=File(0), 2=Dir(1) -> 转换到 C++ 定义
        gui_type = self.combo_type.current()
        if gui_type == 0: f.type = -1
        elif gui_type == 1: f.type = 0  # REGULAR
        elif gui_type == 2: f.type = 1  # DIRECTORY

        f._pad = 0 # 显式填充

        # 处理大小和时间
        f.minSize = self._get_bytes(self.filter_min, self.combo_unit_min)
        f.maxSize = self._get_bytes(self.filter_max, self.combo_unit_max)

        try: d = int(self.filter_days.get())
        except: d = 0
        f.startTime = int(time.time() - d*86400) if d > 0 else 0

        f.targetUid = -1

        def run():
            # 禁用按钮防止重复点击
            try:
                res = core.C_PackWithFilter(src.encode('utf-8'), dst.encode('utf-8'), pwd.encode('utf-8'), enc, ctypes.byref(f), comp)
                if res: messagebox.showinfo("打包成功", f"✅ 任务完成！\n文件已保存至: {dst}")
                else: messagebox.showerror("打包失败", "❌ 核心引擎返回错误，请检查日志。")
            except Exception as e:
                messagebox.showerror("异常", f"调用过程发生异常:\n{e}")

        threading.Thread(target=run).start()

    def do_unpack(self):
        pck = self.entry_pck_in.get(); dst = self.entry_dst_in.get(); pwd = self.entry_pwd_in.get()
        if pck and dst:
            def run():
                if core.C_Unpack(pck.encode('utf-8'), dst.encode('utf-8'), pwd.encode('utf-8')): messagebox.showinfo("成功", "解包并校验通过！")
                else: messagebox.showerror("失败", "解包失败或校验不通过")
            threading.Thread(target=run).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = MiniBackupVideoDemo(root)
    root.mainloop()