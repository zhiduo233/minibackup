import unittest
import ctypes
import os
import shutil
import time
import platform

# ==========================================
# C 结构体定义 (已对齐)
# ==========================================
class CFilter(ctypes.Structure):
    _fields_ = [
        ("nameContains", ctypes.c_char_p),
        ("pathContains", ctypes.c_char_p),
        ("type", ctypes.c_int),
        ("_pad", ctypes.c_int), # [修正] 这里必须加 padding
        ("minSize", ctypes.c_ulonglong),
        ("maxSize", ctypes.c_ulonglong),
        ("startTime", ctypes.c_longlong),
        ("targetUid", ctypes.c_int)
    ]

# ==========================================
# 单元测试类
# ==========================================
class TestMiniBackup(unittest.TestCase):

    # [类级别设置] 所有测试开始前只运行一次：加载 DLL
    @classmethod
    def setUpClass(cls):
        print("\n[Setup] Loading Core Library...")

        # 1. 获取当前脚本所在的目录 (即 tests 文件夹的绝对路径)
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # 2. 获取项目根目录 (tests 的上一级)
        project_root = os.path.dirname(current_dir)

        print(f"   [Debug] Project Root identified as: {project_root}")

        # 3. 在项目根目录下的常见构建位置寻找 DLL
        lib_names = ["core.dll", "libcore.dll", "libcore.so", "libcore.dylib"]
        search_paths = [
            os.path.join(project_root, "cmake-build-debug"),
            os.path.join(project_root, "build_win"),
            os.path.join(project_root, "build"),
            project_root, # 根目录本身
            os.path.join(project_root, "bin") # 为了配合刚才建议的提交结构
        ]

        cls.lib = None
        lib_path = ""
        for p in search_paths:
            for name in lib_names:
                full_path = os.path.join(p, name)
                if os.path.exists(full_path):
                    lib_path = os.path.abspath(full_path)
                    print(f"   [Debug] Found library at: {lib_path}")
                    break
            if lib_path: break

        if not lib_path:
            # 打印搜索路径方便调试
            print(f"   [Error] Searched in: {search_paths}")
            raise RuntimeError("Cannot find core library! Please build first.")

        try:
            cls.lib = ctypes.cdll.LoadLibrary(lib_path)
        except OSError as e:
            raise RuntimeError(f"Found library but failed to load: {e}")

        # 设置函数参数类型
        cls.lib.C_PackWithFilter.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_int, ctypes.POINTER(CFilter), ctypes.c_int
        ]
        cls.lib.C_Unpack.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

    # [每个测试前] 准备干净的临时目录
    def setUp(self):
        # 同样使用绝对路径，确保临时文件夹生成在项目根目录下，而不是 tests 目录下
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)

        self.test_dir = os.path.join(project_root, "temp_test_env")

        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        os.makedirs(self.test_dir)

        self.src_dir = os.path.join(self.test_dir, "src")
        self.out_dir = os.path.join(self.test_dir, "out")
        os.makedirs(self.src_dir)
        os.makedirs(self.out_dir)

    # [每个测试后] 清理垃圾
    def tearDown(self):
        """
        # 为了调试方便，如果想看现场，可以注释掉这行
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir)
            except:
                pass # Windows 有时候文件占用删不掉，忽略
        """
        print(f"   [Debug] Files kept in: {self.test_dir}") # 提示一下位置

    # --- 辅助函数：创建文件 ---
    def create_dummy_file(self, name, content=b"data"):
        path = os.path.join(self.src_dir, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    # ==========================================
    # 测试用例 (Test Cases)
    # ==========================================

    def test_01_rle_compression(self):
        """rle RLE 压缩率：1000字节应被大幅压缩"""
        # 1. 准备数据: 1000个 'A'
        self.create_dummy_file("heavy.txt", b"A" * 1000)
        pck_path = os.path.join(self.test_dir, "test.pck")

        # 2. 调用打包: No Enc(0), RLE(1)
        res = self.lib.C_PackWithFilter(
            self.src_dir.encode(), pck_path.encode(), b"", 0, None, 1
        )
        self.assertEqual(res, 1, "Pack function should return 1 (Success)")

        # 3. 验证压缩效果
        size = os.path.getsize(pck_path)
        print(f"\n   [RLE] Original: 1000 -> Compressed: {size}")
        self.assertLess(size, 500, "RLE compression failed to reduce size significantly")

        # 4. 验证解压内容
        self.lib.C_Unpack(pck_path.encode(), self.out_dir.encode(), b"")
        with open(os.path.join(self.out_dir, "heavy.txt"), "rb") as f:
            self.assertEqual(f.read(), b"A" * 1000, "Decompressed content mismatch")

    def test_02_rc4_encryption(self):
        """rle RC4 加密：文件头检查与内容保护"""
        self.create_dummy_file("secret.txt", b"MySecretData")
        pck_path = os.path.join(self.test_dir, "enc.pck")
        pwd = b"123456"

        # 打包: RC4(2), No Comp(0)
        self.lib.C_PackWithFilter(
            self.src_dir.encode(), pck_path.encode(), pwd, 2, None, 0
        )

        # 验证 Magic Number
        with open(pck_path, "rb") as f:
            header = f.read(8)
            self.assertEqual(header, b"MINIBK_R", "Wrong Header Magic for RC4")

        # 验证解包
        self.lib.C_Unpack(pck_path.encode(), self.out_dir.encode(), pwd)
        self.assertTrue(os.path.exists(os.path.join(self.out_dir, "secret.txt")))

    def test_03_filter_logic(self):
        """测试筛选器：只备份 .txt 文件"""
        self.create_dummy_file("keep.txt", b"text")
        self.create_dummy_file("skip.jpg", b"image")
        pck_path = os.path.join(self.test_dir, "filter.pck")

        # 构造 Filter
        f = CFilter()
        f.nameContains = b".txt"
        f.type = -1; f.minSize=0; f.maxSize=0; f.startTime=0; f.targetUid=-1

        self.lib.C_PackWithFilter(
            self.src_dir.encode(), pck_path.encode(), b"", 0, ctypes.byref(f), 0
        )

        self.lib.C_Unpack(pck_path.encode(), self.out_dir.encode(), b"")

        self.assertTrue(os.path.exists(os.path.join(self.out_dir, "keep.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.out_dir, "skip.jpg")))

    def test_04_metadata_restore(self):
        """测试元数据：时间戳还原"""
        path = self.create_dummy_file("old.txt", b"data")
        # 修改时间到 2020-01-01
        old_time = 1577836800
        os.utime(path, (old_time, old_time))

        pck_path = os.path.join(self.test_dir, "meta.pck")
        self.lib.C_PackWithFilter(self.src_dir.encode(), pck_path.encode(), b"", 0, None, 0)

        # 确保时间流逝
        time.sleep(1.1)

        self.lib.C_Unpack(pck_path.encode(), self.out_dir.encode(), b"")

        restored_path = os.path.join(self.out_dir, "old.txt")
        restored_time = os.path.getmtime(restored_path)

        # 允许 2 秒误差
        self.assertAlmostEqual(restored_time, old_time, delta=2, msg="Mtime not restored")

    def test_05_complex_scenario(self):
        """[综合测试] 复杂目录结构 + 混合文件 + RLE压缩 + RC4加密"""
        print("\n   [Complex] Generating nested directory structure...")

        # 1. 构建复杂的源目录结构
        # structure:
        # src/
        #  ├── root.txt          (普通文本)
        #  ├── empty.dat         (空文件)
        #  ├── images/           (子目录)
        #  │    └── logo.png     (伪造的二进制数据)
        #  └── deep/
        #       └── nested/
        #            └── code.cpp (深层文件)

        # 创建目录
        os.makedirs(os.path.join(self.src_dir, "images"), exist_ok=True)
        os.makedirs(os.path.join(self.src_dir, "deep", "nested"), exist_ok=True)

        # 创建文件 A: 普通文本
        with open(os.path.join(self.src_dir, "root.txt"), "wb") as f:
            f.write(b"Hello World " * 100) # 重复文本，适合压缩

        # 创建文件 B: 空文件
        with open(os.path.join(self.src_dir, "empty.dat"), "wb") as f:
            pass

            # 创建文件 C: 伪二进制文件 (模拟图片，随机性高，难压缩)
        # 这里手动写入一些不可见字符
        binary_data = b"\x89PNG\r\n\x1a\n" + b"\x00\xFF\x12\x34" * 50
        with open(os.path.join(self.src_dir, "images", "logo.png"), "wb") as f:
            f.write(binary_data)

        # 创建文件 D: 深层文件
        with open(os.path.join(self.src_dir, "deep", "nested", "code.cpp"), "wb") as f:
            f.write(b"#include <iostream>\nint main() { return 0; }")

        pck_path = os.path.join(self.test_dir, "complex.pck")
        pwd = b"SuperHardPwd"

        # 2. 执行打包 (难度全开)
        # Encrypt: RC4 (2)
        # Filter: None
        # Compress: RLE (1)
        print("   [Complex] Packing with RC4 + RLE...")
        res = self.lib.C_PackWithFilter(
            self.src_dir.encode(), pck_path.encode(), pwd, 2, None, 1
        )
        self.assertEqual(res, 1, "Pack failed in complex scenario")

        # 3. 执行解包
        print("   [Complex] Unpacking...")
        self.lib.C_Unpack(pck_path.encode(), self.out_dir.encode(), pwd)

        # 4. 逐一验证所有文件

        # 验证 A (文本内容)
        with open(os.path.join(self.out_dir, "root.txt"), "rb") as f:
            self.assertEqual(f.read(), b"Hello World " * 100)

        # 验证 B (空文件存在且大小为0)
        empty_path = os.path.join(self.out_dir, "empty.dat")
        self.assertTrue(os.path.exists(empty_path))
        self.assertEqual(os.path.getsize(empty_path), 0)

        # 验证 C (二进制内容)
        with open(os.path.join(self.out_dir, "images", "logo.png"), "rb") as f:
            self.assertEqual(f.read(), binary_data)

        # 验证 D (深层目录结构)
        deep_path = os.path.join(self.out_dir, "deep", "nested", "code.cpp")
        self.assertTrue(os.path.exists(deep_path))
        with open(deep_path, "rb") as f:
            self.assertTrue(b"#include" in f.read())

    def test_verify_alignment_explicitly(self):
        """🔍 专门用于验证内存对齐的测试：发送特殊数值"""
        print("\n=== [Alignment Test] Sending Magic Numbers ===")
        pck_path = os.path.join(self.test_dir, "align_test.pck")

        # 构造 Filter，填入特殊数字
        f = CFilter()
        f.nameContains = None
        f.pathContains = None
        f.type = -1
        f.minSize = 12345      # <--- 魔法数字 1
        f.maxSize = 999999     # <--- 魔法数字 2
        f.startTime = 88888888 # <--- 魔法数字 3
        f.targetUid = -1

        # 调用 C++，我们主要看控制台的打印
        self.lib.C_PackWithFilter(
            self.src_dir.encode(), pck_path.encode(), b"", 0, ctypes.byref(f), 0
        )
        print("=== [Alignment Test] End ===\n")

if __name__ == "__main__":
    unittest.main(verbosity=2)