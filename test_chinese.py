import unittest
import ctypes
import os
import shutil
import platform

# ==========================================
# 1. 基础配置 (C 结构体与库加载)
# ==========================================
class CFilter(ctypes.Structure):
    _fields_ = [
        ("nameContains", ctypes.c_char_p),
        ("pathContains", ctypes.c_char_p),
        ("type", ctypes.c_int),
        ("minSize", ctypes.c_ulonglong),
        ("maxSize", ctypes.c_ulonglong),
        ("startTime", ctypes.c_longlong),
        ("targetUid", ctypes.c_int)
    ]

class TestChinesePath(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n[Setup] Loading Core Library for Chinese Test...")
        # 自动查找 DLL/SO
        lib_names = ["core.dll", "libcore.dll", "libcore.so", "libcore.dylib"]
        search_paths = ["./cmake-build-debug", "./build_win", "./build", "."]

        cls.lib = None
        lib_path = ""
        for p in search_paths:
            for name in lib_names:
                full_path = os.path.join(p, name)
                if os.path.exists(full_path):
                    lib_path = os.path.abspath(full_path)
                    break
            if lib_path: break

        if not lib_path:
            raise RuntimeError("❌ Cannot find core library! Please build first.")

        print(f"   Library found: {lib_path}")
        cls.lib = ctypes.cdll.LoadLibrary(lib_path)

        # 设置函数参数类型
        cls.lib.C_PackWithFilter.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_int, ctypes.POINTER(CFilter), ctypes.c_int
        ]
        cls.lib.C_Unpack.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

    def setUp(self):
        # 创建一个带有中文名字的临时测试根目录
        self.test_root = "测试环境_Temp"
        if os.path.exists(self.test_root):
            shutil.rmtree(self.test_root)
        os.makedirs(self.test_root)

    def tearDown(self):
        # 测试完成后清理，如果你想看结果文件，可以注释掉下面这行
        """
        if os.path.exists(self.test_root):
            try:
                shutil.rmtree(self.test_root)
            except:
                pass
        """

    def test_full_chinese_support(self):
        """测试：中文目录 + 中文文件名 + 中文内容 + 中文包名"""

        print("\n   [Test] Starting Chinese Path Verification...")

        # 1. 定义中文路径变量
        # -------------------------------------------
        src_dir_name = "源数据_目录"
        file_name = "重要文档.txt"
        content = "你好，世界！这是测试内容。"
        pck_name = "我的备份.pck"
        restore_dir_name = "还原_结果"

        # 拼接绝对路径
        src_full = os.path.join(self.test_root, src_dir_name)
        file_full = os.path.join(src_full, file_name)
        pck_full = os.path.join(self.test_root, pck_name)
        restore_full = os.path.join(self.test_root, restore_dir_name)

        # 2. 创建物理环境
        # -------------------------------------------
        os.makedirs(src_full, exist_ok=True)
        with open(file_full, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"   Created file: {file_full}")

        # 3. 执行打包 (Pack)
        # -------------------------------------------
        # 关键点：所有路径都要 .encode('utf-8')
        print("   Action: Packing...")
        res_pack = self.lib.C_PackWithFilter(
            src_full.encode('utf-8'),
            pck_full.encode('utf-8'),
            b"",    # 无密码
            0,      # 无加密
            None,   # 无筛选
            0       # RLE 压缩
        )

        self.assertEqual(res_pack, 1, "Pack failed!")
        self.assertTrue(os.path.exists(pck_full), "Pack file not created!")
        print(f"   ✅ Pack success: {pck_name}")

        # 4. 执行解包 (Unpack)
        # -------------------------------------------
        print("   Action: Unpacking...")
        res_unpack = self.lib.C_Unpack(
            pck_full.encode('utf-8'),
            restore_full.encode('utf-8'),
            b""
        )

        self.assertEqual(res_unpack, 1, "Unpack failed!")
        print(f"   ✅ Unpack success to: {restore_dir_name}")

        # 5. 验证结果
        # -------------------------------------------
        # 检查还原后的文件路径是否存在
        restored_file_path = os.path.join(restore_full, file_name) # 如果是单文件备份，逻辑可能略有不同，这里假设是目录备份

        # 注意：如果刚才你是备份整个目录，解压出来通常会包含相对路径
        # 在我们的逻辑里，scanDirectory 产生的 relPath 是相对于 src_full 的
        # 所以解压后应该是 restore_full/重要文档.txt

        if not os.path.exists(restored_file_path):
            # 尝试另一种可能性：如果是目录递归，可能多一层
            pass

        self.assertTrue(os.path.exists(restored_file_path), f"Restored file not found: {restored_file_path}")

        # 验证内容是否乱码
        with open(restored_file_path, "r", encoding="utf-8") as f:
            read_content = f.read()

        self.assertEqual(read_content, content, "Content mismatch! (Possible encoding issue)")
        print(f"   ✅ Content verified: {read_content}")

if __name__ == "__main__":
    unittest.main()