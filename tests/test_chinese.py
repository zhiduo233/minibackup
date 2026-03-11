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
        ("_pad", ctypes.c_int), # [修正1] 必须加上 padding，与 C++ 保持一致
        ("minSize", ctypes.c_ulonglong),
        ("maxSize", ctypes.c_ulonglong),
        ("startTime", ctypes.c_longlong),
        ("targetUid", ctypes.c_int)
    ]

class TestChinesePath(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n[Setup] Loading Core Library...")

        # 1. 获取当前脚本所在的目录
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # 2. 获取项目根目录
        project_root = os.path.dirname(current_dir)

        print(f"   [Debug] Project Root identified as: {project_root}")

        lib_names = ["core.dll", "libcore.dll", "libcore.so", "libcore.dylib"]
        search_paths = [
            os.path.join(project_root, "cmake-build-debug"),
            os.path.join(project_root, "build_win"),
            os.path.join(project_root, "build"),
            project_root,
            os.path.join(project_root, "bin")
        ]

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
            raise RuntimeError("Cannot find core library! Please build first.")

        cls.lib = ctypes.cdll.LoadLibrary(lib_path)

        # 设置函数参数类型
        cls.lib.C_PackWithFilter.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_int, ctypes.POINTER(CFilter), ctypes.c_int
        ]
        cls.lib.C_Unpack.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

    def setUp(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)

        # 定义 self.test_dir
        self.test_dir = os.path.join(project_root, "temp_test_env")

        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        os.makedirs(self.test_dir)

        self.src_dir = os.path.join(self.test_dir, "src")
        self.out_dir = os.path.join(self.test_dir, "out")
        os.makedirs(self.src_dir)
        os.makedirs(self.out_dir)

    def tearDown(self):
        # 调试时保留文件
        # if os.path.exists(self.test_dir):
        #    try: shutil.rmtree(self.test_dir)
        #    except: pass
        pass

    def test_full_chinese_support(self):
        """测试：中文目录 + 中文文件名 + 中文内容 + 中文包名"""

        print("\n   [Test] Starting Chinese Path Verification...")

        # 1. 定义中文路径变量
        src_dir_name = "源数据_目录"
        file_name = "重要文档.txt"
        content = "你好，世界！这是测试内容。"
        pck_name = "我的备份.pck"
        restore_dir_name = "还原_结果"

        # [修正2] 使用 self.test_dir 而不是 self.test_root
        src_full = os.path.join(self.test_dir, src_dir_name)
        file_full = os.path.join(src_full, file_name)
        pck_full = os.path.join(self.test_dir, pck_name)
        restore_full = os.path.join(self.test_dir, restore_dir_name)

        # 2. 创建物理环境
        os.makedirs(src_full, exist_ok=True)
        with open(file_full, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"   Created file: {file_full}")

        # 3. 执行打包 (Pack)
        print("   Action: Packing...")
        res_pack = self.lib.C_PackWithFilter(
            src_full.encode('utf-8'),
            pck_full.encode('utf-8'),
            b"",
            0,
            None,
            0
        )

        self.assertEqual(res_pack, 1, "Pack failed!")
        self.assertTrue(os.path.exists(pck_full), "Pack file not created!")
        print(f"   ✅ Pack success: {pck_name}")

        # 4. 执行解包 (Unpack)
        print("   Action: Unpacking...")
        res_unpack = self.lib.C_Unpack(
            pck_full.encode('utf-8'),
            restore_full.encode('utf-8'),
            b""
        )

        self.assertEqual(res_unpack, 1, "Unpack failed!")
        print(f"   ✅ Unpack success to: {restore_dir_name}")

        # 5. 验证结果

        # 尝试直接拼接
        restored_file_path = os.path.join(restore_full, file_name)

        # 如果找不到，可能是因为打包时包含了顶层目录名
        if not os.path.exists(restored_file_path):
            restored_file_path = os.path.join(restore_full, src_dir_name, file_name)

        self.assertTrue(os.path.exists(restored_file_path), f"Restored file not found at: {restored_file_path}")

        # 验证内容
        with open(restored_file_path, "r", encoding="utf-8") as f:
            read_content = f.read()

        self.assertEqual(read_content, content, "Content mismatch!")
        print(f"   ✅ Content verified: {read_content}")

if __name__ == "__main__":
    unittest.main()