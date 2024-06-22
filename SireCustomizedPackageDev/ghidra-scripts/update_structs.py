# TODO write a description for this script
# @author
# @category Python 3
# @keybinding
# @menupath
# @toolbar


import os
import time
from dataclasses import dataclass

from ghidra.program.model.data import (
    ArrayDataType,
    BitFieldDataType,
    ByteDataType,
    CategoryPath,
    DataTypeConflictHandler,
    StructureDataType,
    Undefined,
)
from java.io import File
from javax.swing import JFileChooser


def get_now_time():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def format_address(addr: int) -> str:
    """格式化地址"""
    return f"{addr:08X}"


# 为字段名清洗
def clean_field_name(name: str) -> str:
    # 去掉 name 中不能作为结构体成员名的字符
    # fmt: off
    illegal_chars = [" ", "/", ".", ":", "(", ")", "[", "]", "{", "}", "<", ">",
                        ",", ";", "'", "\"", "`", "~", "!", "@", "#", "$", "%", "^",
                        "&", "*", "-", "+", "=", "?", "|", "\\", "～"]
    # fmt: on
    for char in illegal_chars:
        name = name.replace(char, "_")

    return name


def choose_files():
    # 获取脚本所在目录
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # 创建一个文件选择器
    file_chooser = JFileChooser()

    # 设置文件选择模式，可以是 FILES_ONLY, DIRECTORIES_ONLY, FILES_AND_DIRECTORIES
    file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)

    # 启用多选模式
    file_chooser.setMultiSelectionEnabled(True)

    # 设置初始目录为脚本所在目录
    file_chooser.setCurrentDirectory(File(script_dir))

    # 显示打开文件对话框
    result = file_chooser.showOpenDialog(None)

    # 如果用户选择了一个或多个文件
    if result == JFileChooser.APPROVE_OPTION:
        selected_files = file_chooser.getSelectedFiles()
        file_paths = [file.getAbsolutePath() for file in selected_files]
        print("Selected files:")
        for file_path in file_paths:
            print(file_path)
        return file_paths
    else:
        print("File selection canceled.")
        return None


# 获取当前程序的数据类型管理器
data_type_manager = currentProgram().getDataTypeManager()


@dataclass
class StructField:
    offset: int
    size: int
    data_type: str
    name: str
    comment: str

    _is_array: bool = False
    _is_bit: bool = False

    @classmethod
    def from_tuple(cls, tup: tuple[int, int, str, str, str]):
        if len(tup) == 5:
            offset, size, data_type, field_name, field_comment = tup
            if field_name:
                field_name = f"fld_{offset:X}_{field_name}"
            else:
                field_name = f"fld_{offset:X}"
            field_name = clean_field_name(field_name)
            ret = cls(offset, size, data_type, field_name, field_comment)
        else:
            raise ValueError(f"Invalid tuple: {tup}")
        ret._is_array = "[" in ret.data_type
        ret._is_bit = "bit" in ret.data_type
        return ret

    @classmethod
    def from_table_line(cls, line: str):
        """从形如："| +00    | 4      | pointer32 | 宝物相关函数所在地址 | (68 C5 79 00) |" 的 markdown 表格行创建结构体字段"""

        tup = line.strip().strip("|").split("|")
        if len(tup) == 5:
            offset, size, data_type, field_name, field_comment = tup
            offset = int(offset, 16)
            size = int(size)
            data_type = data_type.strip()
            field_name = field_name.strip()
            field_comment = field_comment.strip()
            return cls.from_tuple((offset, size, data_type, field_name, field_comment))
        raise ValueError(f"Invalid table line: {line}")

    def is_array(self):
        return self._is_array

    def is_bit(self):
        return self._is_bit

    def get_true_data_type(self):
        dt_str = self.data_type
        if "[" in self.data_type:
            dt_str = self.data_type.split("[")[0]

        sz = self.size
        if self.is_bit():  # not working now
            return BitFieldDataType(ByteDataType.dataType, sz)

        if self.is_array():
            ele_dt = data_type_manager.getDataType(f"/{dt_str}")
            ele_num = int(self.data_type.split("[")[-1].split("]")[0])
            return ArrayDataType(ele_dt, ele_num)

        if dt_str:
            dt = data_type_manager.getDataType(f"/{dt_str}")
            if dt:
                return dt

        if sz == 1:
            return data_type_manager.getDataType("/byte")
        elif sz == 2:
            return data_type_manager.getDataType("/short")
        elif sz == 4:
            return data_type_manager.getDataType("/int")

        return Undefined.getUndefinedDataType(sz)


@dataclass
class Struct:
    name: str
    name_zh: str
    fields: list[StructField]
    size: int
    comment: str
    array_start_addrs: list[str]
    array_end_addrs: list[str]
    array_sizes: list[int]
    array_updated: bool = False

    _file_path: str = ""
    _last_updated: str = ""

    @classmethod
    def from_file(cls, file_path: str):
        name = ""
        name_zh = ""
        fields = []
        size = 0
        comment = ""
        array_start_addrs = []
        array_end_addrs = []
        array_sizes = []
        array_updated = False

        with open(file_path, "r", encoding="utf-8") as file:
            field_line_started = False
            for line in file:
                # 跳过空行
                if not line.strip():
                    continue
                # 处理特殊行
                if line.startswith("#"):
                    if line.startswith("# struct_name_zh:"):
                        name_zh = line.split(":")[-1].strip()
                    elif line.startswith("# struct_name:"):
                        name = line.split(":")[-1].strip()
                    elif line.startswith("# struct_size:"):
                        sz = line.split(":")[-1].strip()
                        size = int(sz, 16) if sz.startswith("0x") else int(sz)
                    elif line.startswith("# array_start_addrs:"):
                        array_start_addrs = list(map(lambda x: int(x, 16), line.split(":")[-1].strip().split(",")))
                    elif line.startswith("# array_end_addrs:"):
                        array_end_addrs = list(map(lambda x: int(x, 16), line.split(":")[-1].strip().split(",")))
                    elif line.startswith("# array_sizes:"):
                        array_sizes = list(map(int, line.split(":")[-1].strip().split(",")))
                    elif line.startswith("# array_updated:"):
                        _array_updated = line.split(":")[-1].strip().lower() in ("true", "1")
                    continue
                # 处理字段行
                if not field_line_started and line.startswith("| ------"):
                    field_line_started = True
                    continue
                if field_line_started:
                    field = StructField.from_table_line(line)
                    fields.append(field)

        if not name or size == 0:
            raise ValueError(f"Invalid struct: {file_path}")

        ret = cls(name, name_zh, fields, size, comment, array_start_addrs, array_end_addrs, array_sizes, array_updated)
        ret._file_path = file_path
        ret._last_updated = get_now_time()
        if not ret.comment:
            ret.comment = f"{ret.name_zh}. 最后更新：{ret._last_updated}"

        return ret

    def update_file(self):
        """更新文件"""
        with open(self._file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            for i, line in enumerate(lines):
                if line.startswith("# array_end_addrs:"):
                    lines[i] = f"# array_end_addrs: {','.join(map(format_address, self.array_end_addrs))}\n"
                if line.startswith("# array_sizes:"):
                    lines[i] = f"# array_sizes: {','.join(map(str, self.array_sizes))}\n"
                if line.startswith("# array_updated:"):
                    lines[i] = f"# array_updated: {self.array_updated}\n"
                if line.startswith("# last_update:"):
                    lines[i] = f"# last_update: {self._last_updated}\n"

        with open(self._file_path, "w", encoding="utf-8") as file:
            file.writelines(lines)


def create_or_replace_struct(st: Struct):
    struct_name = st.name
    struct_fields = st.fields
    struct_size = st.size
    struct_comment = st.comment

    # 定义结构体名称和路径
    category_path = CategoryPath("/_san11")

    # 创建新的结构体数据类型
    struct = StructureDataType(category_path, struct_name, struct_size)

    # 添加字段到结构体
    for fld in struct_fields:
        try:
            struct.replaceAtOffset(fld.offset, fld.get_true_data_type(), fld.size, fld.name, fld.comment)
        except Exception as e:
            print(f"Error adding field '{fld}' to struct '{struct_name}': {e}")
            raise e

    # 开始事务以进行数据类型管理操作
    transaction_id = data_type_manager.startTransaction("Create or Replace Struct")

    try:
        # 添加结构体到数据类型管理器
        struct = data_type_manager.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)

        # 校验结构体大小
        if struct_size and struct.getLength() != struct_size:
            raise ValueError(f"Struct size mismatch: expected {struct_size}, got {struct.getLength()}")

        # 添加注释
        if struct_comment:
            struct.setDescription(struct_comment)

        # 应用结构体到特定地址
        # for start_addr, end_addr, array_size in zip(start_addrs, end_addrs, array_sizes):
        #     start_address = toAddr(start_addr)
        #     end_address = toAddr(end_addr)
        #     apply_data_struct(start_address, end_address, struct, array_size)

    finally:
        # 结束事务
        data_type_manager.endTransaction(transaction_id, True)

    print(f"Structure '{struct_name}' created/replaced successfully!")


# def apply_data_struct(start_address, end_address, struct, array_size):
#     # 获取当前程序的 listing
#     listing = currentProgram().getListing()

#     # 应用结构体到指定地址
#     for i in range(array_size):
#         address = start_address.add(i * struct.getLength())
#         if address.compareTo(end_address) <= 0:
#             data = listing.getDataAt(address)
#             if data:
#                 listing.clearCodeUnits(address, address.add(struct.getLength()), False)
#             create_data(address, struct)


def main():
    # 调用函数调出文件选择对话框
    selected_files = choose_files()

    for file_path in selected_files:
        print(f"Processing file: {file_path}")
        st = Struct.from_file(file_path)

        create_or_replace_struct(st)

        st.update_file()

    # st = {
    #     "struct_name": "MyUpdatedStruct",  # 结构体名
    #     "struct_name_zh": "更新的结构体",  # 结构体中文名
    #     "struct_fields": [  # 字段信息: (offset, nbytes, data_type, field_name, field_comment)
    #         (0, 4, "int", "field1", "This is field 1"),
    #         (4, 2, "short", "field2", "This is field 2"),
    #         (6, 1, "byte", "field3", "This is field 3"),
    #         (7, 1, "byte", "", "This is an unnamed field"),  # 没有字段名称
    #         (8, 4, "long", "field5", "This is field 5"),  # 新增字段
    #     ],
    #     "struct_size": 16,  # 结构体大小
    #     "struct_comment": "This is an updated test struct",  # 结构体注释
    #     "start_addrs": ["0x1000", "0x2000"],  # 结构体数组的起始地址
    #     "end_addrs": ["0x100F", "0x200F"],  # 结构体数组的结束地址
    #     "array_sizes": [4, 2],  # 数组大小
    # }
    # create_or_replace_struct(st)


main()
