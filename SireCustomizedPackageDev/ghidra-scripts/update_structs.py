# 更新 Ghidra 中的结构体定义和数组
# @author
# @category Python 3
# @keybinding
# @menupath
# @toolbar


import os
import time
from dataclasses import dataclass

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import (
    ArrayDataType,
    BitFieldDataType,
    ByteDataType,
    CategoryPath,
    DataTypeConflictHandler,
    StructureDataType,
    Undefined,
)
from ghidra.program.model.listing import CodeUnit
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


started_selection_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "structs")


def choose_files():

    # 创建一个文件选择器
    file_chooser = JFileChooser()

    # 设置文件选择模式，可以是 FILES_ONLY, DIRECTORIES_ONLY, FILES_AND_DIRECTORIES
    file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)

    # 启用多选模式
    file_chooser.setMultiSelectionEnabled(True)

    # 设置初始目录为脚本所在目录
    file_chooser.setCurrentDirectory(File(started_selection_path))

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
        return []


# 获取当前程序的数据类型管理器
data_type_manager = currentProgram().getDataTypeManager()

# 获取当前程序的 listing
listing = currentProgram().getListing()

memory = currentProgram().getMemory()

fpapi = FlatProgramAPI(currentProgram())


def get_4_bytes(addr):
    return tuple(memory.getByte(addr.add(i)) for i in range(4))  # 4 bytes


def find_struct_array_size(start_addr, struct_size):
    flag_value = get_4_bytes(start_addr)
    cur_addr = start_addr.add(struct_size)
    item_cnt = 1
    while True:
        cur_flag_value = get_4_bytes(cur_addr)
        if cur_flag_value != flag_value:
            break
        item_cnt += 1
        cur_addr = cur_addr.add(struct_size)
    return item_cnt


def apply_structure_to_memory(struct, start_address):
    # 计算结构体大小
    struct_size = struct.getLength()

    # 计算结束地址
    end_address = start_address.add(struct_size - 1)

    # 清除目标地址范围内的现有数据
    listing.clearCodeUnits(start_address, end_address, False)

    # 应用结构体到内存
    try:
        listing.createData(start_address, struct)
        print(f"Structure applied at {start_address}")
    except Exception as e:
        print(f"Error applying structure: {e} at {start_address}")


def apply_struct_array_to_memory(struct, start_address, array_size):
    # 计算结构体大小
    struct_size = struct.getLength()

    # 创建结构体数组数据类型
    array_data_type = ArrayDataType(struct, array_size, struct_size)

    # 计算结束地址
    end_address = start_address.add(array_data_type.getLength() - 1)

    # 清除目标地址范围内的现有数据
    listing.clearCodeUnits(start_address, end_address, False)

    # 应用结构体数组到内存
    try:
        listing.createData(start_address, array_data_type)
        print(f"Structure array applied at {start_address}")
    except Exception as e:
        print(f"Error applying structure array: {e}")


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

    def get_ghidra_data_type(self):
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
    array_start_addrs: list[int]
    array_end_addrs: list[int]
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
                        s = line.split(":")[-1].strip()
                        if s:
                            array_start_addrs = list(map(lambda x: int(x, 16), s.split(",")))
                    elif line.startswith("# array_end_addrs:"):
                        s = line.split(":")[-1].strip()
                        if s:
                            array_end_addrs = list(map(lambda x: int(x, 16), s.split(",")))
                    elif line.startswith("# array_sizes:"):
                        s = line.split(":")[-1].strip()
                        if s:
                            array_sizes = list(map(int, s.split(",")))
                    elif line.startswith("# array_updated:"):
                        array_updated = line.split(":")[-1].strip().lower() in ("true", "1")
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

        if len(array_start_addrs) != len(array_end_addrs):
            array_end_addrs = []  # reset array_end_addrs

        if len(array_start_addrs) != len(array_sizes):
            array_sizes = []  # reset array_sizes

        ret = cls(name, name_zh, fields, size, comment, array_start_addrs, array_end_addrs, array_sizes, array_updated)
        ret._file_path = file_path
        ret._last_updated = get_now_time()
        if not ret.comment:
            ret.comment = f"{ret.name_zh}. 最后更新：{ret._last_updated}"

        return ret

    def update_in_ghidra(self):
        """在 Ghidra 中更新结构体"""

        struct_name = self.name
        struct_fields = self.fields
        struct_size = self.size
        struct_comment = self.comment

        # 定义结构体名称和路径
        category_path = CategoryPath("/_san11")

        # 创建新的结构体数据类型
        struct = StructureDataType(category_path, struct_name, struct_size)

        # 添加字段到结构体
        for fld in struct_fields:
            try:
                struct.replaceAtOffset(fld.offset, fld.get_ghidra_data_type(), fld.size, fld.name, fld.comment)
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
            if not self.array_updated:
                self.update_array_in_ghidra(struct)
                self.array_updated = True
                print(f"Array updated for struct '{struct_name}'")
            else:
                print(f"Array already updated for struct '{struct_name}', skipping...")

        finally:
            # 结束事务
            data_type_manager.endTransaction(transaction_id, True)

        print(f"Structure '{struct_name}' created/replaced successfully!")

    def update_array_in_ghidra(self, struct):
        """在 Ghidra 中更新结构体对应的数组"""
        for i, array_start_addr in enumerate(self.array_start_addrs):
            if len(self.array_end_addrs) > i:
                array_end_addr = self.array_end_addrs[i]
                array_size = (array_end_addr - array_start_addr) // self.size
                if len(self.array_sizes) > i:
                    self.array_sizes[i] = array_size
                else:
                    self.array_sizes.append(array_size)
            elif len(self.array_sizes) > i:
                array_size = self.array_sizes[i]
                if len(self.array_end_addrs) > i:
                    self.array_end_addrs[i] = array_start_addr + array_size * self.size
                else:
                    self.array_end_addrs.append(array_start_addr + array_size * self.size)
            else:  # 仅提供了起始地址，需自行查找 end_addr 和 array_size
                # 大部分结构体第一个字段是指向该类结构体函数的指针，可根据这个特征来查找数组的结束地址
                # 如果不是该特征，则无法自动查找结束地址，需要手动指定
                array_size = find_struct_array_size(toAddr(array_start_addr), self.size)
                self.array_end_addrs.append(array_start_addr + array_size * self.size)
                self.array_sizes.append(array_size)

            apply_struct_array_to_memory(struct, toAddr(array_start_addr), array_size)

            # 创建数组标签
            array_name = self.name_zh + "数组"
            if i > 0:
                array_name += f"_{i + 1}"
            fpapi.createLabel(toAddr(array_start_addr), array_name, True)

            # 给数组添加注释
            array_comment = f"{self.name_zh}数组。数组大小：{array_size}, 结构体大小：0x{self.size:x}。"
            listing.setComment(toAddr(array_start_addr), CodeUnit.PLATE_COMMENT, array_comment)

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


def main():
    # 调用函数调出文件选择对话框
    selected_files = choose_files()

    for file_path in selected_files:
        print(f"Processing file: {file_path}")
        st = Struct.from_file(file_path)

        st.update_in_ghidra()

        st.update_file()


main()
