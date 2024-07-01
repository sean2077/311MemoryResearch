"""
san11pk's IDA Struct Tool
"""

import os
from dataclasses import dataclass
from datetime import datetime

import idaapi
import idc

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

STRUCTS_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "material", "structs")


##########################################################################
###                               Utils                                ###
##########################################################################


def get_now_time() -> str:
    """获取当前时间，形如 2020-06-06 14:00:00"""
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")


def format_address(addr: int) -> str:
    """格式化地址"""
    return f"{addr:08x}"


def ask_file_paths() -> list[str]:
    file_paths = []

    button = idaapi.ask_buttons("All", "One", "Cancel", 0, "Select all or one file")
    if button == 1:
        for fp in os.listdir(STRUCTS_DIR):
            if fp.endswith(".md"):
                file_paths.append(os.path.join(STRUCTS_DIR, fp))
    elif button == 0:
        file_path = idaapi.ask_file(False, "*.md", "Please select a struct defining file.")
        if file_path:
            file_paths.append(file_path)
    if not file_paths:
        idaapi.msg("No file selected.\n")

    return file_paths


##########################################################################
###                           结构体相关                                ###
##########################################################################


@dataclass
class StructField:
    offset: int
    size: int  # 字段大小
    data_type: str
    name: str
    comment: str

    _is_array: bool = False
    _is_ptr: bool = False
    _data_flags: int = 0
    _pure_data_type: str = ""  # 去掉 [] 和 * 的 data_type

    @classmethod
    def from_table_row(cls, row: str):  # | offset | nbytes | data_type | field_name | field_comment |
        items = row.strip().strip("|").split("|")
        if len(items) != 5:
            raise ValueError(f"Invalid table line: {row}")

        offset, size, data_type, field_name, field_comment = items
        offset = int(offset, 16)
        size = int(size)
        data_type = data_type.strip()
        field_name = field_name.strip()
        if field_name:
            field_name = f"fld_{offset:X}_{field_name}"
        else:
            field_name = f"fld_{offset:X}"
        field_comment = field_comment.strip()

        ret = cls(offset, size, data_type, field_name, field_comment)
        ret._is_array = "[" in ret.data_type
        ret._is_ptr = ret.data_type in ("pointer", "address", "pointer32") or "*" in ret.data_type
        ret._data_flags = _get_data_flags(ret)
        ret._pure_data_type = _get_pure_data_type(ret.data_type)

        return ret


def _get_pure_data_type(data_type: str) -> str:
    """获取去掉 [], *, () 的 data_type"""
    return data_type.split("[")[0].split("*")[0].split("(")[0].strip()


def _get_data_flags(fld: StructField):
    if fld._is_ptr:
        return idaapi.FF_DWORD | idaapi.FF_1OFF | idaapi.FF_DATA
        # FF_1OFF 表示 "First Offset"（第一个偏移量）。这个标志通常用于表示一个数据成员应该被解释为一个偏移量或指针。

    dt_str = fld._pure_data_type

    if dt_str in ("byte", "char", "uchar"):
        return idaapi.byte_flag()

    if dt_str in ("word", "short", "ushort"):
        return idaapi.word_flag()

    if dt_str in ("dword", "int", "uint"):
        return idaapi.dword_flag()

    if dt_str in ("float",):
        return idaapi.float_flag()

    if dt_str in ("string",):
        return idaapi.strlit_flag()

    if dt_str.startswith("struct_"):
        return idaapi.stru_flag()

    return 0  # 其他类型用不到 flag


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
    id: int = -1

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
        struct_id = -1

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
                    elif line.startswith("# struct_id:"):
                        s = line.split(":")[-1].strip()
                        if s:
                            struct_id = int(s, 16)
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
                if not field_line_started and any(line.startswith(x) for x in ("| ---", "|--", "| :--", "|:--")):
                    field_line_started = True
                    continue
                if field_line_started:
                    field = StructField.from_table_row(line)
                    fields.append(field)

        if not name or size == 0:
            raise ValueError(f"Invalid struct: {file_path}")

        if not comment:
            comment = f"{name_zh}. 最后更新：{get_now_time()}"

        if len(array_start_addrs) != len(array_end_addrs):
            array_end_addrs = []  # reset array_end_addrs

        if len(array_start_addrs) != len(array_sizes):
            array_sizes = []  # reset array_sizes

        ret = cls(
            name, name_zh, fields, size, comment, array_start_addrs, array_end_addrs, array_sizes, array_updated, struct_id
        )
        ret._file_path = file_path
        ret._last_updated = get_now_time()

        return ret

    def to_file(self, file_path: str = ""):
        """更新文件"""
        file_path = file_path or self._file_path
        with open(self._file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            for i, line in enumerate(lines):
                if lines[i].startswith("# struct_id:"):
                    lines[i] = f"# struct_id: {self.id:#x}\n"
                if line.startswith("# array_end_addrs:"):
                    lines[i] = f"# array_end_addrs: {','.join(map(format_address, self.array_end_addrs))}\n"
                if line.startswith("# array_sizes:"):
                    lines[i] = f"# array_sizes: {','.join(map(str, self.array_sizes))}\n"
                if line.startswith("# array_updated:"):
                    lines[i] = f"# array_updated: {self.array_updated}\n"
                if line.startswith("# last_update:"):
                    lines[i] = f"# last_update: {self._last_updated}\n"

        with open(file_path, "w", encoding="utf-8") as file:
            file.writelines(lines)


def _find_struct_array_size(start_addr, struct_size):
    # 首先找到 start_addr 处的双字地址，这是每个结构体的标识
    func_addr = idaapi.get_wide_dword(start_addr)

    cur_addr = start_addr + struct_size
    item_cnt = 1
    while True:
        cur_func_addr = idaapi.get_wide_dword(cur_addr)
        if cur_func_addr != func_addr:
            break
        item_cnt += 1
        cur_addr += struct_size

    return item_cnt, cur_addr


def _add_struc_member(sptr, field: StructField):
    """添加结构体或结构体数组成员"""
    member_struct_name = field._pure_data_type
    opinfo = idaapi.opinfo_t()
    opinfo.tid = idaapi.get_struc_id(member_struct_name)
    if opinfo.tid == idaapi.BADADDR:
        idaapi.warning(f"Struct '{member_struct_name}' not found")
        return False
    idaapi.add_struc_member(sptr, field.name, field.offset, idaapi.stru_flag(), opinfo, field.size)


def _add_string_member(sptr, field: StructField):
    """添加字符串成员"""
    opinfo = idaapi.opinfo_t()
    opinfo.strtype = idaapi.STRTYPE_C_32
    idaapi.add_struc_member(sptr, field.name, field.offset, idaapi.strlit_flag(), opinfo, field.size)


def _get_tinfo_from_base_type(base_type: str) -> idaapi.tinfo_t | None:
    """根据基础类型返回 tinfo_t 对象"""
    if base_type == "void":
        return idaapi.tinfo_t(idaapi.BT_VOID)
    if base_type in ("byte", "char", "int8"):
        return idaapi.tinfo_t(idaapi.BT_INT8)
    if base_type in ("uchar", "uint8"):
        return idaapi.tinfo_t(idaapi.BT_INT8 | idaapi.BTMT_UNSIGNED)
    if base_type in ("word", "short", "int16"):
        return idaapi.tinfo_t(idaapi.BT_INT16)
    if base_type in ("ushort", "uint16"):
        return idaapi.tinfo_t(idaapi.BT_INT16 | idaapi.BTMT_UNSIGNED)
    if base_type in ("dword", "int"):
        return idaapi.tinfo_t(idaapi.BT_INT32)
    if base_type in ("uint",):
        return idaapi.tinfo_t(idaapi.BT_INT32 | idaapi.BTMT_UNSIGNED)
    if base_type == "float":
        return idaapi.tinfo_t(idaapi.BT_FLOAT)
    if base_type == "bool":
        return idaapi.tinfo_t(idaapi.BT_BOOL)

    return None


def _get_tinfo_from_stru_name(stru_name):
    tinfo = idaapi.tinfo_t()
    if tinfo.get_named_type(idaapi.get_idati(), stru_name):
        return tinfo
    return None


def _get_tinfo_from_data_type(data_type: str) -> idaapi.tinfo_t | None:
    """根据数据类型返回tinfo_t, 考虑基础类型和结构体类型与指针和数组嵌套定义的情况"""
    pure_data_type = _get_pure_data_type(data_type)

    # 快速排查一些特例
    if pure_data_type in ("pointer", "address", "pointer32"):
        return None

    # 先处理基础类型和结构体类型
    t = _get_tinfo_from_base_type(pure_data_type)
    if t is None:
        t = _get_tinfo_from_stru_name(pure_data_type)
    if t is None:
        return None

    # 处理指针数组嵌套情况
    remaining = data_type[len(pure_data_type) :].strip().replace(" ", "")
    l = 0
    r = len(remaining) - 1
    cur = l
    while l <= r:
        if remaining[cur] == "*":
            t.create_ptr(t)
            l += 1
            cur = l
            # 处理一种特殊情况, 最里层的 *[, 实际应为 *(variable_name)[，所以也要跳到右边
            if l <= r and remaining[l] == "[":
                cur = r
            continue
        if remaining[cur] == "(":  # 此时应跳转到右边，从右边开始解析
            l += 1
            cur = r
            continue
        if remaining[cur] == ")":  # 此时应跳转到左边，从左边开始解析
            r -= 1
            cur = l
            continue
        if remaining[cur] == "]":  # 往左找到对应的 "["，然后解析数组大小
            r = cur - 1
            for cur in range(r, l - 1, -1):
                if remaining[cur] == "[":
                    break
            else:
                idaapi.warning(f"Invalid data type: {data_type}")
                return None
            try:
                array_size = int(remaining[cur + 1 : r + 1]) if r > cur else 0
            except ValueError:
                idaapi.warning(f"Invalid array size: {data_type} for {remaining[cur + 1 : r + 1]} is not a int.")
                return None
            t.create_array(t, array_size)
            r = cur - 1
            cur = r
            continue
        if remaining[cur] == "[":
            l = cur + 1
            for cur in range(l, r + 1):
                if remaining[cur] == "]":
                    break
            else:
                idaapi.warning(f"Invalid data type: {data_type}")
                return None
            try:
                array_size = int(remaining[l:cur]) if cur > l else 0
            except ValueError:
                idaapi.warning(f"Invalid array size: {data_type} for {remaining[l:cur]} is not a int.")
                return None
            t.create_array(t, array_size)
            l = cur + 1
            cur = l
            continue

    return t


def import_struct(struct: Struct):
    # 先判断结构体是否已经存在，如果存在则对齐进行更新，否则创建新的结构体
    is_update = False

    tid = struct.id
    if tid == -1:  # 若未指定 id，则根据名称查找
        tid = idaapi.get_struc_id(struct.name)
        struct.id = tid
    else:
        struct_name = idaapi.get_struc_name(tid)
        if struct_name != struct.name:
            idaapi.set_struc_name(tid, struct.name)
            idaapi.msg(f"Struct {struct_name} renamed to {struct.name}.\n")
        tid = idaapi.get_struc_id(struct.name)

    if tid == idaapi.BADADDR:
        tid = idaapi.add_struc(idaapi.BADADDR, struct.name)
        idaapi.msg(f"Struct {struct.name} created.\n")
        struct.id = tid
    else:
        is_update = True
        idaapi.msg(f"Struct {struct.name} exists, updating...\n")

    sptr = idaapi.get_struc(tid)
    idaapi.set_struc_cmt(tid, struct.comment, 1)

    for field in struct.fields:
        if is_update:  # 更新结构体时，先删除原有成员
            idaapi.del_struc_members(sptr, field.offset, field.offset + field.size)

        # 添加成员
        if field._pure_data_type.startswith("struct_"):  # 结构体
            if field._is_ptr:  # 结构体指针
                idaapi.add_struc_member(sptr, field.name, field.offset, field._data_flags, None, field.size)
            else:  # 结构体或结构体数组
                _add_struc_member(sptr, field)
        elif field.data_type == "string":  # 字符串
            _add_string_member(sptr, field)
        else:  # 其他类型（基础类型，指针）
            idaapi.add_struc_member(sptr, field.name, field.offset, field._data_flags, None, field.size)

        mptr = idaapi.get_member(sptr, field.offset)
        if mptr == idaapi.BADADDR:
            idaapi.warning(f"Failed to add member '{field.name}' to struct '{struct.name}'")
            continue

        # set tinfo
        tinfo = _get_tinfo_from_data_type(field.data_type)
        if tinfo:
            idaapi.set_member_tinfo(sptr, mptr, 0, tinfo, 0)
        # set comment
        idaapi.set_member_cmt(mptr, field.comment, 1)

    struct_name = idaapi.get_struc_name(tid)
    struct_size = idaapi.get_struc_size(sptr)

    # 校验结构体大小是否一致
    if struct.size == struct_size:
        idaapi.msg(f"Struct {struct_name} size: {struct_size:X}\n")
    else:
        idaapi.warning(f"Struct size mismatch: {struct.size:X} vs {struct_size:X}\n")

    # IDA 视图中创建结构体数组
    # struct.array_updated = False
    if not struct.array_updated and len(struct.array_start_addrs) > 0:
        struct.array_updated = True
        for i, array_start_addr in enumerate(struct.array_start_addrs):
            # 先找出数组的结束地址和大小
            if len(struct.array_end_addrs) > i:
                array_end_addr = struct.array_end_addrs[i]
                array_size = (array_end_addr - array_start_addr) // struct.size
                if len(struct.array_sizes) > i:
                    struct.array_sizes[i] = array_size
                else:
                    struct.array_sizes.append(array_size)
            elif len(struct.array_sizes) > i:
                array_size = struct.array_sizes[i]
                array_end_addr = array_start_addr + array_size * struct.size
                if len(struct.array_end_addrs) > i:
                    struct.array_end_addrs[i] = array_end_addr
                else:
                    struct.array_end_addrs.append(array_end_addr)
            else:  # 仅提供了起始地址，需自行查找 end_addr 和 array_size
                # 大部分结构体第一个字段是指向该类结构体函数的指针，可根据这个特征来查找数组的结束地址
                # 如果不是该特征，则无法自动查找结束地址，需要手动指定
                array_size, array_end_addr = _find_struct_array_size(array_start_addr, struct.size)
                struct.array_end_addrs.append(array_end_addr)
                struct.array_sizes.append(array_size)

                # 更新结构体相关函数所在地址名称
                func_addr_name = struct.fields[0].name.removeprefix("fld_0_")
                func_addr = idaapi.get_wide_dword(array_start_addr)
                idaapi.set_name(func_addr, func_addr_name)

            # 创建结构体数组
            idaapi.del_items(array_start_addr, idaapi.DELIT_SIMPLE, array_size * struct.size)
            if array_size <= 100 or array_size * struct.size < 0x1000:  # 小数组
                idaapi.create_struct(array_start_addr, struct.size, tid)
                if not idc.make_array(array_start_addr, array_size):
                    idaapi.warning(f"Failed to create array at {array_start_addr:X}.\n")
                    continue
                ap = idaapi.array_parameters_t()
                ap.flags = idaapi.AP_INDEX | idaapi.AP_IDXDEC | idaapi.AP_ARRAY
                idaapi.set_array_parameters(array_start_addr, ap)
            else:  # 大数组
                cnt = 0
                for addr in range(array_start_addr, array_end_addr, struct.size):
                    idaapi.create_struct(addr, struct.size, tid)
                    if cnt > 0:
                        idaapi.set_cmt(addr, f"{struct.name}_ARRAY[{cnt}]", 1)
                    cnt += 1

            # 结构体数组名和注释
            array_name = f"{struct.name}_ARRAY"
            if i > 0:
                array_name += f"_{i}"
            idaapi.set_name(array_start_addr, array_name)
            array_comment = f"{array_name}，大小: {array_size}, 结构体大小: {struct.size:X} bytes"
            idaapi.set_cmt(array_start_addr, array_comment, 1)

            idaapi.msg(
                f"Struct array {array_name} created, size: {array_size}, struct size: {struct.size}, start at {array_start_addr:X}, end at {array_end_addr:X}\n"
            )


def action():
    fps = ask_file_paths()
    for i, fp in enumerate(fps):
        idaapi.msg(f"Processing {i + 1}/{len(fps)}: {fp}")
        st = Struct.from_file(fp)
        import_struct(st)
        st.to_file(fp)

        idaapi.msg("Done.")

    idaapi.msg("-" * 50)


##########################################################################
###                        IDA Plugin 接口相关                           ###
##########################################################################


class San11StruPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Import or export structs (@san11pk)."
    help = "Alt-Shift-S to import or export structs."
    wanted_name = "San11StruPlugin"
    wanted_hotkey = "Alt-Shift-S"

    def init(self):
        idaapi.msg("San11StruPlugin initialized.\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        action()

    def term(self):
        idaapi.msg("San11StruPlugin terminated.\n")


def PLUGIN_ENTRY():
    return San11StruPlugin()


if __name__ == "__main__":
    action()
