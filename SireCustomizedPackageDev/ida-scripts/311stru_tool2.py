"""
san11pk's IDA Struct Tool
"""

import os
from datetime import datetime

import prettytable
from attrs import define, field

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

STRUCTS_FILE = os.path.join(os.path.dirname(SCRIPT_DIR), "material", "结构体汇总.md")


#######################################################################################################
###                                            Utils                                                ###
#######################################################################################################


def get_now_time() -> str:
    """获取当前时间，形如 2020-06-06 14:00:00"""
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")


def format_address(addr: int) -> str:
    """格式化地址"""
    return f"{addr:08x}"


def int16(x: str) -> int:
    return int(x, 16)


def smart_int(s: str):
    if s.startswith("0x"):
        return int(s, 16)
    return int(s)


def get_pure_data_type(data_type: str) -> str:
    """获取去掉 [], *, () 的 data_type"""
    return data_type.split("[")[0].split("*")[0].split("(")[0].strip()


#######################################################################################################
###                                     结构体文件读写相关                                             ###
#######################################################################################################

_STRUCT_TABLE_HEADER = ["offset", "nbytes", "data_type", "field_name", "field_comment"]


def _set_hook(instance, attrib, new_value):
    instance._mark_modified()
    c = attrib.converter
    if c:
        return c(new_value)
    return new_value


@define
class StructField:
    """结构体字段"""

    offset: int = field(on_setattr=_set_hook)
    size: int = field(on_setattr=_set_hook)  # 字段大小
    data_type: str = field(on_setattr=_set_hook)  # 数据类型
    name: str = field(on_setattr=_set_hook)  # 字段名
    comment: str = field(on_setattr=_set_hook)  # 字段注释

    _is_array: bool = field(default=False, init=False, repr=False)  # 是否是数组
    _is_ptr: bool = field(default=False, init=False, repr=False)  # 是否是指针
    _pure_data_type: str = field(default="", init=False, repr=False)  # 去掉 [], *, () 的 data_type

    _modified: bool = field(default=False, init=False, repr=False)  # 是否被修改

    def _mark_modified(self):
        object.__setattr__(self, "_modified", True)

    def __attrs_post_init__(self):
        self._modified = False

    @classmethod
    def from_table_row(cls, row: list[str]):
        # | offset | nbytes | data_type | field_name | field_comment |
        offset, size, data_type, field_name, field_comment = row
        offset = int(offset, 16)
        size = int(size)
        data_type = data_type.strip()
        field_name = f"fld_{offset:X}_{field_name.strip()}"
        field_comment = field_comment.strip()
        ret = cls(offset, size, data_type, field_name, field_comment)

        ret._is_array = "[" in ret.data_type
        ret._is_ptr = ret.data_type in ("pointer", "address", "pointer32") or "*" in ret.data_type
        ret._pure_data_type = get_pure_data_type(ret.data_type)

        return ret

    def to_table_row(self) -> list[str]:
        name = self.name.removeprefix(f"fld_{self.offset:X}_")  # 去掉前缀
        return [f"{self.offset:X}", str(self.size), self.data_type, name, self.comment]


def _cvt_int16_array(s: str):
    return list(map(int16, s.split(","))) if s else []


def _cvt_int_array(s: str):
    return list(map(int, s.split(","))) if s else []


@define
class Struct:
    """Markdown 文件中存储结构体表格及相关信息"""

    # 元信息
    name: str = field(default="", init=False)
    name_zh: str = field(default="", init=False)
    id: int = field(default=0xFFFFFFFF, init=False)
    size: int = field(default=0, init=False)
    comment: str = field(default="", init=False)
    array_start_addrs: list[int] = field(factory=list, init=False)
    array_end_addrs: list[int] = field(factory=list, init=False)
    array_sizes: list[int] = field(factory=list, init=False)
    array_updated: bool = field(default=False, init=False)
    last_update: str = field(default="", init=False)

    # 解析后的字段
    fields: list[StructField] = field(factory=list, init=False)  # 表格中的字段

    _content: list[str] = field(factory=list, init=False, repr=False)  # 原文件中表格以下至下一个表格标题之间的内容，用于写回文件

    # 各元信息解析函数表
    _META_PARSE_FUNCS = {
        "struct_name": ("name", str.strip),  # 元信息名: (属性名, 处理函数)
        "struct_name_zh": ("name_zh", str.strip),
        "struct_id": ("id", int16),
        "struct_size": ("size", int16),
        "array_start_addrs": ("array_start_addrs", _cvt_int16_array),
        "array_end_addrs": ("array_end_addrs", _cvt_int16_array),
        "array_sizes": ("array_sizes", _cvt_int_array),
        "array_updated": ("array_updated", lambda x: x.lower() == "true"),
        "last_update": ("last_update", str.strip),
    }

    def parse_meta_line(self, line: str):
        if not line.startswith("- "):
            return
        line = line[2:].strip()
        for key, (attr, func) in self._META_PARSE_FUNCS.items():
            if line.startswith(key + ":"):
                setattr(self, attr, func(line.removeprefix(key + ":").strip()))
                break

    def meta_lines(self) -> list[str]:
        lines = []
        lines.append(f"- struct_name_zh: {self.name_zh}\n")
        lines.append(f"- struct_name: {self.name}\n")
        lines.append(f"- struct_id: {self.id:08x}\n")
        lines.append(f"- struct_size: {self.size:#x}\n")
        lines.append(f"- array_start_addrs: {','.join(map(format_address, self.array_start_addrs))}\n")
        lines.append(f"- array_end_addrs: {','.join(map(format_address, self.array_end_addrs))}\n")
        lines.append(f"- array_sizes: {','.join(map(str, self.array_sizes))}\n")
        lines.append(f"- array_updated: {self.array_updated}\n")
        lines.append(f"- last_update: {self.last_update}\n")
        return lines

    def table_string(self) -> str:
        tb = prettytable.PrettyTable()
        tb.set_style(prettytable.MARKDOWN)
        tb.align = "l"
        tb.field_names = _STRUCT_TABLE_HEADER
        for field in self.fields:
            tb.add_row(field.to_table_row())
        return tb.get_string().replace("-|", " |")  # 与 vscode markdown 插件格式化结果一致

    def is_modified(self):
        """是否被修改过"""
        return any(f._modified for f in self.fields)


class StructMDFileParser:
    """结构体汇总.md 文件解析器"""

    _STATE_FINDING_TITLE = 0  # 正在寻找下一个表格标题
    _STATE_BEFORE_TABLE = 1  # 处理表格标题到表格上方之间的内容行
    _STATE_ON_TABLE = 2  # 处理表格内容行

    def __init__(self):
        self._structs: list[Struct] = []
        self._before_content: list[str] = []  # 第一个表格之前的内容
        self._state = self._STATE_FINDING_TITLE
        self._current_table: Struct = None
        self._specific_table_titles: list[str] = None  # 如果不为 None, 则只解析指定标题的表格，否则解析所有表格

    def _reset(self):
        self._structs.clear()
        self._before_content.clear()
        self._state = self._STATE_FINDING_TITLE
        self._current_table = None
        self._specific_table_titles = None

    def parse(self, mk_file: str, specific_table_titles: list[str] = None) -> list[Struct]:
        self._reset()
        self._specific_table_titles = specific_table_titles

        with open(mk_file, "r", encoding="utf-8") as file:
            for line in file:
                self._parse_line(line)

        return self._structs

    def _parse_line(self, line: str):
        if self._state == self._STATE_FINDING_TITLE:
            return self._state_finding_title(line)

        if self._state == self._STATE_BEFORE_TABLE:
            return self._state_before_table(line)

        if self._state == self._STATE_ON_TABLE:
            return self._state_on_table(line)

    def _state_finding_title(self, line: str):
        if line.startswith("## "):
            title = line[3:].strip()
            if not self._specific_table_titles or title in self._specific_table_titles:
                # 找到了一个表格标题
                self._state = self._STATE_BEFORE_TABLE
                self._current_table = Struct()
                self._structs.append(self._current_table)
                return

        if not self._current_table:
            self._before_content.append(line)
        else:
            self._current_table._content.append(line)

    def _state_before_table(self, line: str):
        if self._reach_table_row(line):
            self._state = self._STATE_ON_TABLE
            return

        # 解析结构体元信息
        self._current_table.parse_meta_line(line)

    def _state_on_table(self, line: str):
        if not line.strip():  # 空行
            self._state = self._STATE_FINDING_TITLE
            self._current_table._content.append(line)
            return

        # 解析结构体字段
        row = list(map(str.strip, line.strip().strip("|").split("|")))
        if len(row) != len(_STRUCT_TABLE_HEADER):
            # 无效的表格行，这种情况不应该出现
            raise ValueError(f"Invalid table row: {line}")
        self._current_table.fields.append(StructField.from_table_row(row))

    def add_struct(self, struct: Struct):
        self._structs.append(struct)

    def write_file(self, file_path: str):
        """写入文件"""
        now = get_now_time()
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(self._before_content)
            for table in self._structs:
                # 写入标题
                f.write(f"## {table.name_zh}\n\n")
                # 写入元信息
                if table.is_modified():
                    table.last_update = now
                f.writelines(table.meta_lines())
                f.write("\n")
                # 写入表格
                f.write(table.table_string())
                f.write("\n")
                # 写入表格以下内容
                f.writelines(table._content)

    @staticmethod
    def _reach_table_row(line: str) -> bool:
        """判断是否到达表格内容开始行"""
        return any(line.startswith(x) for x in ("| ---", "|--", "| :--", "|:--"))


if __name__ == "__main__":
    parser = StructMDFileParser()
    tbs = parser.parse(STRUCTS_FILE, ["城市", "港口", "关隘"])

    for i, tb in enumerate(tbs):
        if i % 2 == 0:
            tb.fields[0].comment = "test"
        print(tb)

    new_tb = Struct()
    new_tb.name = "test"
    new_tb.name_zh = "测试"
    parser.add_struct(new_tb)

    parser.write_file(STRUCTS_FILE)

    exit(0)

#######################################################################################################
###                                         IDA 操作相关                                             ###
#######################################################################################################


import idaapi


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
    pure_data_type = get_pure_data_type(data_type)

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


def import_structs():
    pass


def export_structs():
    pass


def action():
    # 交互式选择导入或导出
    button = idaapi.ask_buttons("Import", "Export", "Cancel", 1, "Import or export structs")
    if button == 1:
        import_structs()
    elif button == 0:
        export_structs()
    else:
        idaapi.msg("Canceled.\n")


#######################################################################################################
###                                     IDA Plugin 接口相关                                           ###
#######################################################################################################


class San11StruPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Import or export structs (@san11pk)."
    help = "Shift-S to import or Alt-Shift-S to export san11pk structs."
    wanted_name = "San11StruPlugin"
    wanted_hotkey = ""

    ACTION_IMPORT = "san11:import_struct"
    ACTION_EXPORT = "san11:export_struct"

    def init(self):
        # 注册 import action
        import_action_desc = idaapi.action_desc_t(
            self.ACTION_IMPORT,
            "Import structs",
            IDACtxEntry(import_structs),
            "Shift-S",
            "Import structs (@san11pk)",
            0,
        )
        assert idaapi.register_action(import_action_desc), "Failed to register action: import"
        # 注册 export action
        export_action_desc = idaapi.action_desc_t(
            self.ACTION_EXPORT,
            "Export structs",
            IDACtxEntry(export_structs),
            "Alt-Shift-S",
            "Export structs (@san11pk)",
            0,
        )
        assert idaapi.register_action(export_action_desc), "Failed to register action: export"

        idaapi.msg("San11StruPlugin initialized.\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        action()

    def term(self):
        idaapi.unregister_action(self.ACTION_IMPORT)
        idaapi.unregister_action(self.ACTION_EXPORT)
        idaapi.msg("San11StruPlugin terminated.\n")


class IDACtxEntry(idaapi.action_handler_t):
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def PLUGIN_ENTRY():
    return San11StruPlugin()


if __name__ == "__main__":
    action()
