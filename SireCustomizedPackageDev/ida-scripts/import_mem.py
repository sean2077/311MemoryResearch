#!python
"""
将内存地址记录导入到 IDA 中
"""
import os
import re
from dataclasses import dataclass, field
from datetime import datetime

import idaapi
import idc

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


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


def get_ida_data_type(base_dt_str: str):
    if base_dt_str in ("byte", "bit"):
        return idaapi.FF_BYTE
    if base_dt_str in ("word", "short"):
        return idaapi.FF_WORD
    if base_dt_str in ("dword", "int", "pointer32"):
        return idaapi.FF_DWORD
    return idaapi.FF_BYTE


def get_ida_data_type_flag(dt_str):
    if dt_str in ("byte",):
        return idaapi.byte_flag(), 1
    if dt_str in ("word", "short"):
        return idaapi.word_flag(), 2
    if dt_str in ("dword", "int", "pointer32"):
        return idaapi.dword_flag(), 4
    if dt_str in ("float",):
        return idaapi.float_flag(), 4
    return idaapi.byte_flag(), 1


##########################################################################
###                           内存地址记录相关                            ###
##########################################################################


MEM_RECORDS_FILE = os.path.join(os.path.dirname(SCRIPT_DIR), "material", "内存地址汇总.md")


@dataclass
class Record:
    address: int
    type: str
    name: str = ""
    tags: list[str] = field(default_factory=list)
    comment: str = ""

    _info: dict = field(default_factory=dict)  # 附加信息, 形如 key1=value1,key2=value2

    @classmethod
    def from_table_row(cls, row: str):  # | 地址 | 类型 | 名称 | 标签 | 注释 | 附加信息 |
        items = row.strip().strip("|").split("|")
        if len(items) != 6:
            raise ValueError(f"Invalid row: {row}")
        address, type_, name, tags, comment, info = items
        address = int(address, 16)
        type_ = type_.strip()
        name = name.strip()
        tags = tags.strip()
        tags = list(tags.strip().split(",")) if tags else []
        tags.sort()
        comment = comment.strip()
        ret = cls(address, type_, name, tags, comment)

        # 附加信息
        info = info.strip()
        if info:
            for item in info.split(","):
                key, value = item.split("=")
                ret._info[key.strip()] = value.strip()

        return ret


def collect_records(file_path: str = MEM_RECORDS_FILE) -> list[Record]:
    records = []
    name_set = set()

    with open(file_path, "r", encoding="utf-8") as f:
        reach_records = False
        for line in f:
            line = line.strip()
            if not line:
                continue
            if not reach_records:
                if line.startswith("| ---") or line.startswith("|--"):
                    reach_records = True
                continue
            if reach_records:
                record = Record.from_table_row(line)
                if record.name:
                    if record.name in name_set:
                        print(f"Name conflict: {record.name}")
                        record.name += f"_{record.address:x}"
                    name_set.add(record.name)
                records.append(record)

    return records


def save_records(records: list[Record], dest_file: str = MEM_RECORDS_FILE):
    with open(dest_file, "w", encoding="utf-8") as f:
        f.write("| 地址 | 类型 | 名称 | 标签 | 注释 | 附加信息 | \n")
        f.write("| ---- | ---- | ---- | ---- | ---- | ---- |\n")
        for record in records:
            info = ",".join([f"{k}={v}" for k, v in record._info.items()])
            f.write(
                f"| {record.address:08x} | {record.type} | {record.name} | {','.join(record.tags)} | {record.comment} | {info} |\n"
            )


def import_records(records_file: str):
    idaapi.msg("-" * 50 + "\n")
    idaapi.msg(f"Importing records from {records_file}...\n")

    records = collect_records(records_file)

    for record in records:

        # 1. 如果为函数开头地址，更新函数名称和注释
        func = idaapi.get_func(record.address)
        if func and func.start_ea == record.address:
            idaapi.set_name(record.address, record.name)
            idaapi.set_func_cmt(record.address, record.comment, True)
            idaapi.msg(f"Function at {record.address:x} name updated to {record.name}.\n")
            continue

        # 2. 如果为参数
        if record.type in ["参数"]:
            param_type = record._info.get("type", None)
            if param_type:
                if param_type.startswith("struct_"):
                    tid = idaapi.get_struc_id(param_type)
                    if tid == idaapi.BADADDR:
                        idaapi.warning(f"Struct {param_type} not found. Skipped.\n")
                        continue
                    dt_sz = idaapi.get_struc_size(tid)
                    idaapi.create_struct(record.address, dt_sz, tid)
                else:
                    dt_flag, dt_sz = get_ida_data_type_flag(param_type)
                    idaapi.create_data(record.address, dt_flag, dt_sz, idaapi.BADNODE)

            idaapi.set_name(record.address, record.name, idaapi.SN_NOWARN)
            idaapi.set_cmt(record.address, record.comment, True)
            idaapi.msg(f"Parameter at {record.address:x} created, named to {record.name}.\n")
            continue

        # 3. 如果为数表，创建数组
        if record.type in ["数表"]:
            table_type = record._info.get("type", None)  # data_type[array_size]
            if not table_type:
                idaapi.msg(f"Table at {record.address:x} has no type info. Skipped.\n")
                continue

            # 解析 data_type 和 array_size
            pattern = r"(\w+)\[(\d+)\]"
            match = re.match(pattern, table_type)
            if not match:
                idaapi.msg(f"Invalid table type: {table_type}. Skipped.\n")
                continue
            dt_str, array_size = match.groups()
            array_size = int(array_size)

            # 首先定义 record.address 处的数据结构
            is_struct_array = dt_str.startswith("struct_")
            if is_struct_array:  # 结构体数组
                tid = idaapi.get_struc_id(dt_str)
                if tid == idaapi.BADADDR:
                    idaapi.warning(f"Struct {dt_str} not found. Skipped.\n")
                    continue
                dt_sz = idaapi.get_struc_size(tid)
                idaapi.del_items(record.address, idaapi.DELIT_SIMPLE, array_size * dt_sz)  # 去掉原有定义
                if not idaapi.create_struct(record.address, dt_sz, tid):
                    idaapi.warning(f"Failed to create struct {dt_str} at {record.address:x}.\n")
                    continue
            else:
                dt_flag, dt_sz = get_ida_data_type_flag(dt_str)
                idaapi.del_items(record.address, idaapi.DELIT_SIMPLE, array_size * dt_sz)  # 去掉原有定义
                if not idaapi.create_data(record.address, dt_flag, dt_sz, idaapi.BADNODE):
                    idaapi.warning(f"Failed to create data type {dt_str} at {record.address:x}.\n")
                    continue

            # 创建数组
            need_create_array = (array_size <= 100 or array_size * dt_sz < 0x1000) and (
                record._info.get("no_array", "0") != "1"
            )
            if need_create_array:
                if not idc.make_array(record.address, array_size):
                    idaapi.warning(f"Failed to create array at {record.address:x}.\n")
                    continue
                ap = idaapi.array_parameters_t()
                ap.flags = idaapi.AP_INDEX | idaapi.AP_IDXDEC
                if not record._info.get("no_array", False):
                    ap.flags |= idaapi.AP_ARRAY
                ap.lineitems = 0 if is_struct_array else 1
                idaapi.set_array_parameters(record.address, ap)
            else:
                for i in range(1, array_size):
                    if is_struct_array:
                        if not idaapi.create_struct(record.address + i * dt_sz, tid):
                            idaapi.warning(f"Failed to create struct {dt_str} at {record.address + i * dt_sz:x}.\n")
                            continue
                    else:
                        if not idc.create_data(record.address + i * dt_sz, dt_flag, dt_sz, idaapi.BADNODE):
                            idaapi.warning(f"Failed to create data type {dt_str} at {record.address + i * dt_sz:x}.\n")
                            continue

            # 补充数组信息
            array_detail = f"[end={record.address+dt_sz*array_size:x},size={array_size},item_size={dt_sz:#x}]"
            if not record.comment.startswith(array_detail):
                record.comment = array_detail + " " + record.comment

            idaapi.set_name(record.address, record.name, idaapi.SN_NOWARN)
            idaapi.set_cmt(record.address, record.comment, True)
            idaapi.msg(f"Array at {record.address:x} created, size: {array_size}, named to {record.name}.\n")
            continue

        # 其他情况，更新地址名称和注释
        idaapi.set_name(record.address, record.name, idaapi.SN_NOWARN)
        idaapi.set_cmt(record.address, record.comment, True)
        idaapi.msg(f"Address at {record.address:x} name updated to {record.name}.\n")

    # 刷新 IDA 视图和 反编译视图
    window_refresh_flags = idaapi.IWID_DISASM | idaapi.IWID_PSEUDOCODE
    idaapi.request_refresh(window_refresh_flags)
    idaapi.refresh_idaview()

    # 按(类别，标签，地址)排序
    records.sort(key=lambda x: x.address)
    records.sort(key=lambda x: tuple(sorted(x.tags)), reverse=True)
    records.sort(key=lambda x: x.type)

    # 保存记录
    save_records(records, records_file)

    idaapi.msg(f"Records imported from {records_file}.\n")
    idaapi.msg("Done.\n")


def action():
    import_records(MEM_RECORDS_FILE)


##########################################################################
###                        IDA Plugin 接口相关                           ###
##########################################################################


class ImportMemPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Import san11pk memory records."
    help = "Alt-Shift-M to import san11pk memory records."
    wanted_name = "Import Memory Records (@san11pk)"
    wanted_hotkey = "Alt-Shift-M"

    def init(self):
        idaapi.msg("ImportMemPlugin initialized.\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        action()

    def term(self):
        idaapi.msg("ImportMemPlugin terminated.\n")


def PLUGIN_ENTRY():
    return ImportMemPlugin()


if __name__ == "__main__":
    action()
