#!python
"""
将内存地址记录导入到 IDA 中
"""
import os
from dataclasses import dataclass, field
from datetime import datetime

import idaapi

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

    @classmethod
    def from_table_row(cls, row: str):  # | 地址 | 类型 | 名称 | 标签 | 注释 |
        items = row.strip().strip("|").split("|")
        if len(items) != 5:
            raise ValueError(f"Invalid row: {row}")
        address, type_, name, tags, comment = items
        address = int(address, 16)
        type_ = type_.strip()
        name = name.strip()
        tags = tags.strip()
        tags = list(tags.strip().split(",")) if tags else []
        tags.sort()
        comment = comment.strip()
        return cls(address, type_, name, tags, comment)


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
        f.write("| 地址 | 类型 | 名称 | 标签 | 注释 |\n")
        f.write("| ---- | ---- | ---- | ---- | ---- |\n")
        for record in records:
            f.write(f"| {record.address:08x} | {record.type} | {record.name} | {','.join(record.tags)} | {record.comment} |\n")


def import_records(records_file: str):
    idaapi.msg("-" * 50 + "\n")
    idaapi.msg(f"Importing records from {records_file}...\n")

    records = collect_records(records_file)

    for record in records:
        flags = idaapi.get_flags(record.address)
        if idaapi.is_unknown(flags):
            idaapi.msg(f"Address at {record.address} is undefined. Skipped.\n")
            continue
        func = idaapi.get_func(record.address)
        if func and func.start_ea == record.address:
            idaapi.set_name(record.address, record.name)
            idaapi.set_func_cmt(record.address, record.comment, True)
            idaapi.msg(f"Function at {record.address:x} name updated to {record.name}.\n")
        else:
            idaapi.set_name(record.address, record.name, idaapi.SN_NOWARN)
            idaapi.set_cmt(record.address, record.comment, True)
            idaapi.msg(f"Address at {record.address:x} name updated to {record.name}.\n")

    # 按地址排序
    records.sort(key=lambda x: x.address)

    # 保存记录
    save_records(records, records_file)

    idaapi.msg(f"Records imported from {records_file}.\n")
    idaapi.msg("Done.\n")


# import_records(MEM_RECORDS_FILE)


##########################################################################
###                        IDA Plugin 接口相关                           ###
##########################################################################


def action():
    import_records(MEM_RECORDS_FILE)


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
