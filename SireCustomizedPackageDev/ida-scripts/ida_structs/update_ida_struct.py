# 参考内存资料中的结构体资料，对 IDA 中的结构体进行定义和编辑

import os
import re
from datetime import datetime

import ida_kernwin
import ida_struct
import idaapi
import idc


def ask_file_path() -> list[str]:
    file_paths = []

    # 弹出文件选择对话框
    file_path = ida_kernwin.ask_file(
        False, "*.txt", "Please select a struct defining file, or cancel to enter file or directory path for batch handling."
    )
    if file_path:
        file_paths.append(file_path)
    else:
        args_str = idaapi.ask_text(0, "", "Enter file or directory path for batch handling:")
        if args_str is None:
            print("No arguments provided.")
            idaapi.exist()

        if os.path.exists(args_str):
            if os.path.isfile(args_str):
                file_paths.append(args_str)
            elif os.path.isdir(args_str):
                for file_path in os.listdir(args_str):
                    if file_path.endswith(".txt"):
                        file_paths.append(os.path.join(args_str, file_path))

    if not file_paths:
        idaapi.msg("No file selected.\n")
        idaapi.exist()

    return file_paths


def get_now_time() -> str:
    """获取当前时间，形如 2020-06-06 14:00:00"""
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")


def parse_defined_struct_txt(file_path: str) -> dict:
    """解析定义的结构体的txt文件，位于 ida-scripts\structs 目录"""

    st = {
        "struct_name_zh": "",  # 从文件中提取的结构体中文名
        "fields": [],
        "ida_struct_name": None,  # 从文件中提取的 IDA 结构体名
        "struct_size": None,  # 若文件中设置，将进行大小校验
        "comment": "",
        "start_addrs": [],  # 结构体数组的起始地址
        "end_addrs": [],
        "array_sizes": [],
        "last_update": get_now_time(),
    }

    # 正则表达式，用于匹配每行的三部分内容
    pattern = re.compile(r"\+(\w+)\s+(\d+)\s*byte\s*(.*)")

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            # 处理特殊行
            if line.startswith("#"):
                if line.startswith("# struct_name_zh:"):
                    st["struct_name_zh"] = line.split(":")[-1].strip()
                elif line.startswith("# ida_struct:"):
                    st["ida_struct_name"] = line.split(":")[-1].strip()
                elif line.startswith("# struct_size:"):
                    sz = line.split(":")[-1].strip()
                    if sz.startswith("0x"):
                        st["struct_size"] = int(sz, 16)
                    else:
                        st["struct_size"] = int(sz)

                elif line.startswith("# start_addrs:"):
                    st["start_addrs"] = list(map(lambda x: int(x, 16), line.split(":")[-1].strip().split(",")))

                continue

            match = pattern.match(line.strip())
            if match:
                offset = match.group(1)
                nbytes = match.group(2)
                name = match.group(3)
                name = name.strip()
                # 如果name中存在"\(.*\)"", 则将其分割为name和comment, 否则comment为空
                field_comment = ""
                if name.startswith("("):
                    field_comment, name = name.split(")", 1)
                    field_comment = field_comment[1:]
                    name = name.strip()
                elif name.endswith(")"):
                    name, field_comment = name.split("(", 1)
                    field_comment = field_comment[:-1]
                    name = name.strip()

            # 去掉 name 中不能作为 IDA 结构体成员名的字符
            # fmt: off
            illegal_chars = [" ", "/", ".", ":", "(", ")", "[", "]", "{", "}", "<", ">",
                             ",", ";", "'", "\"", "`", "~", "!", "@", "#", "$", "%", "^",
                             "&", "*", "-", "+", "=", "?", "|", "\\", "～"]
            # fmt: on
            for char in illegal_chars:
                name = name.replace(char, "_")

            field_name = f"fld_{offset}"
            if name:
                field_name += f"_{name}"

            st["fields"].append((int(offset, 16), int(nbytes), field_name, field_comment))

    # 以去掉后缀的文件名作为该结构体的注释
    st["comment"] = f'{os.path.splitext(os.path.basename(file_path))[0]}, 最后更新：{st["last_update"]}'

    return st


def create_ida_struct(st: dict):
    """在 IDA 中创建结构体"""
    ida_struct_name = st.get("ida_struct_name")
    if not ida_struct_name:
        ida_struct_name = None

    # 先判断结构体是否已经存在，如果存在则对齐进行更新，否则创建新的结构体
    is_update = False
    tid = ida_struct.get_struc_id(ida_struct_name)
    if tid == idaapi.BADADDR:
        tid = ida_struct.add_struc(idaapi.BADADDR, ida_struct_name)
        idaapi.msg(f"Struct {ida_struct_name} creating...\n")
    else:
        is_update = True
        idaapi.msg(f"Struct {ida_struct_name} exists, updating...\n")

    sptr = ida_struct.get_struc(tid)

    ida_struct.set_struc_cmt(tid, st.get("comment", ""), 1)

    for offset, nbytes, field_name, comment in st["fields"]:
        flag = None
        if nbytes == 1:
            flag = idc.FF_BYTE
        elif nbytes == 2:
            flag = idc.FF_WORD
        elif nbytes == 4:
            flag = idc.FF_DWORD
        else:
            flag = idc.FF_BYTE

        if is_update:
            # delete the existing member
            mptr = ida_struct.get_member(sptr, offset)
            if mptr != idaapi.BADADDR:
                ida_struct.del_struc_member(sptr, offset)

        ida_struct.add_struc_member(sptr, field_name, offset, flag, None, nbytes)
        if comment:
            mptr = ida_struct.get_member(sptr, offset)
            ida_struct.set_member_cmt(mptr, comment, 1)

    ida_struct_name = ida_struct.get_struc_name(tid)
    struct_size = ida_struct.get_struc_size(sptr)

    # 校验结构体的大小是否正确
    struct_size = ida_struct.get_struc_size(sptr)
    if st["struct_size"] and st["struct_size"] != struct_size:
        idaapi.warning(f"Struct {ida_struct_name} size mismatch: {st['struct_size']} != {struct_size}\n")
        idaapi.exist(-1)
    else:
        idaapi.msg(f"Struct {ida_struct_name} {'updated' if is_update else 'created'}, size: 0x{struct_size:X} bytes\n")

    st["tid"] = tid


def format_struct_array(start_addr: int, tid: int, ele_name_zh: str, idx: int = 0) -> tuple[int, int]:
    """找到内存中的结构体数组，并将其格式化为结构体，返回数组的大小和结束地址"""

    # 首先找到 start_addr 处的双字地址，这是每个结构体的标识
    func_addr = idaapi.get_32bit(start_addr)

    sptr = ida_struct.get_struc(tid)
    struct_size = ida_struct.get_struc_size(sptr)

    # 首先给 start_addr 处的地址命名
    array_name = f"{ele_name_zh}数组"
    if idx > 0:
        array_name += f"_{idx}"
    idaapi.create_struct(start_addr, struct_size, tid)
    idaapi.set_name(start_addr, array_name)
    # 对 func_addr 命名
    idaapi.set_name(func_addr, f"{ele_name_zh}相关函数地址")

    cur_addr = start_addr + struct_size
    item_cnt = 1
    while True:
        cur_func_addr = idaapi.get_32bit(cur_addr)
        if cur_func_addr != func_addr:
            break
        if idaapi.create_struct(cur_addr, struct_size, tid):
            item_cnt += 1
            cur_addr += struct_size

    array_comment = f"{array_name}，大小: {item_cnt}, 结构体大小: 0x{struct_size:X} bytes"
    idaapi.set_cmt(start_addr, array_comment, 1)

    return item_cnt, cur_addr


def format_address(addr: int) -> str:
    """格式化地址"""
    return f"{addr:08X}"


def handle(struct_file: str):
    # 解析结构体定义文件
    st = parse_defined_struct_txt(struct_file)

    # 在 IDA 中创建结构体
    create_ida_struct(st)

    # IDA 视图中创建结构体数组

    tid = st["tid"]
    end_addrs = []
    array_sizes = []
    for i, start_addr in enumerate(st["start_addrs"]):
        array_size, end_addr = format_struct_array(start_addr, tid, st["struct_name_zh"], i)
        array_sizes.append(array_size)
        end_addrs.append(end_addr)
        idaapi.msg(f"Array at 0x{start_addr:X} created, size: {array_size}, end at 0x{end_addr:X}\n")

    # 更新 struct_file 文件开头，主要是修改"# end_addr: "和"# array_size:"
    with open(struct_file, "r", encoding="utf-8") as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            if line.startswith("# end_addrs:"):
                lines[i] = f"# end_addrs: {','.join(map(format_address, end_addrs))}\n"
            if line.startswith("# array_sizes:"):
                lines[i] = f"# array_sizes: {','.join(map(str, array_sizes))}\n"
            if line.startswith("# last_update:"):
                # 最后更新时间，形如 2020-06-06 14:00:00
                lines[i] = f"# last_update: {st['last_update']}\n"
                idaapi.msg(f"Last update time: {st['last_update']}\n")

        with open(struct_file, "w", encoding="utf-8") as file:
            file.writelines(lines)

    print("-" * 50)


def main():
    struct_files = ask_file_path()
    for i, struct_file in enumerate(struct_files):
        idaapi.msg(f"Processing file({i + 1}/{len(struct_files)}): {struct_file}\n")
        handle(struct_file)


main()
