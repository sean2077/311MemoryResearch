#!python3
"""
杂项.

功能：
    - 排序 函数汇总.md 中的函数
    
    
依赖：
    pip install attrs typer
"""
import os

import typer
from attrs import define, field
from typer import Typer

app = Typer(add_completion=False)


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


##########################################################################
###                              函数相关                               ###
##########################################################################

ALL_FUNCTIONS_FILE = os.path.join(SCRIPT_DIR, "函数汇总.md")


def clean_name(name: str) -> str:
    # 去掉 name 中不能作为名称的字符
    # fmt: off
    illegal_chars = [" "]
    # fmt: on
    for char in illegal_chars:
        name = name.replace(char, "_")

    return name


@define
class Function:
    address: int
    name: str
    comment: str
    tags: list[str] = field(factory=list)

    @classmethod
    def from_table_row(cls, row):  # |序号| 地址 | 函数名 | 标签 | 注释  |
        items = row.strip().strip("|").split("|")
        if len(items) != 5:
            raise ValueError(f"Invalid row: {row}")

        _, address, name, tags, comment = items
        address = int(address, 16)
        name = clean_name(name.strip())
        tags = tags.strip()
        tags = list(tags.strip().split(",")) if tags else []
        tags.sort()
        comment = comment.strip()
        return cls(address, name, comment, tags)


def _collect_functions(file_path: str) -> list[Function]:
    dest_functions = []

    with open(file_path, "r", encoding="utf-8") as f:
        reach_functions = False
        for line in f:
            if not line.strip():
                continue
            if not reach_functions and line.startswith("| ----"):
                reach_functions = True
                continue
            if reach_functions:
                items = line.strip().strip("|").split("|")
                if len(items) == 5:
                    function = Function.from_table_row(line)
                    dest_functions.append(function)
                else:
                    raise ValueError(f"Invalid row: {line}")

    return dest_functions


def _write_functions(functions, dest_file_path):
    with open(dest_file_path, "w", encoding="utf-8") as f:
        # 先写表头
        f.write("| 序号 | 地址 | 函数名 | 标签 | 注释  |\n")
        f.write("| ---- | ---- | ------ | ---- | ---- |\n")
        for i, function in enumerate(functions, 1):
            f.write(f"| {i:03} | {function.address:08x} | {function.name} | {','.join(function.tags)} | {function.comment} |\n")


@app.command()
def sort_func(
    sort_by: str = typer.Argument(
        "1",
        help="(1:地址, 2:函数名, 3:标签, 4:注释) 支持多个排序字段，以逗号分隔; 如果排序字段不在 1-4 中，则按地址排序; 如果数子加前缀 r 表示降序排序，如 r1,2,3",
        show_default=True,
        show_choices=False,
        case_sensitive=False,
    )
):
    """排序 函数汇总.md 中的函数"""

    def _sort_key_by_addr(func: Function):
        return func.address

    def _sort_key_by_name(func: Function):
        return func.name

    def _sort_key_by_tags(func: Function):
        # 取排序最前的 tag
        tags = sorted(func.tags)
        return tags[0] if tags else ""

    def _sort_key_by_comment(func: Function):
        return func.comment

    def _default_sort_key(func: Function):
        return func.address

    sort_key_map = {
        "1": _sort_key_by_addr,
        "2": _sort_key_by_name,
        "3": _sort_key_by_tags,
        "4": _sort_key_by_comment,
    }

    # 整理排序字段
    sort_keys = []
    reversed_flags = []
    for by in sort_by.split(","):
        by = by.strip()
        if by.startswith("r"):
            reversed_flags.append(True)
            by = by[1:]
        else:
            reversed_flags.append(False)
        sort_keys.append(sort_key_map.get(by, _default_sort_key))

    # 读取函数
    functions = _collect_functions(ALL_FUNCTIONS_FILE)

    # 从后往前排序
    for i in range(len(sort_keys) - 1, -1, -1):
        sort_key = sort_keys[i]
        reversed_flag = reversed_flags[i]
        functions.sort(key=sort_key, reverse=reversed_flag)

    # 写入文件
    _write_functions(functions, ALL_FUNCTIONS_FILE)


##########################################################################
###                              结构体相关                               ###
##########################################################################


if __name__ == "__main__":
    app()
