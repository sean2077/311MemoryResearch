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
from typer import Typer

app = Typer(add_completion=False)


def _parse_markdown_table(mk_file: str):
    header = ""
    rows = []
    with open(mk_file, "r", encoding="utf-8") as f:
        reach_rows = False
        for line in f:
            line = line.strip()
            if not line:
                header += "\n"
                continue
            if not reach_rows:
                if line.startswith("| --") or line.startswith("|--"):
                    reach_rows = True
                header += line + "\n"
                continue
            if reach_rows:
                cols = line.strip("|").split("|")
                rows.append(tuple(str.strip() for str in cols))
    return header, rows


@app.command()
def sort_markdown_table(
    markdown_file: str = typer.Argument(..., help="markdown文件路径"),
    sort_by: str = typer.Option(
        "1",
        "--sort-by",
        "-s",
        help="要排序的列序号(从1开始); 支持多个排序字段，以逗号分隔; 如果序号加前缀 r 表示降序排序. 例: r1,2,3",
        show_default=True,
        show_choices=False,
        case_sensitive=False,
    ),
    save_as: str = typer.Option(
        None,
        "--save-as",
        "-o",
        help="保存排序后的 markdown 文件路径, 默认覆盖原文件",
        show_default=True,
    ),
):
    """排序 markdown 文件中的表格"""

    header, rows = _parse_markdown_table(markdown_file)

    sort_indexes = []
    reverse_flags = []
    for by in sort_by.split(","):
        by = by.strip()
        if by.startswith("r"):
            reverse_flags.append(True)
            by = by[1:]
        else:
            reverse_flags.append(False)
        sort_indexes.append(int(by) - 1)

    # 从后往前排序
    for index, reverse in zip(reversed(sort_indexes), reversed(reverse_flags)):
        rows.sort(key=lambda x: x[index], reverse=reverse)

    # 保存
    output_file = save_as or markdown_file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(header)
        for row in rows:
            f.write("| " + " | ".join(row) + " |\n")


if __name__ == "__main__":
    app()
