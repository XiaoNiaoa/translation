# -*- coding: utf-8 -*-
"""将 translate.json 中的翻译内容安全地写回 Pawn 源码。"""

import json
import os
import shutil
import tempfile
from collections import defaultdict


# 根据 Pawn 编译环境设置源码编码："gbk" 或 "utf-8"。
# 这里默认 GBK，沿用原替换脚本的设置；带 UTF-8 BOM 的文件会自动识别为 UTF-8。
SOURCE_ENCODING = "gbk"

# True：首次修改文件前，创建 file.pwn.bak 备份；不会覆盖已经存在的备份。
CREATE_BACKUP = True


def load_json(json_path):
    """读取提取器输出的 JSON：优先 UTF-8，兼容旧版 GBK JSON。"""
    with open(json_path, "rb") as f:
        raw = f.read()

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("gbk")

    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("JSON 顶层必须是数组。")
    return data


def read_source_file(filepath):
    """严格按 GBK 读取 Pawn 源码，并保留原始换行；不自动切换成 UTF-8。"""
    with open(filepath, "rb") as f:
        raw = f.read()

    if raw.startswith(b"\xef\xbb\xbf"):
        raise UnicodeError(
            "检测到 UTF-8 BOM；本项目 Pawn 源码应使用 GBK，请先将该文件转换为 GBK。"
        )

    text = raw.decode(SOURCE_ENCODING)  # 严格解码，失败时拒绝修改
    return text.splitlines(keepends=True), SOURCE_ENCODING


def split_line_ending(line):
    """将一行拆成正文和原始行尾，支持 CRLF、LF、CR 和无行尾。"""
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    if line.endswith("\r"):
        return line[:-1], "\r"
    return line, ""


def get_replacement(entry):
    """新格式优先使用 translated_line；兼容旧格式直接修改 original_line。"""
    if "translated_line" in entry:
        translated = entry["translated_line"]
        if translated is None or translated == "":
            return None
        return translated

    # 旧工作流：直接把 original_line 改成翻译后的整行。
    return entry.get("original_line")


def apply_file(filepath, entries):
    lines, encoding = read_source_file(filepath)
    replacements = {}
    expected_originals = {}
    legacy_count = 0

    for entry in entries:
        if "line" not in entry:
            raise ValueError("记录缺少 line 字段。")

        line_num = entry["line"]
        if not isinstance(line_num, int) or line_num < 1:
            raise ValueError("无效行号：{!r}".format(line_num))

        translated = get_replacement(entry)
        if translated is None:
            continue
        if not isinstance(translated, str):
            raise ValueError("第 {} 行的翻译内容必须是字符串。".format(line_num))
        if "\n" in translated or "\r" in translated:
            raise ValueError(
                "第 {} 行的 translated_line 包含真实换行；每条记录必须只替换一行。".format(line_num)
            )

        index = line_num - 1
        if index >= len(lines):
            raise IndexError(
                "行号超出文件范围：{}（文件共 {} 行）".format(line_num, len(lines))
            )

        # 新格式保留 original_line 作为校验基准。
        if "translated_line" in entry and entry.get("original_line") is not None:
            expected = entry["original_line"]
            current, _ = split_line_ending(lines[index])
            if current != expected:
                raise ValueError(
                    "第 {} 行与提取时的 original_line 不一致，拒绝覆盖。\n"
                    "提取记录：{}\n当前源码：{}".format(line_num, expected, current)
                )
            expected_originals[line_num] = expected
        else:
            legacy_count += 1

        if line_num in replacements and replacements[line_num] != translated:
            raise ValueError("同一文件第 {} 行存在互相冲突的翻译记录。".format(line_num))

        replacements[line_num] = translated

    if not replacements:
        return 0, legacy_count

    # 先在内存中完成全部替换；验证失败时不会写入文件。
    for line_num, translated in replacements.items():
        index = line_num - 1
        _, original_newline = split_line_ending(lines[index])
        lines[index] = translated + original_newline

    output_text = "".join(lines)
    output_bytes = output_text.encode(encoding)

    if CREATE_BACKUP:
        backup_path = filepath + ".bak"
        if not os.path.exists(backup_path):
            shutil.copy2(filepath, backup_path)

    # 临时文件与源文件放在同一目录，os.replace 可避免写到一半中断造成文件残缺。
    directory = os.path.dirname(os.path.abspath(filepath))
    fd, temp_path = tempfile.mkstemp(prefix=".pawn_replace_", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(output_bytes)
        os.replace(temp_path, filepath)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise

    return len(replacements), legacy_count


def replace_lines(translated_file="translate.json"):
    translated = load_json(translated_file)

    file_groups = defaultdict(list)
    for entry in translated:
        if not isinstance(entry, dict):
            raise ValueError("JSON 中的每条记录都必须是对象。")
        filepath = entry.get("file")
        if not filepath:
            raise ValueError("记录缺少 file 字段。")
        file_groups[os.path.normpath(filepath)].append(entry)

    total_replaced = 0
    total_legacy = 0
    failed_files = []

    for filepath, entries in file_groups.items():
        if not os.path.isfile(filepath):
            print("[跳过] 文件不存在：{}".format(filepath))
            failed_files.append(filepath)
            continue

        try:
            replaced, legacy = apply_file(filepath, entries)
            total_replaced += replaced
            total_legacy += legacy
            print("[完成] {}：替换 {} 行".format(filepath, replaced))
        except Exception as exc:
            print("[失败] {}：{}".format(filepath, exc))
            failed_files.append(filepath)

    print("\n替换完成：共修改 {} 行，涉及 {} 个文件。".format(total_replaced, len(file_groups) - len(failed_files)))

    if total_legacy:
        print(
            "注意：有 {} 条记录使用旧格式（直接把 original_line 当作翻译内容）。"
            "旧格式无法校验原文是否已变化。建议逐步改用 translated_line。".format(total_legacy)
        )

    if failed_files:
        print("有 {} 个文件未修改，请检查上面的错误信息。".format(len(failed_files)))


if __name__ == "__main__":
    import sys
    json_path = sys.argv[1] if len(sys.argv) > 1 else "translate.json"
    replace_lines(json_path)
