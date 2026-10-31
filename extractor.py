# -*- coding: utf-8 -*-
"""Pawn / SA-MP 翻译文本候选提取器。

用法：
    python extractor.py ./gamemodes
    python extractor.py "E:\\server\\gamemodes" -o translate.json

输出仍然采用旧版兼容的 JSON 结构：
    {"file": "绝对路径", "line": 123, "original_line": "原始源码行"}
"""

from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


class PawnStatementFinalExtractor:
    """按 Pawn statement 提取可能需要翻译的源码行。

    与旧版保持兼容的参数：PawnStatementFinalExtractor(root_dir, tab_size=4)
    tab_size 仅为兼容旧接口保留；默认不展开 TAB，以免改变原始缩进。
    """

    SOURCE_EXTENSIONS = {".pwn", ".inc"}
    SKIP_DIRS = {
        ".git", "__pycache__", "node_modules", "build", "dist", ".venv", "venv"
    }

    # 旧版忽略项：按代码标识符判断，而不是在原始文本中做任意子串搜索。
    DEFAULT_IGNORE_KEYS = ["sscanf", "mysql"]

    # 旧版关键字保留为可配置项。匹配发生在注释和字符串被屏蔽后的代码标识符中。
    DEFAULT_TARGET_KEYS = [
        "format", "strcat", "Msg", "Error", "Log", "Message", "Show",
        "Warning", "print", "3DText", "GameText", "TextDraw", "Dialog",
        "ProxDetector", "SCM", "Debug", "Kit_", "Notify", "Describe",
        "Info", "info", "#define", "const"
    ]

    # 项目中明确存在/常见的文本构造方式。补充 sprintf / strcopy / strmid / valstr。
    EXTRA_TEXT_FUNCTIONS = {
        "sprintf", "strcopy", "strmid", "valstr",
        "sendclientmessage", "sendclientmessagetoplayer", "sendclientmessagetoall",
        "sendplayermessage", "gameTextForPlayer".lower(), "gametextforall",
        "createdynamic3dtextlabel", "updatedynamic3dtextlabeltext",
        "create3dtextlabel", "update3dtextlabeltext",
        "showplayerdialog", "showasyncdialog",
        "gui_notify", "gui_showmessage", "gui_confirmleave",
        "infobox_show", "infobox_showprompt", "subtitle_show"
    }

    ASSIGNMENT_RE = re.compile(r"(?<![=!<>])=(?!=)")
    IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    DEFINE_RE = re.compile(r"^\s*#\s*define\b", re.IGNORECASE)
    STRING_DECL_RE = re.compile(
        r"^\s*(?:(?:static|new|stock|public)\s+)*(?:const)\b",
        re.IGNORECASE
    )
    STRING_ARRAY_INIT_RE = re.compile(
        r"^\s*(?:(?:static|new)\s+)*(?:const\s+)?"
        r"(?:[A-Za-z_]\w*:\s*)?[A-Za-z_]\w*"
        r"(?:\s*\[[^\]]*\])+\s*=",
        re.IGNORECASE
    )

    def __init__(
        self,
        root_dir: str,
        tab_size: int = 4,
        output_path: str = "translate.json",
        target_keys: Optional[Sequence[str]] = None,
        ignore_keys: Optional[Sequence[str]] = None,
        include_legacy: bool = True,
    ) -> None:
        self.root_dir = os.path.abspath(os.path.expanduser(root_dir))
        self.tab_size = tab_size  # 兼容旧接口；默认保留原始 TAB，不调用 expandtabs。
        self.output_path = output_path
        self.target_keys = list(target_keys or self.DEFAULT_TARGET_KEYS)
        self.ignore_keys = list(ignore_keys or self.DEFAULT_IGNORE_KEYS)
        self.include_legacy = include_legacy

        self.results: List[Dict[str, object]] = []
        self.scanned_files = 0
        self.candidate_statements = 0
        self.decode_warnings: List[str] = []
        self._seen_lines: Set[Tuple[str, int]] = set()

        self._lower_target_keys = [k.lower() for k in self.target_keys]
        self._lower_ignore_keys = [k.lower() for k in self.ignore_keys]

    # ------------------------------------------------------------------
    # 读取与词法屏蔽
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_source(data: bytes) -> Tuple[str, str]:
        """严格按 GBK 读取 Pawn 源码，避免自动猜测编码导致中文误解码。"""
        if data.startswith(b"\xef\xbb\xbf"):
            raise UnicodeError(
                "检测到 UTF-8 BOM；本项目 Pawn 源码应使用 GBK，请先将该文件转换为 GBK。"
            )
        return data.decode("gbk"), "gbk"

    @staticmethod
    def _mask_source(source: str) -> Tuple[str, List[Tuple[int, int]]]:
        """屏蔽注释和双引号字符串，保留每个字符的位置及换行。

        返回：
            masked: 与 source 等长的代码掩码；字符串/注释内容替换为空格。
            strings: 原始字符串字面量的 [start, end) 区间。

        支持 // 注释、跨行 /* */ 注释、转义引号以及跨物理行字符串。
        """
        chars = list(source)
        strings: List[Tuple[int, int]] = []
        state = "code"  # code / string / line_comment / block_comment
        string_start = -1
        escaped = False
        i = 0
        length = len(source)

        while i < length:
            ch = source[i]
            nxt = source[i + 1] if i + 1 < length else ""

            if state == "code":
                if ch == "/" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    state = "line_comment"
                    i += 2
                    continue
                if ch == "/" and nxt == "*":
                    chars[i] = chars[i + 1] = " "
                    state = "block_comment"
                    i += 2
                    continue
                if ch == '"':
                    string_start = i
                    chars[i] = " "
                    state = "string"
                    escaped = False
                    i += 1
                    continue
                i += 1
                continue

            if state == "string":
                if ch in "\r\n":
                    # 保留换行位置；Pawn 的反斜线续行也继续保持字符串状态。
                    escaped = False
                    i += 1
                    continue
                if escaped:
                    chars[i] = " "
                    escaped = False
                    i += 1
                    continue
                if ch == "\\":
                    chars[i] = " "
                    escaped = True
                    i += 1
                    continue
                if ch == '"':
                    chars[i] = " "
                    strings.append((string_start, i + 1))
                    string_start = -1
                    state = "code"
                    i += 1
                    continue
                chars[i] = " "
                i += 1
                continue

            if state == "line_comment":
                if ch in "\r\n":
                    state = "code"
                else:
                    chars[i] = " "
                i += 1
                continue

            if state == "block_comment":
                if ch == "*" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    state = "code"
                    i += 2
                    continue
                if ch not in "\r\n":
                    chars[i] = " "
                i += 1

        if state == "string" and string_start >= 0:
            # 未闭合字符串也保留为候选，方便人工发现源码问题。
            strings.append((string_start, length))

        return "".join(chars), strings

    @staticmethod
    def _split_lines(source: str) -> Tuple[List[str], List[int]]:
        """返回去掉换行符的原始行，以及每行在 source 中的起始偏移。"""
        kept = source.splitlines(keepends=True)
        if not kept and source == "":
            return [], []

        lines: List[str] = []
        starts: List[int] = []
        offset = 0
        for line in kept:
            starts.append(offset)
            lines.append(line.rstrip("\r\n"))
            offset += len(line)
        return lines, starts

    # ------------------------------------------------------------------
    # 预处理指令与 statement 分割
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_preprocessor_blocks(
        source: str, masked: str, lines: Sequence[str], starts: Sequence[int]
    ) -> List[Tuple[int, int]]:
        """识别 # 开头的预处理指令块，处理末尾反斜线续行。"""
        blocks: List[Tuple[int, int]] = []
        if not lines:
            return blocks

        masked_lines = masked.splitlines(keepends=True)
        i = 0
        offset = 0
        while i < len(lines):
            raw = lines[i]
            code_line = masked_lines[i].rstrip("\r\n") if i < len(masked_lines) else ""
            start = starts[i]
            line_end = start + len(raw)
            if i < len(masked_lines):
                line_end = start + len(masked_lines[i])

            if code_line.lstrip().startswith("#"):
                block_start = start
                block_end = line_end
                while raw.rstrip().endswith("\\") and i + 1 < len(lines):
                    i += 1
                    raw = lines[i]
                    block_end = starts[i] + (len(masked_lines[i]) if i < len(masked_lines) else len(raw))
                blocks.append((block_start, block_end))

            i += 1
        return blocks

    @staticmethod
    def _has_top_level_assignment(prefix: str) -> bool:
        """判断当前花括号前是否存在不在参数/下标内部的赋值号。"""
        paren_depth = 0
        bracket_depth = 0
        for index, ch in enumerate(prefix):
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif ch == "=" and paren_depth == 0 and bracket_depth == 0:
                before = prefix[index - 1] if index > 0 else ""
                after = prefix[index + 1] if index + 1 < len(prefix) else ""
                if before not in "=!<>" and after != "=":
                    return True
        return False

    @classmethod
    def _iter_statements(cls, masked: str) -> Iterable[Tuple[int, int]]:
        """按分号切分语句；数组初始化花括号保留，代码块花括号作为边界。

        例如 static const names[] = { "A", "B" }; 会作为一个整体保留。
        函数/if/loop 的代码块大括号不会把整个函数连成一个大 statement。
        """
        start = 0
        paren_depth = 0
        bracket_depth = 0
        brace_stack: List[bool] = []  # True 表示数组/初始化器，False 表示代码块。

        for i, ch in enumerate(masked):
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif ch == "{":
                prefix = masked[start:i]
                is_initializer = cls._has_top_level_assignment(prefix)
                brace_stack.append(is_initializer)
                if not is_initializer:
                    # function / if / switch / loop 等代码块：不把块头混进第一条语句。
                    start = i + 1
            elif ch == "}":
                is_initializer = brace_stack.pop() if brace_stack else False
                if not is_initializer:
                    start = i + 1
            elif ch == ";" and paren_depth == 0 and bracket_depth == 0:
                if masked[start:i + 1].strip():
                    yield start, i + 1
                start = i + 1

        if start < len(masked) and masked[start:].strip():
            yield start, len(masked)

    # ------------------------------------------------------------------
    # 候选判断
    # ------------------------------------------------------------------

    def _contains_ignore_key(self, code: str) -> bool:
        identifiers = [token.lower() for token in self.IDENTIFIER_RE.findall(code)]
        for token in identifiers:
            for key in self._lower_ignore_keys:
                if token == key or token.startswith(key + "_"):
                    return True
        return False

    def _is_target_code(self, code: str) -> bool:
        identifiers = [token.lower() for token in self.IDENTIFIER_RE.findall(code)]
        if not identifiers:
            return False

        for token in identifiers:
            if token in self.EXTRA_TEXT_FUNCTIONS:
                return True

            # 保留旧版关键字覆盖率，但限制在代码标识符中匹配。
            for key in self._lower_target_keys:
                if key in {"#define", "const"}:
                    continue
                if key in token:
                    return True

        # Kit_ 是项目自定义 GUI 层，任何 Kit_* 调用都作为候选入口。
        if any(token.startswith("kit_") for token in identifiers):
            return True
        return False

    def _is_candidate_statement(self, code: str, has_string: bool) -> bool:
        if not has_string or not code.strip():
            return False

        if self._contains_ignore_key(code):
            return False

        # #define 文本常量单独处理；普通 #include/#if 不会进入这里。
        if self.DEFINE_RE.match(code):
            return True

        # 捕获 static const / new const / const 字符串数组或常量。
        # 只检查声明开头，避免把函数参数中的 const 误当成声明。
        declaration_head = code.split("=", 1)[0]
        if self.STRING_DECL_RE.match(declaration_head):
            return True
        if self.STRING_ARRAY_INIT_RE.match(declaration_head):
            return True

        return self._is_target_code(code)

    # ------------------------------------------------------------------
    # 源码行收集
    # ------------------------------------------------------------------

    @staticmethod
    def _range_has_string(
        start: int, end: int, string_spans: Sequence[Tuple[int, int]]
    ) -> bool:
        # string_spans 已按起始偏移排序，二分查找避免大文件出现 O(语句数 × 字符串数)。
        index = bisect.bisect_left(string_spans, (start, -1))
        if index > 0 and string_spans[index - 1][1] > start:
            return True
        return index < len(string_spans) and string_spans[index][0] < end

    def _append_range(
        self,
        file_path: str,
        start: int,
        end: int,
        lines: Sequence[str],
        line_starts: Sequence[int],
    ) -> None:
        if not lines or not line_starts or end <= start:
            return

        first_line = max(0, bisect.bisect_right(line_starts, start) - 1)
        last_offset = max(start, end - 1)
        last_line = min(len(lines) - 1, bisect.bisect_right(line_starts, last_offset) - 1)

        for index in range(first_line, last_line + 1):
            line_num = index + 1
            key = (file_path, line_num)
            if key in self._seen_lines:
                continue
            self._seen_lines.add(key)
            self.results.append({
                "file": file_path,
                "line": line_num,
                "original_line": lines[index],
            })

    def process_file(self, file_path: str) -> None:
        try:
            data = Path(file_path).read_bytes()
            source, encoding = self._decode_source(data)
        except Exception as exc:
            print("读取失败: {} ({})".format(file_path, exc), file=sys.stderr)
            return

        if encoding.endswith("replacement"):
            self.decode_warnings.append(file_path)

        lines, line_starts = self._split_lines(source)
        masked, string_spans = self._mask_source(source)
        masked_chars = list(masked)

        # 预处理指令与普通代码分离。只收集含字符串字面量的 #define。
        pp_blocks = self._collect_preprocessor_blocks(source, masked, lines, line_starts)
        for block_start, block_end in pp_blocks:
            code = masked[block_start:block_end]
            has_string = self._range_has_string(block_start, block_end, string_spans)
            if has_string and self.DEFINE_RE.match(code):
                self.candidate_statements += 1
                self._append_range(file_path, block_start, block_end, lines, line_starts)

            # 屏蔽整个预处理块，避免混入相邻 Pawn statement。
            for pos in range(block_start, min(block_end, len(masked_chars))):
                if masked_chars[pos] not in "\r\n":
                    masked_chars[pos] = " "

        code_only = "".join(masked_chars)
        for start, end in self._iter_statements(code_only):
            code = code_only[start:end]
            has_string = self._range_has_string(start, end, string_spans)
            if self._is_candidate_statement(code, has_string):
                first_code = re.search(r"\S", code)
                if first_code is None:
                    continue
                self.candidate_statements += 1
                self._append_range(
                    file_path, start + first_code.start(), end, lines, line_starts
                )

    # ------------------------------------------------------------------
    # 扫描与保存
    # ------------------------------------------------------------------

    def run(self) -> None:
        if not os.path.isdir(self.root_dir):
            raise FileNotFoundError("源码目录不存在: {}".format(self.root_dir))

        self.results.clear()
        self._seen_lines.clear()
        self.scanned_files = 0
        self.candidate_statements = 0
        self.decode_warnings.clear()

        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = sorted(d for d in dirs if d not in self.SKIP_DIRS)
            if not self.include_legacy and os.path.basename(root).lower() == "legacy":
                dirs[:] = []
                continue

            for filename in sorted(files):
                if Path(filename).suffix.lower() not in self.SOURCE_EXTENSIONS:
                    continue
                full_path = os.path.join(root, filename)
                self.scanned_files += 1
                self.process_file(full_path)

        self.save_json()
        print(
            "提取完成：扫描 {} 个源文件，命中 {} 条 statement，输出 {} 行记录。".format(
                self.scanned_files, self.candidate_statements, len(self.results)
            )
        )
        if self.decode_warnings:
            print(
                "警告：{} 个文件不是有效 UTF-8/GBK，已使用替换字符读取；请检查这些文件的编码。".format(
                    len(self.decode_warnings)
                ),
                file=sys.stderr,
            )

    def save_json(self) -> None:
        try:
            output = Path(self.output_path).expanduser()
            if output.parent and str(output.parent) not in (".", ""):
                output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(self.results, handle, ensure_ascii=False, indent=4)
                handle.write("\n")
        except Exception as exc:
            print("保存失败: {}".format(exc), file=sys.stderr)
            raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description="扫描 .pwn/.inc 文件，提取 SA-MP / Pawn 翻译候选 statement。"
    )
    parser.add_argument(
        "root_dir",
        nargs="?",
        default="gamemodes",
        help="源码根目录，默认 ./gamemodes",
    )
    parser.add_argument(
        "-o", "--output",
        default="translate.json",
        help="输出 JSON 路径，默认 ./translate.json",
    )
    parser.add_argument(
        "--exclude-legacy",
        action="store_true",
        help="跳过目录名为 legacy 的第三方/旧版代码目录",
    )
    args = parser.parse_args()

    extractor = PawnStatementFinalExtractor(
        args.root_dir,
        output_path=args.output,
        include_legacy=not args.exclude_legacy,
    )
    extractor.run()


if __name__ == "__main__":
    main()
