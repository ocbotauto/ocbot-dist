#!/usr/bin/env python3
"""Жёсткая проверка: ocbot.zip в этом репозитории — всегда защищённая (обфусцированная) сборка для
покупателей, никогда читаемый код с комментариями/docstring'ами и никогда REQUIRED=False.

Что проверяет (внутри ocbot.zip):
  - ocbot/*.py и tools/*.py (но НЕ site/ — это шаблон сайта покупателя, он должен быть читаемым):
      * ни одного оставшегося комментария (токен COMMENT через tokenize — без ложных срабатываний
        на "#" внутри строк);
      * ни одного docstring'а (первый statement модуля/класса/функции — голая строка).
  - ocbot/license.py: REQUIRED = True (покупательская сборка без этого бесполезна — лицензия не
    проверяется).

Запуск: python3 verify_protected.py [путь/к/ocbot.zip]  (по умолчанию ocbot.zip рядом со скриптом)
Код возврата: 0 — всё чисто, 1 — нашёл нарушение (печатает что и где).
"""
from __future__ import annotations
import ast
import io
import sys
import tokenize
import zipfile
from pathlib import Path

CHECK_DIRS = ("ocbot/", "tools/")


def find_comments(src: str) -> list:
    out = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                out.append(tok.start[0])
    except tokenize.TokenizeError:
        pass
    return out


def find_docstrings(src: str) -> list:
    out = []
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return [f"SyntaxError: {e}"]

    def check(node):
        body = getattr(node, "body", None)
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                and isinstance(body[0].value.value, str):
            out.append(body[0].lineno)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                check(child)
    check(tree)
    return out


def main() -> int:
    zip_path = Path(sys.argv[1] if len(sys.argv) > 1 else "ocbot.zip")
    if not zip_path.exists():
        print(f"ОШИБКА: не нашёл {zip_path}")
        return 1
    problems = []
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        for name in names:
            if not name.endswith(".py"):
                continue
            if not any(name.startswith(d) for d in CHECK_DIRS):
                continue
            src = zf.read(name).decode("utf-8", errors="replace")
            comment_lines = find_comments(src)
            if comment_lines:
                problems.append(f"{name}: остались комментарии на строках {comment_lines[:10]}"
                                 + (" …" if len(comment_lines) > 10 else ""))
            doc_lines = find_docstrings(src)
            if doc_lines:
                problems.append(f"{name}: остались docstring'и на строках {doc_lines[:10]}"
                                 + (" …" if len(doc_lines) > 10 else ""))
        lic_name = next((n for n in names if n.endswith("ocbot/license.py")), None)
        if lic_name is None:
            problems.append("ocbot/license.py не найден в архиве")
        else:
            lic_src = zf.read(lic_name).decode("utf-8", errors="replace")
            if "REQUIRED = True" not in lic_src:
                problems.append("ocbot/license.py: REQUIRED = True НЕ найден — покупательская сборка "
                                 "без лицензии недопустима")
    if problems:
        print(f"НЕ ОБФУСЦИРОВАНО / нарушение правила для покупательской сборки ({zip_path}):")
        for p in problems:
            print("  - " + p)
        print("\nПравило: для покупателей (ocbotauto/ocbot-dist, файл ocbot.zip) — ВСЕГДА собирать через "
              "build_protected.py (обфускация + REQUIRED=True). Читаемый код допустим только в личном "
              "репозитории (hive-oc-bot.zip).")
        return 1
    print(f"OK: {zip_path} — защищённая сборка, нарушений не найдено.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
