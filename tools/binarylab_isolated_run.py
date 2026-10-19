"""Изолированный прогон тестов граничных и ошибочных случаев BinaryLab.

Каждый тест из реестра tools/binarylab_cases.py запускается отдельным процессом
(MineHunter.Tests.exe --run:<модуль>.<класс>.<тест>) в Debug и Release. Итог каждого
запуска пишется в build/binarylab-isolated.json; tools/binarylab_test_matrix.py
показывает его в матрице. Код возврата 1 — хотя бы один тест не прошёл.

Запуск: python tools/binarylab_isolated_run.py
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from binarylab_cases import CASES  # noqa: E402
from binarylab_test_matrix import REQUIREMENTS, TESTS, read  # noqa: E402


def qualified_names():
    """Имя теста → «Модуль.Класс.Тест» для --run."""
    names = {}
    for path in TESTS:
        text = read(path)
        unit = os.path.basename(path)[:-4]
        for m in re.finditer(r'^\s*(T\w+)\s*=\s*class\b([\s\S]*?)^\s*end;', text, re.M):
            for test in re.findall(r'\[Test\]\s*procedure\s+(\w+)', m.group(2)):
                names.setdefault(test, []).append('%s.%s.%s' % (unit, m.group(1), test))
    return names


def main():
    wanted = sorted({t for _c, tests in CASES.values() for t in tests} | {t for _r, tests in REQUIREMENTS for t in tests})
    names = qualified_names()
    results = {}
    failed = []
    for config in ('Debug', 'Release'):
        exe = os.path.join(ROOT, 'build', 'Win64', config, 'MineHunter.Tests.exe')
        results[config] = {}
        for test in wanted:
            ok = True
            for full in names.get(test, []):
                proc = subprocess.run([exe, '--exitbehavior:Continue', '--consolemode:Quiet', '--run:' + full],
                                      capture_output=True, timeout=600)
                out = proc.stdout.decode('cp866', errors='replace')
                passed = re.search(r'Tests Passed\s*:\s*(\d+)', out)
                found = re.search(r'Tests Found\s*:\s*(\d+)', out)
                ok = ok and proc.returncode == 0 and found and passed and found.group(1) == passed.group(1) != '0'
            if not names.get(test):
                ok = False
            results[config][test] = bool(ok)
            if not ok:
                failed.append('%s %s' % (config, test))
            print('%-8s %-55s %s' % (config, test, 'пройден' if ok else 'НЕ ПРОЙДЕН'), flush=True)
    with open(os.path.join(ROOT, 'build', 'binarylab-isolated.json'), 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
    print('tests=%d failed=%d' % (len(wanted), len(failed)))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
