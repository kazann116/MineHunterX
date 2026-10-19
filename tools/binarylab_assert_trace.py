"""Построчная трассировка проверок BinaryLab.

1. Берёт список строк Assert из build/binarylab-checks.json (создаёт
   tools/binarylab_test_matrix.py) — проверки граничных и ошибочных случаев.
2. Копирует тестовые модули в build/tmp/trace и в каждую такую строку вставляет
   TraceHit('<файл>:<строка>') (в блоке begin … end, чтобы не менять логику
   конструкций вида «if … then Assert…»).
3. Собирает копию набора тестов в конфигурациях Debug и Release (tools/dcc_config.ps1 —
   ключи компилятора тех же конфигураций проекта) и запускает весь набор в каждой.
4. Проверяет: все тесты пройдены и каждая строка Assert выполнилась хотя бы раз.
   Тест прерывается на первой неудачной проверке, поэтому выполненная строка в
   пройденном тесте — пройденная проверка.

Итог — build/binarylab-assert-trace.json; код возврата 1 — есть невыполненные строки
или непройденные тесты.

Запуск: python tools/binarylab_assert_trace.py
"""
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACE_DIR = os.path.join(ROOT, 'build', 'tmp', 'trace')


def instrument(rel, lines_to_mark):
    text = open(os.path.join(ROOT, rel), encoding='utf-8-sig', newline='').read()
    lines = text.split('\r\n')
    for lineno in sorted(lines_to_mark, reverse=True):
        start = lineno - 1
        # Конец оператора — «;» вне скобок и строк (внутри WillRaise(procedure … end, …) свои «;»).
        depth = 0
        end = col = None
        for i in range(start, len(lines)):
            in_string = False
            for j, ch in enumerate(lines[i]):
                if ch == "'":
                    in_string = not in_string
                elif in_string:
                    continue
                elif ch == '/' and lines[i][j:j + 2] == '//':
                    break
                elif ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                elif ch == ';' and depth == 0:
                    end, col = i, j
                    break
            if end is not None:
                break
        if end is None:
            raise SystemExit('Не найден конец проверки %s:%d' % (rel, lineno))
        lines[end] = lines[end][:col + 1] + ' end;' + lines[end][col + 1:]
        stripped = lines[start].lstrip()
        indent = lines[start][:len(lines[start]) - len(stripped)]
        lines[start] = "%sbegin TraceHit('%s:%d'); %s" % (indent, rel, lineno, stripped)
    text = '\r\n'.join(lines)
    # Модуль трассировки — в раздел uses реализации.
    text = re.sub(r'(\nimplementation\s*\r\n\s*uses\s*\r\n)', r'\1  MineHunter.Tests.Trace,\r\n', text, count=1)
    if 'MineHunter.Tests.Trace' not in text:
        raise SystemExit('Нет раздела uses реализации в %s' % rel)
    out = os.path.join(TRACE_DIR, os.path.basename(rel))
    open(out, 'w', encoding='utf-8-sig', newline='').write(text)
    return out


def main():
    checks = json.load(open(os.path.join(ROOT, 'build', 'binarylab-checks.json'), encoding='utf-8'))
    by_file = {}
    for item in checks:
        by_file.setdefault(item['file'], set()).add(item['line'])
    if os.path.isdir(TRACE_DIR):
        shutil.rmtree(TRACE_DIR)
    os.makedirs(TRACE_DIR)
    copies = {rel: instrument(rel, marks) for rel, marks in by_file.items()}
    # Проект тестов с путями к копиям; остальные модули — из исходных папок (абсолютные пути).
    dpr = open(os.path.join(ROOT, 'tests', 'MineHunter.Tests.dpr'), encoding='utf-8-sig').read()
    tests_dir = os.path.join(ROOT, 'tests')

    def repath(m):
        rel_in_tests = m.group(2).replace('\\', '/')
        rel = os.path.relpath(os.path.normpath(os.path.join(tests_dir, rel_in_tests)), ROOT).replace('\\', '/')
        path = copies.get(rel, os.path.normpath(os.path.join(tests_dir, rel_in_tests)))
        return "%s in '%s'" % (m.group(1), path)

    dpr = re.sub(r"(\w[\w.]*) in '([^']+)'", repath, dpr)
    dpr = re.sub(r"\{\$R '([^']+)' '([^']+)'\}",
                 lambda m: "{$R '%s' '%s'}" % (os.path.normpath(os.path.join(tests_dir, m.group(1))),
                                              os.path.normpath(os.path.join(tests_dir, m.group(2)))), dpr)
    dpr = dpr.replace('  MineHunter.Tests.PeBuilder in',
                      "  MineHunter.Tests.Trace in '%s',\n  MineHunter.Tests.PeBuilder in" %
                      os.path.join(ROOT, 'tests', 'Fixtures', 'MineHunter.Tests.Trace.pas'), 1)
    dpr_path = os.path.join(TRACE_DIR, 'MineHunter.Tests.dpr')
    open(dpr_path, 'w', encoding='utf-8-sig', newline='\r\n').write(dpr)
    summary = {}
    failed = False
    for config in ('Debug', 'Release'):
        out_name = 'traceout-' + config
        build = subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-File',
                                os.path.join(ROOT, 'tools', 'dcc_config.ps1'), '-Dpr', dpr_path, '-Out', out_name,
                                '-Config', config], capture_output=True, cwd=ROOT)
        log = build.stdout.decode('cp866', errors='replace')
        if build.returncode != 0 or re.search(r'\b(Error|Fatal)\b', log):
            print(log[-3000:])
            raise SystemExit('Сборка трассировки %s не удалась' % config)
        exe = os.path.join(ROOT, 'build', 'tmp', out_name, 'MineHunter.Tests.exe')
        hits_file = os.path.join(ROOT, 'build', 'tmp', out_name, 'hits.txt')
        if os.path.exists(hits_file):
            os.remove(hits_file)
        env = dict(os.environ, MH_TRACE_FILE=hits_file)
        xml = os.path.join(ROOT, 'build', 'tmp', out_name, 'results.xml')
        run = subprocess.run([exe, '--exitbehavior:Continue', '--consolemode:Quiet', '--xml:' + xml], capture_output=True,
                             env=env, cwd=os.path.dirname(exe), timeout=3000)
        if os.path.exists(xml):
            text = open(xml, encoding='utf-8', errors='replace').read()
            for name, message in re.findall(r'<test-case name="([^"]+)"[^>]*success="False"[^>]*>[\s\S]*?'
                                            r'<message>([\s\S]*?)</message>', text):
                print('FAILED (%s): %s — %s' % (config, name, message.strip()[:300]))
        out = run.stdout.decode('cp866', errors='replace')
        found = re.search(r'Tests Found\s*:\s*(\d+)', out)
        passed = re.search(r'Tests Passed\s*:\s*(\d+)', out)
        all_passed = bool(run.returncode == 0 and found and passed and found.group(1) == passed.group(1))
        hits = {}
        for line in open(hits_file, encoding='utf-8-sig').read().splitlines():
            key, count = line.split('\t')
            hits[key] = int(count)
        not_hit = [('%s:%d' % (c['file'], c['line'])) for c in checks if hits.get('%s:%d' % (c['file'], c['line']), 0) == 0]
        summary[config] = {'tests_found': found.group(1) if found else None,
                           'tests_passed': passed.group(1) if passed else None, 'all_passed': all_passed,
                           'executed': {('%s:%d' % (c['file'], c['line'])): hits.get('%s:%d' % (c['file'], c['line']), 0)
                                        for c in checks}}
        print('%s: tests %s/%s passed; checks=%d executed=%d not_executed=%d' % (
            config, summary[config]['tests_passed'], summary[config]['tests_found'], len(checks),
            len(checks) - len(not_hit), len(not_hit)))
        for key in not_hit:
            print('NOT EXECUTED (%s): %s' % (config, key))
        failed = failed or not all_passed or bool(not_hit)
    with open(os.path.join(ROOT, 'build', 'binarylab-assert-trace.json'), 'w', encoding='utf-8') as f:
        json.dump({'checks': checks, 'configs': summary}, f, ensure_ascii=False, indent=0)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
