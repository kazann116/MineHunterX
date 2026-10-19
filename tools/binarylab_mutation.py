"""Мутационное тестирование ядра BinaryLab.

Для каждого мутанта в копию одного модуля src/Core/BinaryLab вносится одна ошибка
(оператор сравнения, граница, логическая связка, арифметика, логическая константа).
Копия набора тестов собирается с мутантом (tools/dcc_config.ps1, Debug) и запускаются
тесты категории BinaryLab. Мутант «убит», если тест упал, процесс завис (тайм-аут) или
аварийно завершился; «выжил» — если все тесты прошли. Не скомпилировавшиеся мутанты
не учитываются.

Итог — build/binarylab-mutation.json. Запуск:
  python tools/binarylab_mutation.py [число мутантов, по умолчанию 60] [начальное число]
  python tools/binarylab_mutation.py --survivors   — повторить только выживших прошлого прогона
    (после новых тестов); итог — build/binarylab-mutation-survivors.json
"""
import json
import os
import random
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(ROOT, 'build', 'tmp', 'mutation')
CORE = os.path.join(ROOT, 'src', 'Core', 'BinaryLab')

# (шаблон, замена, описание) — применяются к коду вне комментариев и строк.
OPERATORS = [
    (r'(?<![<>:=])>=(?!=)', '>', '>= → >'),
    (r'(?<![<>:=])<=(?!=)', '<', '<= → <'),
    (r'(?<![<>:=])>(?![=>])', '>=', '> → >='),
    (r'(?<![<>:=])<(?![=>])', '<=', '< → <='),
    (r'(?<![<>:])=(?![=>])', '<>', '= → <>'),
    (r'<>', '=', '<> → ='),
    (r'\band\b', 'or', 'and → or'),
    (r'\bor\b', 'and', 'or → and'),
    (r'(?<=[\w)\]]) \+ 1\b', ' + 2', '+ 1 → + 2'),
    (r'(?<=[\w)\]]) - 1\b', '', '- 1 → (убрано)'),
    (r'\bTrue\b', 'False', 'True → False'),
]


def code_spans(line):
    """Части строки вне строковых литералов и комментария //."""
    spans = []
    start = 0
    in_string = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'":
            if not in_string:
                spans.append((start, i))
            else:
                start = i + 1
            in_string = not in_string
        elif not in_string and line[i:i + 2] == '//':
            spans.append((start, i))
            return spans
        i += 1
    if not in_string:
        spans.append((start, len(line)))
    return spans


def candidate_sites():
    sites = []
    for name in sorted(os.listdir(CORE)):
        if not name.endswith('.pas'):
            continue
        path = os.path.join(CORE, name)
        lines = open(path, encoding='utf-8-sig').read().split('\n')
        try:
            begin = next(i for i, l in enumerate(lines) if l.strip() == 'implementation')
        except StopIteration:
            continue
        in_brace = False
        for no in range(begin + 1, len(lines)):
            line = lines[no]
            stripped = line.strip()
            if in_brace:
                if '}' in line:
                    in_brace = False
                continue
            if stripped.startswith('{') and '}' not in stripped:
                in_brace = True
                continue
            # Только исполняемые строки: не объявления, не uses, не const-таблицы.
            if not stripped or stripped.startswith(('//', '{', 'uses', 'function ', 'procedure ', 'constructor ',
                                                     'destructor ', 'class ', 'type', 'var', 'const')):
                continue
            if not re.search(r'\b(if|while|until|Result|:=|Exit|and|or)\b|[<>]', line):
                continue
            for pattern, replacement, title in OPERATORS:
                for a, b in code_spans(line):
                    for m in re.finditer(pattern, line[a:b]):
                        sites.append((name, no, a + m.start(), a + m.end(), replacement, title))
    return sites


def run(cmd, timeout, env=None, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env, cwd=cwd)
        return p.returncode, p.stdout.decode('cp866', errors='replace'), False
    except subprocess.TimeoutExpired:
        return None, '', True


def main():
    survivors_mode = len(sys.argv) > 1 and sys.argv[1] == '--survivors'
    count = int(sys.argv[1]) if len(sys.argv) > 1 and not survivors_mode else 60
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 2026
    previous = []
    if survivors_mode:
        data = json.load(open(os.path.join(ROOT, 'build', 'binarylab-mutation.json'), encoding='utf-8'))
        previous = [r for r in data['results'] if r['status'] == 'выжил']
        seed = data['seed']
    sites = candidate_sites()
    rng = random.Random(seed)
    # Равномерно по модулям: каждому модулю — доля мутантов.
    by_unit = {}
    for s in sites:
        by_unit.setdefault(s[0], []).append(s)
    chosen = []
    units = sorted(by_unit)
    while not survivors_mode and len(chosen) < count and any(by_unit.values()):
        for unit in units:
            if by_unit[unit] and len(chosen) < count:
                chosen.append(by_unit[unit].pop(rng.randrange(len(by_unit[unit]))))
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK)
    tests_dir = os.path.join(ROOT, 'tests')
    dpr_text = open(os.path.join(tests_dir, 'MineHunter.Tests.dpr'), encoding='utf-8-sig').read()
    results = []
    if survivors_mode:
        chosen = [(r['unit'], r['line'] - 1, None, None, r['mutated'], r['mutation']) for r in previous]
    for index, (unit, no, a, b, replacement, title) in enumerate(chosen, 1):
        src_path = os.path.join(CORE, unit)
        lines = open(src_path, encoding='utf-8-sig', newline='').read().split('\r\n')
        original = lines[no]
        if a is None:
            # Повтор выжившего: строка целиком, с прежним отступом.
            lines[no] = original[:len(original) - len(original.lstrip())] + replacement
        else:
            lines[no] = original[:a] + replacement + original[b:]
        mutant_dir = os.path.join(WORK, 'src')
        os.makedirs(mutant_dir, exist_ok=True)
        mutant_path = os.path.join(mutant_dir, unit)
        open(mutant_path, 'w', encoding='utf-8-sig', newline='').write('\r\n'.join(lines))

        def repath(m):
            path = os.path.normpath(os.path.join(tests_dir, m.group(2)))
            if os.path.normcase(path) == os.path.normcase(src_path):
                path = mutant_path
            return "%s in '%s'" % (m.group(1), path)

        dpr = re.sub(r"(\w[\w.]*) in '([^']+)'", repath, dpr_text)
        dpr = re.sub(r"\{\$R '([^']+)' '([^']+)'\}",
                     lambda m: "{$R '%s' '%s'}" % (os.path.normpath(os.path.join(tests_dir, m.group(1))),
                                                  os.path.normpath(os.path.join(tests_dir, m.group(2)))), dpr)
        dpr_path = os.path.join(WORK, 'MineHunter.Tests.dpr')
        open(dpr_path, 'w', encoding='utf-8-sig', newline='\r\n').write(dpr)
        code, log, _ = run(['powershell', '-ExecutionPolicy', 'Bypass', '-File', os.path.join(ROOT, 'tools', 'dcc_config.ps1'),
                            '-Dpr', dpr_path, '-Out', 'mutation-out', '-Config', 'Debug'], 900, cwd=ROOT)
        entry = {'unit': unit, 'line': no + 1, 'mutation': title, 'original': original.strip(),
                 'mutated': lines[no].strip()}
        if code != 0 or re.search(r'\b(Error|Fatal)\b', log):
            entry['status'] = 'не компилируется'
        else:
            exe = os.path.join(ROOT, 'build', 'tmp', 'mutation-out', 'MineHunter.Tests.exe')
            code, out, timed_out = run([exe, '--exitbehavior:Continue', '--consolemode:Quiet', '--include:BinaryLab',
                                        '--exclude:UI'], 300, cwd=os.path.dirname(exe))
            failed = re.search(r'Tests Failed\s*:\s*(\d+)', out)
            errored = re.search(r'Tests Errored\s*:\s*(\d+)', out)
            if timed_out:
                entry['status'] = 'убит (зависание)'
            elif code != 0 or (failed and int(failed.group(1)) > 0) or (errored and int(errored.group(1)) > 0) \
                    or not failed:
                names = re.findall(r'^\s+(MineHunter\.Tests\.[\w.]+)\s*$', out, re.M)
                entry['status'] = 'убит'
                entry['killed_by'] = names[:5]
            else:
                entry['status'] = 'выжил'
        results.append(entry)
        print('%2d/%d %-8s %s:%d %s' % (index, len(chosen), entry['status'], unit, no + 1, title), flush=True)
    valid = [r for r in results if r['status'] != 'не компилируется']
    killed = [r for r in valid if r['status'].startswith('убит')]
    summary = {'seed': seed, 'mutants': len(results), 'compiled': len(valid), 'killed': len(killed),
               'survived': len(valid) - len(killed),
               'score_percent': round(100.0 * len(killed) / len(valid), 1) if valid else 0.0, 'results': results}
    name = 'binarylab-mutation-survivors.json' if survivors_mode else 'binarylab-mutation.json'
    with open(os.path.join(ROOT, 'build', name), 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print('mutants=%d compiled=%d killed=%d survived=%d score=%.1f%%' % (
        len(results), len(valid), len(killed), len(valid) - len(killed), summary['score_percent']))
    for r in valid:
        if r['status'] == 'выжил':
            print('SURVIVED: %s:%d %s | %s' % (r['unit'], r['line'], r['mutation'], r['mutated']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
