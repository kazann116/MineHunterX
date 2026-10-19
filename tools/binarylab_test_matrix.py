"""Матрица «публичная функция BinaryLab → тесты DUnitX» (docs/binarylab-tests.md).

Публичные функции берутся из интерфейсных частей модулей src/Core/BinaryLab и
страницы/элементов BinaryLab; тесты — процедуры тестовых модулей, в теле которых
встречается имя функции. Функция без тестов — ошибка (код возврата 1).

Запуск: python tools/binarylab_test_matrix.py [--check]
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = sorted(glob.glob(os.path.join(ROOT, 'src', 'Core', 'BinaryLab', '*.pas'))) + [
    os.path.join(ROOT, 'src', 'App', 'MineHunter.App.BinaryLab.Controls.pas'),
    os.path.join(ROOT, 'src', 'App', 'MineHunter.App.BinaryLabPage.pas')]
TESTS = sorted(glob.glob(os.path.join(ROOT, 'tests', 'Unit', 'MineHunter.Tests.BinaryLab.*.pas'))) + [
    os.path.join(ROOT, 'tests', 'UI', 'MineHunter.Tests.UI.BinaryLabControls.pas'),
    os.path.join(ROOT, 'tests', 'UI', 'MineHunter.Tests.UI.Smoke.pas'),
    os.path.join(ROOT, 'tests', 'UI', 'MineHunter.Tests.UI.FileActions.pas')]
# Внутренние методы потоков и отрисовки проверяются через публичное поведение.
SKIP_SECTIONS = ('private', 'protected', 'strict private', 'strict protected', 'private type', 'private const')


REQUIREMENTS = [
    ('1. Типы файлов по содержимому (EXE, DLL, SYS, BIN, DAT…)',
     ['Detect_PeKinds', 'Detect_ArchivesImagesDocuments', 'Detect_TextAndScripts', 'Detect_EmptyAndUnknown',
      'Detect_ExtensionMismatch', 'Detect_DamagedPe_IsMsDos', 'IdentifyAt_StrictRejectsWeakSignatures',
      'Extensions_ExpectedAndInList']),
    ('2. PE Analyzer (заголовки, секции, импорт, экспорт, ресурсы, точка входа, подпись, PE32/PE32+)',
     ['Pe64_HeadersSectionsImportsExports', 'Pe32_OrdinalImportsAndImageBase', 'Resources_TreeTypesLanguagesAndContent',
      'TlsDotNetCertificateOverlay', 'EntryPoint_OffsetSectionAndRvaMapping', 'Checksum_MatchesBuilderIncludingOddLength',
      'NotPe_IsInvalidWithReason', 'Truncated_AtEveryLength_NeverRaises', 'HugeCounts_AreClampedWithWarnings',
      'ImportOutsideFile_AndUnterminatedThunks', 'ResourceCycle_DoesNotHang', 'Limits_ImportsAndExports',
      'Fuzz_RandomHeaderCorruption_NeverRaises', 'Signature_FromFileApi_AndApiFailure', 'RealSystemFiles_SignedAndParsed']),
    ('3. Энтропия, упакованные и шифрованные области, карта',
     ['Entropy_AllZero_NoHighRegions', 'Entropy_AutoBlockSize', 'Entropy_Cancel_Raises', 'Entropy_EmptyAndNilSource',
      'RangeEntropy_BoundsAndClipping', 'Entropy_ShannonBounds', 'Cells_ConsistentWithBlockAtPoint',
      'ManyBlocks_Aggregated', 'Click_RaisesBlockOffset', 'EntropyColor_ScaleMonotonicAndDistinctEnds']),
    ('4. Hex Viewer (просмотр, поиск байтов и строк, смещения, подсветка)',
     ['Goto_ScrollsIntoViewAndSelects', 'Keys_MoveCaret', 'Highlights_LookupAndHint',
      'FindNext_FindsWrapsAndKeepsPositionWhenMissing', 'FindNext_IgnoreCase', 'NilSource_Safe',
      'BigVirtualSource_ScrollsToEndAndReadsOnlyPage', 'FindBytes_FoundCaseLimitAndBoundary', 'FindBytes_EdgeAndErrorCases',
      'ParseHexPattern_ValidAndInvalid', 'BinaryLab_ButtonsDialogsAndDoubleClicks']),
    ('5. Строки ASCII/Unicode, URL, IP, пути, команды, индикаторы',
     ['Classify_Mining', 'Classify_Ip', 'Classify_Domain', 'Classify_Base64AndPlain', 'Strings_MiningWalletCommands']),
    ('6. Вложенные EXE, DLL, архивы, сценарии',
     ['Embedded_RandomData_NoFalsePositives', 'Embedded_Cancel_Raises', 'Embedded_LocateAndMaxScanBytes',
      'Embedded_ExecutableArchiveScript']),
    ('7. BinaryDiff (секции, импорт, строки, ресурсы, блоки)',
     ['Identical_Files', 'Modified_Pe_SectionsImportsExportsResourcesBlocks', 'DifferentSizes_TailIsChanged',
      'NonPe_StringsCompared', 'Limits_Truncated', 'NilAndCancel']),
    ('8. Аномалии PE, необычные секции, скрытые данные, несоответствия формата',
     ['CleanProgram_NoThreatVerdict', 'EntryOutsideSections', 'UpxLikePacking', 'PackedCodeAndEncryptedData',
      'Imports_NoneDynamicFewInjectionAntiDebug', 'DotNet_NoImportsIsNormal', 'Driver_UnsignedAndChecksum',
      'Signature_InvalidAndTrustedHalvesScore', 'Overlay_EncryptedVsInstaller', 'Score_ClampedAndLevelFromThresholds']),
    ('9. Открыть файл процесса в BinaryLab; результаты — в движок угроз',
     ['Menu_OpenInBinaryLab', 'BinaryLab_PageAndMenus', 'FromReport_WeightsSignalsAndCap', 'Store_MatchByPathAndHash',
      'Store_EvictsOldest', 'Store_ConcurrentAccess', 'Engine_AddsBinaryLabEvidenceToProcessFinding',
      'Engine_IgnoresVerdictForChangedFile']),
    ('10. Отчёты JSON и HTML',
     ['Json_RoundTripStructure', 'Html_EscapesFileData', 'Save_ByExtension', 'Diff_JsonAndHtml', 'DiffTitles_AndSaveDiff']),
    ('Без запуска и изменения файла', ['File_AnalysedWithoutModification', 'FileSource_ReadsAndKeepsFileUnchanged',
     'FileSource_OpenWhileFileIsLockedForWrite']),
    ('Асинхронно, без зависания интерфейса', ['BinaryLab_AnalyzeNavigateFindExportCompare',
     'BinaryLab_ErrorsCancelAndCloseWhileBusy', 'Progress_AndCancel']),
    ('Лимиты памяти, повреждённые файлы', ['Partial_WhenLargerThanScanLimit', 'Chunks_LimitAndCancel',
     'Reader_BoundsAreChecked', 'Truncated_AtEveryLength_NeverRaises', 'Fuzz_RandomHeaderCorruption_NeverRaises']),
]


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from binarylab_cases import CASES  # noqa: E402


def read(path):
    return open(path, encoding='utf-8-sig').read()


def public_api(path):
    text = read(path)
    interface = text[text.index('\ninterface'):text.index('\nimplementation')]
    names = []
    section = 'public'
    for line in interface.splitlines():
        stripped = line.strip().lower()
        if stripped in SKIP_SECTIONS or stripped.startswith('private') or stripped.startswith('protected'):
            section = 'private'
            continue
        if stripped.startswith('public') or stripped.startswith('published'):
            section = 'public'
            continue
        if re.match(r'^\s*\w+\s*=\s*(class|record)', line):
            section = 'public'
            continue
        m = re.match(r'^\s*(?:class\s+)?(?:function|procedure|constructor)\s+(\w+)', line)
        if m and section == 'public':
            names.append(m.group(1))
    return names


RESULT_FILES = {'Debug': os.path.join(ROOT, 'build', 'tests-Debug.xml'),
                'Release': os.path.join(ROOT, 'build', 'tests-Release.xml')}


def load_isolated():
    """Итоги изолированного прогона (tools/binarylab_isolated_run.py): сборка → {тест: пройден}."""
    path = os.path.join(ROOT, 'build', 'binarylab-isolated.json')
    if not os.path.exists(path):
        return {}
    import json
    return json.load(open(path, encoding='utf-8'))


def load_results():
    """Итоги прогонов DUnitX (NUnit XML): сборка → {тест: пройден}. Нет файла — сборка пропускается."""
    results = {}
    for config, path in RESULT_FILES.items():
        if not os.path.exists(path):
            continue
        text = open(path, encoding='utf-8', errors='replace').read()
        cases = {}
        for m in re.finditer(r'<test-case name="([^"]+)"[^>]*\bsuccess="(True|False)"', text):
            cases[m.group(1)] = cases.get(m.group(1), True) and m.group(2) == 'True'
        results[config] = cases
    return results


HELPERS = []  # (имя, тело) всех вспомогательных подпрограмм тестов, включая перегрузки


def test_procedures():
    result = []
    for path in TESTS:
        text = read(path)
        unit = os.path.basename(path)[:-4]
        # Методы тестов и вспомогательные подпрограммы (Detect, CheckCategory…): вызовы
        # из вспомогательных засчитываются тестам, которые их вызывают.
        rel = os.path.relpath(path, ROOT).replace('\\', '/')
        routines = []
        for m in re.finditer(r'^(?:procedure|function) (?:(T\w+)\.)?(\w+)\b[^\n]*\n([\s\S]*?)^end;', text, re.M):
            first = text.count('\n', 0, m.start(3)) + 1
            numbered = [(rel, first + i, line) for i, line in enumerate(m.group(3).split('\n'))]
            routines.append((m.group(1) or '', m.group(2), m.group(3), numbered))
        declared = set(re.findall(r'\[Test\]\s*procedure\s+(\w+)', text))
        helpers = {name: (body, numbered) for fixture, name, body, numbered in routines if name not in declared}
        for fixture, name, body, numbered in routines:
            if name not in declared:
                HELPERS.append((name, body))
        for fixture, name, body, numbered in routines:
            if fixture and name in declared:
                full = body
                lines = list(numbered)
                for hname, (hbody, hnumbered) in helpers.items():
                    if re.search(r'\b' + re.escape(hname) + r'\b', body):
                        full += hbody
                        lines += hnumbered
                # Засчитываются только тесты с проверками (Assert — в тесте или его
                # вспомогательных подпрограммах), а не упоминание функции.
                if 'Assert.' in full:
                    result.append((unit.replace('MineHunter.Tests.', ''), fixture, name, full, lines))
    return result


SOURCE_LINES = {}


def condition_of(rel, lineno):
    """Условие (if/else/while/case), под которым стоит строка теста; None — выполняется всегда."""
    if rel not in SOURCE_LINES:
        SOURCE_LINES[rel] = open(os.path.join(ROOT, rel), encoding='utf-8-sig').read().split('\n')
    lines = SOURCE_LINES[rel]
    indent = len(lines[lineno - 1]) - len(lines[lineno - 1].lstrip())
    for j in range(lineno - 2, -1, -1):
        text = lines[j]
        if not text.strip():
            continue
        level = len(text) - len(text.lstrip())
        low = text.strip().lower()
        if level >= indent:
            continue
        if low == 'begin':
            # Строка перед begin (if … then, for … do) стоит на том же уровне.
            indent = level + 1
            continue
        if low.startswith(('if ', 'else', 'while ', 'case ')) or low.endswith(' then'):
            return text.strip()
        if low.startswith(('procedure ', 'function ', 'try', 'finally', 'except', 'var')):
            return None
        indent = level
    return None


def assertion_lines(lines, pattern, test):
    """Строки Assert теста, проверяющие функцию: с её вызовом или сразу после вызова."""
    result = []
    taken = set()

    def take(index):
        rel, lineno, text = lines[index]
        if (rel, lineno) not in taken:
            taken.add((rel, lineno))
            short = ' '.join(text.split())
            result.append((rel, lineno, test, short[:140] + ('…' if len(short) > 140 else '')))

    for i, (_rel, _no, text) in enumerate(lines):
        if not re.search(pattern, text):
            continue
        if 'Assert.' in text:
            take(i)
            continue
        # Продолжение многострочной проверки: Assert на предыдущей строке.
        if i > 0 and 'Assert.' in lines[i - 1][2] and not lines[i - 1][2].rstrip().endswith(';'):
            take(i - 1)
            continue
        # Вызов отдельной строкой — проверки в следующих строках теста.
        count = 0
        for j in range(i + 1, min(i + 7, len(lines))):
            if 'Assert.' in lines[j][2]:
                take(j)
                count += 1
                if count >= 2:
                    break
    return result


def main():
    tests = test_procedures()
    results = load_results()
    isolated = load_isolated()
    rows = []
    missing = []
    used = set()
    for path in SOURCES:
        unit = os.path.basename(path)[:-4]
        for name in sorted(set(public_api(path))):
            if name in ('Create', 'Destroy'):
                continue
            pattern = r'\b' + re.escape(name) + r'\b'
            if name.startswith('Get') and len(name) > 3:
                # Методы чтения свойств вызываются через свойство: GetName — «.Name».
                pattern += r'|\.' + re.escape(name[3:]) + r'\b'
            hits = sorted({'%s.%s' % (fixture, proc) for _u, fixture, proc, body, _l in tests
                           if re.search(pattern, body)})
            # Граничные и ошибочные случаи — по реестру tools/binarylab_cases.py, сверенному с кодом.
            key = '%s.%s' % (unit.replace('MineHunter.', ''), name)
            cases, case_tests = CASES.get(key, ('', []))
            if not case_tests:
                missing.append('%s — нет записи в реестре случаев' % key)
            checks = []
            for test in case_tests:
                found = [(body, lines) for _u, _f, proc, body, lines in tests if proc == test]
                if not found:
                    missing.append('%s — тест %s не найден' % (key, test))
                elif not any(re.search(pattern, body) for body, _l in found):
                    missing.append('%s — тест %s не вызывает функцию' % (key, test))
                # Вызов через вспомогательную подпрограмму теста (Detect, Parse…) — её строка тоже вызов.
                wrappers = sorted({h for h, hbody in HELPERS if re.search(pattern, hbody)})
                check_pattern = pattern + ''.join(r'|\b' + re.escape(h) + r'\(' for h in wrappers)
                for _body, lines in found:
                    checks += assertion_lines(lines, check_pattern, test)
            if case_tests and not checks:
                missing.append('%s — нет строк Assert, проверяющих функцию' % key)
            # Тесты случаев должны быть в последнем прогоне каждой сборки и пройти.
            run = []
            for config, cases_run in results.items():
                passed = sum(1 for t in case_tests if cases_run.get(t) is True)
                for t in case_tests:
                    if t not in cases_run:
                        missing.append('%s — тест %s не выполнялся в %s' % (key, t, config))
                    elif not cases_run[t]:
                        missing.append('%s — тест %s не пройден в %s' % (key, t, config))
                run.append('%s %d/%d' % (config, passed, len(case_tests)))
            for config, cases_run in isolated.items():
                alone = sum(1 for t in case_tests if cases_run.get(t) is True)
                for t in case_tests:
                    if cases_run.get(t) is not True:
                        missing.append('%s — тест %s не прошёл изолированно в %s' % (key, t, config))
                run.append('отдельно %s %d/%d' % (config, alone, len(case_tests)))
            run_text = ', '.join(run) or 'не запускались'

            used.add(key)
            rows.append((unit, name, hits, (cases, case_tests, run_text), checks))
            if not hits:
                missing.append('%s.%s' % (unit, name))
    out = ['# BinaryLab: матрица «функция → тесты»', '',
           'Создаётся `python tools/binarylab_test_matrix.py` из исходников: для каждой публичной функции и',
           'метода BinaryLab — граничные и ошибочные случаи из реестра `tools/binarylab_cases.py` и тесты, которые их',
           'проверяют. Генератор сверяет каждую запись с кодом: тест существует, вызывает функцию и содержит Assert.',
           'Внутренние методы отрисовки и потоков проверяются через публичное поведение страницы и элементов.', '',
           '## Требования ТЗ → тесты', '',
           'Колонка «Прогон» — итоги последнего запуска всех тестов (`build/tests-Debug.xml`,',
           '`build/tests-Release.xml`, отчёты NUnit XML DUnitX): сколько тестов случаев выполнено и пройдено;',
           '«отдельно» — каждый тест случая запущен своим процессом (`python tools/binarylab_isolated_run.py`,',
           '`build/binarylab-isolated.json`).', '',
           '| Требование | Тесты (граничные и ошибочные случаи) | Прогон |', '|---|---|---|']
    for requirement, names in REQUIREMENTS:
        found = [n for n in names if any(proc == n for _u, _f, proc, _b, _l in tests)]
        if len(found) != len(names):
            missing.append('ТЗ: %s — нет тестов %s' % (requirement, sorted(set(names) - set(found))))
        run = []
        for config, cases_run in results.items():
            passed = sum(1 for n in names if cases_run.get(n) is True)
            if passed != len(names):
                missing.append('ТЗ: %s — в %s пройдено %d из %d' % (requirement, config, passed, len(names)))
            run.append('%s %d/%d' % (config, passed, len(names)))
        out.append('| %s | %s | %s |' % (requirement, ', '.join('`%s`' % n for n in names),
                                         ', '.join(run) or 'не запускались'))
    out += ['', '## Публичные функции → тесты', '',
            '| Модуль | Функция | Граничные и ошибочные случаи | Тесты этих случаев | Прогон | Все тесты с вызовом |',
            '|---|---|---|---|---|---|']
    for key in sorted(set(CASES) - used):
        missing.append('%s — запись реестра без функции' % key)
    for unit, name, hits, (cases, case_tests, run_text), _checks in rows:
        shown = ', '.join(hits[:4]) + (' и ещё %d' % (len(hits) - 4) if len(hits) > 4 else '')
        out.append('| `%s` | `%s` | %s | %s | %s | %s |' % (unit.replace('MineHunter.', ''), name, cases or '**нет**',
                                                            ', '.join('`%s`' % t for t in case_tests) or '**нет**',
                                                            run_text, shown or '**нет**'))
    conditional = []
    for _unit, _name, _hits, _cases, checks in rows:
        for rel, lineno, test, _text in checks:
            guard = condition_of(rel, lineno)
            if guard:
                conditional.append((rel, lineno, test, guard))
    out += ['', '## Проверки по функциям', '',
            'Строки `Assert`, которые проверяют функцию в тестах её граничных и ошибочных случаев: строка с',
            'вызовом функции или проверка сразу после вызова (файл:строка — текст проверки).', '',
            'DUnitX прерывает тест на первой неудачной проверке, поэтому пройденный тест означает, что каждая',
            'выполненная строка `Assert` в нём прошла. Строки под условием `if` перечислены ниже: для каждой тест',
            'отдельно проверяет, что ветка выполнялась (счётчик или предусловие).', '']
    for rel, lineno, test, guard in conditional:
        out.append('- условная: `%s:%d` (%s) под `%s`' % (rel, lineno, test, guard))
    out.append('')
    total_checks = 0
    for unit, name, _hits, _cases, checks in rows:
        total_checks += len(checks)
        out.append('### `%s.%s` — проверок: %d' % (unit.replace('MineHunter.', ''), name, len(checks)))
        out.append('')
        for rel, lineno, test, text in checks[:12]:
            out.append('- `%s:%d` (%s): `%s`' % (rel, lineno, test, text.replace('`', "'")))
        if len(checks) > 12:
            out.append('- … и ещё %d' % (len(checks) - 12))
        out.append('')
    out += ['Функций: %d, проверок: %d (под условием: %d), пропусков: %d. Прогоны: %s.' % (
        len(rows), total_checks, len(conditional), len(missing),
        ', '.join('%s — %d тестов, пройдено %d' % (c, len(r), sum(1 for v in r.values() if v))
                  for c, r in results.items()) or 'нет')]
    target = os.path.join(ROOT, 'docs', 'binarylab-tests.md')
    with open(target, 'w', encoding='utf-8-sig', newline='\n') as f:
        f.write('\n'.join(out) + '\n')
    print('functions=%d missing=%d' % (len(rows), len(missing)))
    for item in missing:
        print('NO TEST:', item)
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main())
