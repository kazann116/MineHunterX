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


_C = 'App.BinaryLab.Controls.'
_P = 'App.BinaryLabPage.'
# Части интерфейса из ТЗ → публичные функции элементов и страницы (каждая функция App.* — в одной части).
UI_PARTS = [
    ('Интерактивная карта (энтропия, гистограмма)',
     [_C + n for n in ('SetData', 'SetBands', 'BlockAtPoint', 'CellRect', 'CellCount', 'BlockCount', 'BlocksPerCell',
                       'EntropyColor', 'SetHistogram', 'ByteAtPoint', 'BarRect', 'BarFraction', 'HintTextAt',
                       'MHBlendColor')]),
    ('Hex Viewer (просмотр, поиск, смещения, подсветка)',
     [_C + n for n in ('GotoOffset', 'FindNext', 'AddHighlight', 'ClearHighlights', 'HighlightAt', 'HighlightCount',
                       'OffsetAtPoint', 'PointOfOffset', 'VisibleRows', 'RowCount', 'OffsetDigits', 'ContentWidth',
                       'ScrollRows', 'InvalidateData')] + [_P + 'ShowOffset', _P + 'ParseOffset', _P + 'FindPattern']),
    ('Асинхронный анализ (фон, отмена, закрытие во время работы)',
     [_P + n for n in ('OpenFile', 'Cancel', 'Busy', 'ExportReport')]),
    ('Сравнение файлов (BinaryDiff в интерфейсе)',
     [_P + 'CompareWith', _P + 'ExportDiff', _C + 'SetRanges', _C + 'OffsetAtX', _C + 'RangeAtX']),
]

# Эквивалентные мутанты (не меняют наблюдаемого поведения) — с обоснованием.
EQUIVALENT_MUTANTS = {
    ('MineHunter.BinaryLab.Analyzer.pas', 129, 'and → or'):
        'для секции без данных или за концом файла MHRangeEntropy и так возвращает -1, хеш пуст',
    ('MineHunter.BinaryLab.Analyzer.pas', 129, '< → <='):
        'секция, начинающаяся ровно в конце файла, не имеет данных: энтропия -1, хеш пуст',
    ('MineHunter.BinaryLab.FileType.pas', 201, '>= → >'):
        'файл из двух байт FF FE и так признаётся текстом (байты печатные)',
    ('MineHunter.BinaryLab.FileType.pas', 209, '= → <>'):
        'байты метки UTF-8 печатные: файл остаётся текстом с тем же видом',
    ('MineHunter.BinaryLab.Report.pas', 433, '< → <='):
        'при энтропии ровно 6,8 обе ветки дают один и тот же цвет (непрерывная шкала)',
    ('MineHunter.BinaryLab.Anomalies.pas', 661, '> → >='):
        'признаки с нулевым весом не меняют ни оценку, ни итог (оценка ниже порога)',
    ('MineHunter.BinaryLab.Types.pas', 739, '<= → <'):
        'при нулевой сумме все счётчики нулевые — деления нет, результат 0',
    ('MineHunter.BinaryLab.Diff.pas', 264, '> → >='):
        'разница энтропий ровно 0,01 при дробных значениях недостижима; 0,01 сравнивается как порог шума',
    ('MineHunter.BinaryLab.FileType.pas', 384, 'and → or'):
        'без сигнатуры ICO поле не читается (сокращённое вычисление), а LWord инициализировано нулём — '
        'условие «число значков 1..64» ложно; ложный ICO проверен тестом Detect_IconCountWithoutSignature_IsNotIcon',
    ('MineHunter.BinaryLab.Strings.pas', 771, '<> → ='):
        'два прохода UTF-16 (чётный и нечётный) меняются местами, объединение результатов то же; '
        'строка на нечётном смещении через границу блока проверена тестом Strings_Utf16OddOffsetAcrossChunk',
}

# Эквивалентные мутанты интерфейса — с обоснованием.
UI_EQUIVALENT_MUTANTS = {
    ('MineHunter.App.BinaryLab.Controls.pas', 879, '<= → <'):
        'MoveCaret вызывается только из KeyDown, MouseDown, MouseMove и SetCaretOffset — все выходят при пустом файле',
    ('MineHunter.App.BinaryLab.Controls.pas', 910, 'or → and'):
        'размер берётся из источника (нет источника — размер 0); у пустого источника поиск ничего не находит и так',
    ('MineHunter.App.BinaryLab.Controls.pas', 1175, 'and → or'):
        'отбор подсветок только ускоряет рисование: подсветка вне видимых строк не закрашивает ни одной видимой ячейки',
    ('MineHunter.App.BinaryLab.Controls.pas', 1851, '- 1 → (убрано)'):
        'при LRel < W - 1 значение Trunc(LRel / W * размер) всегда меньше размера: верхняя граница недостижима',
    ('MineHunter.App.BinaryLabPage.pas', 875, 'or → and'):
        'хранилище вердиктов создаётся вместе с сервисами и обнуляется после закрытия окна, '
        'а у открытого отчёта путь всегда задан: обе проверки защитные',
    ('MineHunter.App.BinaryLabPage.pas', 1257, '> → >='):
        'AddHighlight отбрасывает подсветку нулевого размера: без оверлея подсветки нет в обоих случаях',
    ('MineHunter.App.BinaryLabPage.pas', 1322, 'or → and'):
        'виртуальный список запрашивает только строки 0..Count-1, а Count = числу отобранных строк',
}

RESULT_FILES = {'Debug': os.path.join(ROOT, 'build', 'tests-Debug.xml'),
                'Release': os.path.join(ROOT, 'build', 'tests-Release.xml')}


def load_isolated():
    """Итоги изолированного прогона (tools/binarylab_isolated_run.py): сборка → {тест: пройден}."""
    path = os.path.join(ROOT, 'build', 'binarylab-isolated.json')
    if not os.path.exists(path):
        return {}
    import json
    return json.load(open(path, encoding='utf-8'))


def load_trace():
    """Построчная трассировка (tools/binarylab_assert_trace.py): сборка → {«файл:строка»: число выполнений}.
    Сборка, где не все тесты прошли, даёт пустой словарь (ни одна строка не засчитывается)."""
    path = os.path.join(ROOT, 'build', 'binarylab-assert-trace.json')
    if not os.path.exists(path):
        return {}
    import json
    data = json.load(open(path, encoding='utf-8'))
    return {config: (info['executed'] if info.get('all_passed') else {})
            for config, info in data.get('configs', {}).items()}


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


def mutation_block(missing, prefix, unit_prefix, equivalents, heading, intro):
    """Итог одного мутационного прогона: выжившие → убиты новыми тестами или эквивалентны."""
    import json
    path = os.path.join(ROOT, 'build', prefix + '.json')
    if not os.path.exists(path):
        missing.append('Нет итога мутационного прогона build/%s.json' % prefix)
        return []
    data = json.load(open(path, encoding='utf-8'))
    again_path = os.path.join(ROOT, 'build', prefix + '-survivors.json')
    again = {}
    if os.path.exists(again_path):
        for r in json.load(open(again_path, encoding='utf-8'))['results']:
            again[(r['unit'], r['line'], r['mutation'])] = r['status']
    out = ['', heading, ''] + intro + ['',
           'Первый прогон: мутантов %d, скомпилировалось %d, убито %d, выжило %d (%.1f%%).' % (
               data['mutants'], data['compiled'], data['killed'], data['survived'], data['score_percent']), '',
           '| Мутант | Было выжившим | Итог |', '|---|---|---|']
    final_killed = data['killed']
    equivalent = 0
    for r in data['results']:
        if r['status'] != 'выжил':
            continue
        key = (r['unit'], r['line'], r['mutation'])
        name = '`%s:%d` %s' % (r['unit'].replace(unit_prefix, ''), r['line'], r['mutation'])
        if again.get(key, '').startswith('убит'):
            final_killed += 1
            result = 'убит новыми тестами'
        elif key in equivalents:
            equivalent += 1
            result = 'эквивалентный: ' + equivalents[key]
        else:
            result = '**выжил**'
            missing.append('Мутант %s:%d %s выжил и не признан эквивалентным' % key)
        out.append('| %s | `%s` | %s |' % (name, r['mutated'].replace('|', '\\|'), result))
    useful = data['compiled'] - equivalent
    out += ['', 'Итог: из %d неэквивалентных мутантов убито %d (%.1f%%), эквивалентных %d.' % (
        useful, final_killed, 100.0 * final_killed / useful if useful else 0, equivalent)]
    return out


def mutation_section(missing):
    """Мутационное тестирование ядра и интерфейса."""
    out = mutation_block(missing, 'binarylab-mutation', 'MineHunter.BinaryLab.', EQUIVALENT_MUTANTS,
                         '## Мутационное тестирование',
                         ['В копию модуля ядра вносится одна ошибка, тесты собираются и запускаются '
                          '(`python tools/binarylab_mutation.py`).',
                          'Мутант должен быть убит упавшим тестом. Выжившие повторены после новых тестов',
                          '(`--survivors`, `tests/Unit/MineHunter.Tests.BinaryLab.Mutation.pas`); '
                          'эквивалентные — с обоснованием.'])
    out += mutation_block(missing, 'binarylab-mutation-ui', 'MineHunter.App.', UI_EQUIVALENT_MUTANTS,
                          '### Интерфейс',
                          ['Ошибка вносится в элементы (`App.BinaryLab.Controls`) или страницу (`App.BinaryLabPage`); '
                           'запускаются тесты BinaryLab, включая элементы, и сценарии страницы из UI Smoke',
                           '(`python tools/binarylab_mutation.py --ui`, повтор выживших — `--survivors --ui`).'])
    return out


def main():
    tests = test_procedures()
    results = load_results()
    isolated = load_isolated()
    trace = load_trace()
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
            for config, executed in trace.items():
                done = sum(1 for rel, lineno, _t, _x in checks if executed.get('%s:%d' % (rel, lineno), 0) > 0)
                for rel, lineno, _t, _x in checks:
                    if executed.get('%s:%d' % (rel, lineno), 0) == 0:
                        missing.append('%s — строка %s:%d не выполнялась в %s' % (key, rel, lineno, config))
                run.append('строк Assert выполнено в %s %d/%d' % (config, done, len(checks)))
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
           '`build/binarylab-isolated.json`); «строк Assert выполнено» — построчная трассировка: в копию тестов',
           'перед каждой строкой проверки вставлена отметка, весь набор пройден, и каждая строка выполнилась',
           '(`python tools/binarylab_assert_trace.py`, `build/binarylab-assert-trace.json`).', '',
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
    # Интерфейс по частям ТЗ: каждая функция части — со случаями и итогами прогонов.
    by_key = {'%s.%s' % (u.replace('MineHunter.', ''), n): (c, r) for u, n, _h, c, r in rows}
    out += mutation_section(missing)
    out += ['', '## Интерфейс: отчёт по каждой функции', '']
    for part, keys in UI_PARTS:
        out += ['### ' + part, '', '| Функция | Граничные и ошибочные случаи | Прогон |', '|---|---|---|']
        for key in keys:
            if key not in by_key:
                missing.append('Интерфейс: %s — %s не найдена' % (part, key))
                continue
            (cases, _tests, run_text), _checks = by_key[key]
            out.append('| `%s` | %s | %s |' % (key, cases, run_text))
        out.append('')
    covered = {k for _p, keys in UI_PARTS for k in keys}
    for key in by_key:
        if key.startswith('App.') and key not in covered:
            missing.append('Интерфейс: функция %s не отнесена ни к одной части' % key)
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
    # Полный список проверок — для построчной трассировки (tools/binarylab_assert_trace.py).
    import json
    all_checks = sorted({(rel, lineno, test) for _u, _n, _h, _c, checks in rows for rel, lineno, test, _t in checks})
    with open(os.path.join(ROOT, 'build', 'binarylab-checks.json'), 'w', encoding='utf-8') as f:
        json.dump([{'file': rel, 'line': lineno, 'test': test} for rel, lineno, test in all_checks], f,
                  ensure_ascii=False, indent=0)
    target = os.path.join(ROOT, 'docs', 'binarylab-tests.md')
    with open(target, 'w', encoding='utf-8-sig', newline='\n') as f:
        f.write('\n'.join(out) + '\n')
    print('functions=%d missing=%d' % (len(rows), len(missing)))
    for item in missing:
        print('NO TEST:', item)
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main())
