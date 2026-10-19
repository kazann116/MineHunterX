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


# Признаки проверки граничного или ошибочного случая в тесте: ожидаемое исключение,
# отказ, «не найдено», пустые и предельные значения, отмена, выход за границы,
# повреждённые данные, лимиты.
EDGE = re.compile(r'WillRaise|Assert\.IsFalse|AreEqual(?:<Int64>)?\(-1|MH_NO_OFFSET|\bnil\b|\(\'\'|, \'\'\)|'
                  r'Default\(T|High\(Int64\)|MaxInt|\$FFFFFFFF|\$7FFFFFFF|1, 1\)|Tiny|Huge|Cancel|'
                  r'[Пп]уст|[Оо]тмен|за конц|[Гг]раниц|[Лл]имит|[Оо]брез|[Пп]овреж|[Нн]евер|[Оо]триц|[Оо]шиб|'
                  r'[Нн]ет такого|[Нн]е найден|вне |огромн|[Пп]редел')


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


def test_procedures():
    result = []
    for path in TESTS:
        text = read(path)
        unit = os.path.basename(path)[:-4]
        # Методы тестов и вспомогательные подпрограммы (Detect, CheckCategory…): вызовы
        # из вспомогательных засчитываются тестам, которые их вызывают.
        routines = [(m.group(1) or '', m.group(2), m.group(3)) for m in re.finditer(
            r'^(?:procedure|function) (?:(T\w+)\.)?(\w+)\b[^\n]*\n([\s\S]*?)^end;', text, re.M)]
        declared = set(re.findall(r'\[Test\]\s*procedure\s+(\w+)', text))
        helpers = {name: body for fixture, name, body in routines if name not in declared}
        for fixture, name, body in routines:
            if fixture and name in declared:
                full = body
                for hname, hbody in helpers.items():
                    if re.search(r'\b' + re.escape(hname) + r'\b', body):
                        full += hbody
                # Засчитываются только тесты с проверками (Assert — в тесте или его
                # вспомогательных подпрограммах), а не упоминание функции.
                if 'Assert.' in full:
                    result.append((unit.replace('MineHunter.Tests.', ''), fixture, name, full))
    return result


def main():
    tests = test_procedures()
    rows = []
    missing = []
    for path in SOURCES:
        unit = os.path.basename(path)[:-4]
        for name in sorted(set(public_api(path))):
            if name in ('Create', 'Destroy'):
                continue
            pattern = r'\b' + re.escape(name) + r'\b'
            if name.startswith('Get') and len(name) > 3:
                # Методы чтения свойств вызываются через свойство: GetName — «.Name».
                pattern += r'|\.' + re.escape(name[3:]) + r'\b'
            hits = sorted({'%s.%s' % (fixture, proc) for _u, fixture, proc, body in tests
                           if re.search(pattern, body)})
            edges = sorted({'%s.%s' % (fixture, proc) for _u, fixture, proc, body in tests
                            if re.search(pattern, body) and EDGE.search(body)})
            rows.append((unit, name, hits, edges))
            if not hits:
                missing.append('%s.%s' % (unit, name))
            elif not edges:
                missing.append('%s.%s — нет граничных или ошибочных случаев' % (unit, name))
    out = ['# BinaryLab: матрица «функция → тесты»', '',
           'Создаётся `python tools/binarylab_test_matrix.py` из исходников: для каждой публичной функции и',
           'метода BinaryLab — тесты DUnitX, которые её вызывают (граничные и ошибочные случаи — в тех же тестах).',
           'Внутренние методы отрисовки и потоков проверяются через публичное поведение страницы и элементов.', '',
           '## Требования ТЗ → тесты', '',
           '| Требование | Тесты (граничные и ошибочные случаи) |', '|---|---|']
    for requirement, names in REQUIREMENTS:
        found = [n for n in names if any(proc == n for _u, _f, proc, _b in tests)]
        if len(found) != len(names):
            missing.append('ТЗ: %s — нет тестов %s' % (requirement, sorted(set(names) - set(found))))
        out.append('| %s | %s |' % (requirement, ', '.join('`%s`' % n for n in names)))
    out += ['', '## Публичные функции → тесты', '',
            '| Модуль | Функция | Тесты | Граничные и ошибочные случаи |', '|---|---|---|---|']
    for unit, name, hits, edges in rows:
        shown = ', '.join(hits[:5]) + (' и ещё %d' % (len(hits) - 5) if len(hits) > 5 else '')
        edge_shown = ', '.join(edges[:4]) + (' и ещё %d' % (len(edges) - 4) if len(edges) > 4 else '')
        out.append('| `%s` | `%s` | %s | %s |' % (unit.replace('MineHunter.', ''), name, shown or '**нет**',
                                                  edge_shown or '**нет**'))
    out += ['', 'Функций: %d, без тестов: %d.' % (len(rows), len(missing))]
    target = os.path.join(ROOT, 'docs', 'binarylab-tests.md')
    with open(target, 'w', encoding='utf-8-sig', newline='\n') as f:
        f.write('\n'.join(out) + '\n')
    print('functions=%d missing=%d' % (len(rows), len(missing)))
    for item in missing:
        print('NO TEST:', item)
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main())
