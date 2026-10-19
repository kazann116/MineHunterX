"""Реестр граничных и ошибочных случаев BinaryLab: функция → (что проверено, тесты).

Каждая запись сверяется tools/binarylab_test_matrix.py с кодом: тест существует,
вызывает функцию (или её свойство) и содержит проверки Assert. Функция без записи
или запись с неверным тестом — ошибка генератора.
"""

CASES = {
    # --- Анализ целиком ---
    'BinaryLab.Analyzer.MHAnalyzeBinaryFile': (
        'нет файла → EMHBinaryLabError; файл не изменяется и не блокируется после анализа; сбой и отключение '
        'проверки подписи; настоящие системные файлы',
        ['File_Missing_Raises', 'File_AnalysedWithoutModification', 'Signature_FromFileApi_AndApiFailure',
         'RealSystemFiles_SignedAndParsed']),
    'BinaryLab.Analyzer.MHAnalyzeBinarySource': (
        'nil-источник → EArgumentNilException; пустой файл; случайные данные; файл больше лимита сканирования; '
        'отмена на середине; ход выполнения только растёт',
        ['File_Missing_Raises', 'TextEmptyAndUnknown', 'Partial_WhenLargerThanScanLimit', 'Progress_AndCancel']),
    # --- Аномалии ---
    'BinaryLab.Anomalies.MHDetectAnomalies': (
        'чистая программа без признаков; не-PE и повреждённый заголовок; .NET без импорта; драйвер без подписи; '
        'установщик со сжатым оверлеем; пустой отчёт',
        ['CleanProgram_NoThreatVerdict', 'DamagedHeader_NonPeData', 'DotNet_NoImportsIsNormal',
         'Driver_UnsignedAndChecksum', 'Overlay_EncryptedVsInstaller', 'ExtensionMismatch_ExecutableVsData']),
    'BinaryLab.Anomalies.MHDetectInstaller': (
        'нет строк → пусто; строка установщика → имя',
        ['Overlay_EncryptedVsInstaller']),
    'BinaryLab.Anomalies.MHPackerBySectionName': (
        'регистр не важен; обычная секция → пусто',
        ['UpxLikePacking']),
    'BinaryLab.Anomalies.MHScoreBinaryReport': (
        'сумма больше 100 → 100; только сведения → 0; доверенная подпись делит пополам',
        ['Score_ClampedAndLevelFromThresholds', 'Signature_InvalidAndTrustedHalvesScore', 'DamagedHeader_NonPeData']),
    # --- Сравнение ---
    'BinaryLab.Diff.MHCompareBinaries': (
        'идентичные файлы; разный размер (хвост); не-PE; предел элементов и лимит байтов → Truncated; '
        'nil-источник → исключение; отмена',
        ['Identical_Files', 'DifferentSizes_TailIsChanged', 'NonPe_StringsCompared', 'Limits_Truncated',
         'NilAndCancel']),
    'BinaryLab.Diff.MHDiffAreaTitle': (
        'все области переведены; неизвестная область — как есть',
        ['DiffTitles_AndSaveDiff']),
    # --- Вложения ---
    'BinaryLab.Embedded.MHFindEmbedded': (
        'случайные данные без ложных срабатываний; слабые сигнатуры в тексте; смещение 0 не считается; '
        'ложный размер не прячет остаток; предел числа объектов; границы блоков; лимит сканирования; отмена',
        ['Embedded_RandomData_NoFalsePositives', 'Embedded_WeakSignaturesInText_Ignored',
         'Embedded_OffsetZero_NotReported', 'Embedded_BogusSize_DoesNotHideRest', 'Embedded_MaxEmbeddedLimit',
         'Embedded_ChunkBoundaries', 'Embedded_LocateAndMaxScanBytes', 'Embedded_Cancel_Raises']),
    # --- Энтропия ---
    'BinaryLab.Entropy.MHAnalyzeEntropy': (
        'пустой и nil-источник; файл в несколько байт; неполный последний блок; одни нули; блоки через границу '
        'чтения; лимит сканирования; отмена',
        ['Entropy_EmptyAndNilSource', 'Entropy_TinyFile', 'Entropy_ExplicitBlockSize_LastPartialBlock',
         'Entropy_AllZero_NoHighRegions', 'Entropy_BlocksAcrossReadChunks', 'Entropy_MaxScanBytesRespected',
         'Entropy_Cancel_Raises']),
    'BinaryLab.Entropy.MHRangeEntropy': (
        'диапазон за концом и отрицательный → -1; обрезка у конца файла',
        ['RangeEntropy_BoundsAndClipping']),
    # --- Вид файла ---
    'BinaryLab.FileType.MHDetectBinaryType': (
        'пустой файл; один байт; случайные данные; повреждённый PE и e_lfanew за концом; несоответствие '
        'расширения и его отсутствие',
        ['Detect_EmptyAndUnknown', 'Detect_DamagedPe_IsMsDos', 'Detect_ExtensionMismatch']),
    'BinaryLab.FileType.MHExpectedExtensions': (
        'пустой список для неизвестных и пустых файлов',
        ['Extensions_ExpectedAndInList']),
    'BinaryLab.FileType.MHExtensionInList': (
        'пустое расширение; пустой список; регистр',
        ['Extensions_ExpectedAndInList']),
    'BinaryLab.FileType.MHIdentifyAt': (
        'строгий режим отбрасывает слабые сигнатуры; смещение за концом',
        ['IdentifyAt_StrictRejectsWeakSignatures']),
    'BinaryLab.FileType.MHMachineName': (
        'неизвестная архитектура → код',
        ['MachineSubsystemAndPeKindNames']),
    'BinaryLab.FileType.MHProbePe': (
        'огромный e_lfanew → False; оверлей не входит в образ',
        ['ProbePe_ImageEndAndHugeLfanew']),
    # --- PE ---
    'BinaryLab.Pe.MHComputePeChecksum': (
        'пустой и однобайтовый файл; поле за концом и в начале; перенос разряда; отмена',
        ['Checksum_EmptyTinyFieldOutsideAndCancel', 'Checksum_MatchesBuilderIncludingOddLength']),
    'BinaryLab.Pe.MHParsePe': (
        'не-PE и неизвестный формат; обрезка на каждой длине; огромные счётчики; импорт вне файла и без '
        'завершающего нуля; цикл в ресурсах; лимиты; отмена; 400 испорченных заголовков',
        ['NotPe_IsInvalidWithReason', 'Truncated_AtEveryLength_NeverRaises', 'HugeCounts_AreClampedWithWarnings',
         'ImportOutsideFile_AndUnterminatedThunks', 'ResourceCycle_DoesNotHang', 'Limits_ImportsAndExports',
         'Cancel_Raises', 'Fuzz_RandomHeaderCorruption_NeverRaises']),
    'BinaryLab.Pe.MHPeLocate': (
        'отрицательное смещение; не-PE → пусто; оверлей и подпись различаются',
        ['Locate_DescribesOffsets']),
    'BinaryLab.Pe.MHPeRvaToOffset': (
        'адрес без данных в файле; адрес вне секций; не-PE → MH_NO_OFFSET',
        ['EntryPoint_OffsetSectionAndRvaMapping']),
    'BinaryLab.Pe.MHRangeSha256': (
        'обрезка у конца; диапазон за концом, отрицательный, нулевой; nil-источник → пусто',
        ['RangeSha256_Bounds']),
    'BinaryLab.Pe.MHResourceTypeName': (
        'нестандартный тип → пусто',
        ['Resources_TreeTypesLanguagesAndContent']),
    'BinaryLab.Pe.MHSubsystemName': (
        'неизвестная подсистема → с номером',
        ['MachineSubsystemAndPeKindNames']),
    # --- Отчёты ---
    'BinaryLab.Report.MHBinaryDiffToHtml': (
        'данные с разметкой экранируются',
        ['Diff_JsonAndHtml']),
    'BinaryLab.Report.MHBinaryDiffToJson': (
        'корректный JSON с диапазонами',
        ['Diff_JsonAndHtml']),
    'BinaryLab.Report.MHBinaryReportToHtml': (
        'имена секций, функций, путь и строки с разметкой экранируются',
        ['Html_EscapesFileData']),
    'BinaryLab.Report.MHBinaryReportToJson': (
        'пустой отчёт (не PE) — корректный JSON; данные с разметкой сохраняются как текст',
        ['Json_RoundTripStructure']),
    'BinaryLab.Report.MHSaveBinaryDiff': (
        'расширение без учёта регистра; недостающие папки создаются; недопустимое имя → исключение',
        ['DiffTitles_AndSaveDiff']),
    'BinaryLab.Report.MHSaveBinaryReport': (
        'выбор формата по расширению; имя файла кириллицей',
        ['Save_ByExtension']),
    # --- Источник и чтение ---
    'BinaryLab.Source.GetName': (
        'путь файла как имя источника',
        ['FileSource_ReadsAndKeepsFileUnchanged']),
    'BinaryLab.Source.GetSize': (
        'пустой источник — 0; размер файла',
        ['Reader_EmptySource', 'FileSource_ReadsAndKeepsFileUnchanged']),
    'BinaryLab.Source.InRange': (
        'диапазон длиннее остатка; отрицательная длина',
        ['Reader_BoundsAreChecked']),
    'BinaryLab.Source.MHCheckCancel': (
        'nil; ложь; истина → EMHBinaryLabCancelled',
        ['CheckCancel_NilFalseTrue']),
    'BinaryLab.Source.MHFindBytes': (
        'граница блока 1 МБ; регистр; лимит; пустой шаблон и данные; начало за концом и отрицательное; nil; отмена',
        ['FindBytes_FoundCaseLimitAndBoundary', 'FindBytes_EdgeAndErrorCases']),
    'BinaryLab.Source.MHParseHexPattern': (
        'пусто; только пробелы; нечётное число цифр; посторонние символы',
        ['ParseHexPattern_ValidAndInvalid']),
    'BinaryLab.Source.MHReadChunks': (
        'сигнатура на границе блоков; лимит; остановка обработчиком; отмена; начало за концом; пустой источник',
        ['Chunks_OverlapCoversBoundaries', 'Chunks_LimitAndCancel']),
    'BinaryLab.Source.MHTextPattern': (
        'символы вне ASCII → «?»; пустой текст',
        ['TextPattern_AsciiAndUtf16']),
    'BinaryLab.Source.MatchesAt': (
        'сигнатура за концом; пустая сигнатура',
        ['Reader_StringsAndSignatures', 'Reader_EmptySource']),
    'BinaryLab.Source.ReadAnsiZ': (
        'ограничение длины; непечатаемые символы; смещение за концом; пустой источник',
        ['Reader_StringsAndSignatures', 'Reader_EmptySource']),
    'BinaryLab.Source.ReadAt': (
        'обрезка у конца; за концом и отрицательное смещение → 0',
        ['FileSource_ReadsAndKeepsFileUnchanged']),
    'BinaryLab.Source.ReadBytes': (
        'за концом → пусто; обрезка у конца; отрицательная длина',
        ['Reader_BoundsAreChecked']),
    'BinaryLab.Source.ReadUtf16': (
        'обрезка у конца файла',
        ['Reader_StringsAndSignatures']),
    'BinaryLab.Source.TryRead': (
        'через границу окна кэша; крупное чтение; частично за концом; нулевая и отрицательная длина',
        ['Reader_TryReadCacheAndLargeReads']),
    'BinaryLab.Source.TryReadByte': (
        'пустой источник → False',
        ['Reader_EmptySource']),
    'BinaryLab.Source.TryReadDWord': (
        'частично за концом → False',
        ['Reader_BoundsAreChecked']),
    'BinaryLab.Source.TryReadQWord': (
        'больше файла → False',
        ['Reader_BoundsAreChecked']),
    'BinaryLab.Source.TryReadWord': (
        'отрицательное смещение и переполнение смещения → False',
        ['Reader_BoundsAreChecked']),
    # --- Строки ---
    'BinaryLab.Strings.MHClassifyString': (
        'версии не IP; имена файлов не домены; обычные слова не Base64; маркер внутри слова не майнинг; '
        'служебные таблицы не пути',
        ['Classify_Ip', 'Classify_Domain', 'Classify_Base64AndPlain', 'Classify_Mining', 'Classify_Path']),
    'BinaryLab.Strings.MHScanStrings': (
        'пустой и nil-источник; граница блока; минимальная длина ±1; обрезка длинной строки; предел числа строк '
        '(и 0); лимит сканирования; отмена',
        ['Strings_EmptyAndNilSource', 'Strings_ChunkBoundary_FoundOnce', 'Strings_MinLengthBoundary',
         'Strings_TruncatedToMaxLength', 'Strings_MaxStrings_KeepsCategorized', 'Strings_MaxStringsZero',
         'Strings_MaxScanBytesRespected', 'Strings_Cancel_Raises']),
    # --- Типы ---
    'BinaryLab.Types.AccessText': ('секция без флагов → «---»; RWX', ['Sections_FlagsFindAndRva']),
    'BinaryLab.Types.ContainsCode': ('без флагов → False', ['Sections_FlagsFindAndRva']),
    'BinaryLab.Types.CountOf': ('пустое сравнение → 0', ['Report_HasAnomalyAndDiffCountOf']),
    'BinaryLab.Types.Default': ('значения по умолчанию не меняются нормализацией', ['Options_NormalizedLimitsBothSides']),
    'BinaryLab.Types.FindSection': ('регистр; не найдено → пустая запись', ['Sections_FlagsFindAndRva']),
    'BinaryLab.Types.HasAnomaly': ('пустой отчёт; регистр кода', ['Report_HasAnomalyAndDiffCountOf']),
    'BinaryLab.Types.ImportsFunction': ('регистр; отсутствующая функция', ['Pe64_HeadersSectionsImportsExports']),
    'BinaryLab.Types.IsExecutable': ('без флагов → False', ['Sections_FlagsFindAndRva']),
    'BinaryLab.Types.IsReadable': ('без флагов → False', ['Sections_FlagsFindAndRva']),
    'BinaryLab.Types.IsWritable': ('без флагов → False', ['Sections_FlagsFindAndRva']),
    'BinaryLab.Types.MHAnomalySeverityTitle': ('все значения непустые', ['EnumTitlesAndNames_AllValuesDistinct']),
    'BinaryLab.Types.MHAnomalySeverityToName': ('все значения различны', ['EnumTitlesAndNames_AllValuesDistinct']),
    'BinaryLab.Types.MHBinaryKindTitle': ('все значения непустые', ['EnumTitlesAndNames_AllValuesDistinct']),
    'BinaryLab.Types.MHBinaryKindToName': ('все значения различны', ['EnumTitlesAndNames_AllValuesDistinct']),
    'BinaryLab.Types.MHDiffChangeTitle': ('все значения непустые', ['EnumTitlesAndNames_AllValuesDistinct']),
    'BinaryLab.Types.MHDiffChangeToName': ('все значения различны', ['EnumTitlesAndNames_AllValuesDistinct']),
    'BinaryLab.Types.MHEntropyClassOf': ('границы классов', ['Entropy_ShannonBounds']),
    'BinaryLab.Types.MHEntropyClassTitle': ('все значения различны', ['EnumTitlesAndNames_AllValuesDistinct']),
    'BinaryLab.Types.MHHexOffset': ('отрицательное смещение → «—»', ['Entropy_ShannonBounds']),
    'BinaryLab.Types.MHPeKindTitle': ('pkNone → пусто', ['MachineSubsystemAndPeKindNames']),
    'BinaryLab.Types.MHShannonEntropy': ('нет данных → 0; один байт → 0; равномерно → 8', ['Entropy_ShannonBounds']),
    'BinaryLab.Types.MHStringCategoryTitle': ('все значения непустые', ['EnumTitlesAndNames_AllValuesDistinct']),
    'BinaryLab.Types.MHStringCategoryToName': ('все значения различны', ['EnumTitlesAndNames_AllValuesDistinct']),
    'BinaryLab.Types.Normalized': ('все пределы сверху и снизу; 0 — автоматический размер блока',
                                   ['Options_NormalizedLimitsBothSides', 'Options_Normalized']),
    'BinaryLab.Types.SectionOfRva': ('сразу за секцией; заголовки; предельный адрес; нет секций',
                                     ['Sections_FlagsFindAndRva']),
    # --- Вердикты ---
    'BinaryLab.Verdicts.Clear': ('после очистки — 0', ['Store_MatchByPathAndHash']),
    'BinaryLab.Verdicts.Count': ('замена вердикта не увеличивает число; вытеснение', ['Store_MatchByPathAndHash',
                                                                                     'Store_EvictsOldest']),
    'BinaryLab.Verdicts.MHVerdictFromReport': ('сведения и слабые признаки не передаются; предел суммы 40; '
                                               'доверенная подпись; пустой отчёт', ['FromReport_WeightsSignalsAndCap']),
    'BinaryLab.Verdicts.Put': ('пустой путь не сохраняется; повтор заменяет; больше предела вытесняет старые; '
                               'параллельный доступ', ['Store_MatchByPathAndHash', 'Store_EvictsOldest',
                                                       'Store_ConcurrentAccess']),
    'BinaryLab.Verdicts.TryGet': ('другой SHA-256 → False; пустой хеш запроса; пустой путь; регистр пути',
                                  ['Store_MatchByPathAndHash', 'Store_EvictsOldest']),
    # --- Элементы интерфейса ---
    'App.BinaryLab.Controls.AddHighlight': ('до создания окна; поиск подсветки вне диапазонов',
                                            ['Highlights_LookupAndHint', 'BeforeHandle_Safe']),
    'App.BinaryLab.Controls.BarFraction': ('пустая гистограмма; нулевой и максимальный столбец; шкалы',
                                           ['Histogram_BarFractionEdges']),
    'App.BinaryLab.Controls.BarRect': ('крошечный размер окна; нет только ширины или только высоты',
                                       ['Paint_NormalEmptyTiny', 'BarRect_PlotWithoutWidthOrHeight_Empty']),
    'App.BinaryLab.Controls.BlockAtPoint': ('точка вне карты; блоков больше, чем клеток',
                                            ['Cells_ConsistentWithBlockAtPoint', 'ManyBlocks_Aggregated']),
    'App.BinaryLab.Controls.BlockCount': ('до данных и после пустых данных — 0', ['EntropyMap_BlockCountEmptyAndData']),
    'App.BinaryLab.Controls.BlocksPerCell': ('блоков больше, чем клеток; ровно вдвое больше ёмкости',
                                             ['ManyBlocks_Aggregated', 'ManyBlocks_PerCellIsMinimal']),
    'App.BinaryLab.Controls.ByteAtPoint': ('неровная ширина — каждый байт достижим; точка вне графика',
                                           ['ByteAtPoint_UnevenWidth_EveryByteReachable', 'ByteAtPoint_MatchesBars']),
    'App.BinaryLab.Controls.CellCount': ('блоков больше, чем клеток; ёмкость заполнена целиком',
                                         ['ManyBlocks_Aggregated', 'ManyBlocks_PerCellIsMinimal']),
    'App.BinaryLab.Controls.CellRect': ('крайние клетки и агрегирование', ['Cells_ConsistentWithBlockAtPoint',
                                                                          'ManyBlocks_Aggregated']),
    'App.BinaryLab.Controls.ClearHighlights': ('после очистки подсветки нет', ['Highlights_LookupAndHint']),
    'App.BinaryLab.Controls.ContentWidth': ('точки правее данных', ['OffsetAtPoint_OutsideColumns_False']),
    'App.BinaryLab.Controls.EntropyColor': ('концы шкалы различны, монотонность',
                                            ['EntropyColor_ScaleMonotonicAndDistinctEnds']),
    'App.BinaryLab.Controls.FindNext': ('не найдено — позиция прежняя; переход в начало; регистр; без источника',
                                        ['FindNext_FindsWrapsAndKeepsPositionWhenMissing', 'FindNext_IgnoreCase',
                                         'NilSource_Safe']),
    'App.BinaryLab.Controls.GotoOffset': ('смещение уже на экране; за концом; без окна',
                                          ['Goto_VisibleOffset_DoesNotScroll', 'Goto_ScrollsIntoViewAndSelects',
                                           'BeforeHandle_Safe']),
    'App.BinaryLab.Controls.HighlightAt': ('смещение вне подсветки → False', ['Highlights_LookupAndHint']),
    'App.BinaryLab.Controls.HighlightCount': ('после очистки — 0', ['Highlights_LookupAndHint']),
    'App.BinaryLab.Controls.HintTextAt': ('точка вне данных; пробел и управляющие байты',
                                          ['Hint_RangeEntropyAndBand', 'Hint_ByteCountPercent',
                                           'Hint_SpaceIsPrintable']),
    'App.BinaryLab.Controls.InvalidateData': ('сброс кэша после прокрутки', ['BinaryLab_ButtonsDialogsAndDoubleClicks']),
    'App.BinaryLab.Controls.MHBlendColor': ('доли 0, 1 и 0,5', ['BinaryLab_ButtonsDialogsAndDoubleClicks']),
    'App.BinaryLab.Controls.OffsetAtPoint': ('точки вне колонок; без источника; без окна',
                                             ['OffsetAtPoint_OutsideColumns_False', 'NilSource_Safe',
                                              'BeforeHandle_Safe']),
    'App.BinaryLab.Controls.OffsetAtX': ('края полосы; нулевой размер файла', ['OffsetAtX_Endpoints',
                                                                              'ZeroFileSize_Safe']),
    'App.BinaryLab.Controls.OffsetDigits': ('ровно 4 ГБ и на байт больше; без источника',
                                            ['HexView_OffsetDigitsAtFourGigabytes']),
    'App.BinaryLab.Controls.PointOfOffset': ('смещение вне экрана; без источника',
                                             ['OffsetAtPoint_InverseOfPointOfOffset', 'NilSource_Safe']),
    'App.BinaryLab.Controls.RangeAtX': ('вне диапазонов; нулевой размер файла', ['Click_OnRangeGivesStart_ElsewhereComputed',
                                                                                'ZeroFileSize_Safe']),
    'App.BinaryLab.Controls.RowCount': ('без источника — 0', ['NilSource_Safe']),
    'App.BinaryLab.Controls.ScrollRows': ('не выше начала', ['BinaryLab_ButtonsDialogsAndDoubleClicks']),
    'App.BinaryLab.Controls.SetBands': ('полоса в подсказке', ['Hint_RangeEntropyAndBand']),
    'App.BinaryLab.Controls.SetData': ('пустые данные; крошечное окно', ['Paint_CellColourAndEmptyAndTiny']),
    'App.BinaryLab.Controls.SetHistogram': ('пустой массив; меньше 256 значений', ['Histogram_BarFractionEdges',
                                                                                  'Paint_NormalEmptyTiny']),
    'App.BinaryLab.Controls.SetRanges': ('нулевой размер файла',
                                         ['ZeroFileSize_Safe']),
    'App.BinaryLab.Controls.VisibleRows': ('огромный виртуальный файл', ['BigVirtualSource_ScrollsToEndAndReadsOnlyPage']),
    # --- Страница ---
    'App.BinaryLabPage.Busy': ('после ошибки, отмены и закрытия окна — False',
                               ['BinaryLab_ErrorsCancelAndCloseWhileBusy', 'BinaryLab_PageMethods_WithoutDataAreSafe']),
    'App.BinaryLabPage.Cancel': ('в простое; во время анализа; закрытие окна во время анализа',
                                 ['BinaryLab_PageMethods_WithoutDataAreSafe', 'BinaryLab_ErrorsCancelAndCloseWhileBusy']),
    'App.BinaryLabPage.CompareWith': ('без отчёта; пустой путь; отсутствующий файл — ошибка, отчёт сохранён',
                                      ['BinaryLab_PageMethods_WithoutDataAreSafe']),
    'App.BinaryLabPage.ExportDiff': ('без сравнения — файла нет', ['BinaryLab_PageMethods_WithoutDataAreSafe']),
    'App.BinaryLabPage.ExportReport': ('без отчёта — файла нет', ['BinaryLab_PageMethods_WithoutDataAreSafe']),
    'App.BinaryLabPage.FindPattern': ('без файла; пустой шаблон; не найдено → -1',
                                      ['BinaryLab_PageMethods_WithoutDataAreSafe',
                                       'BinaryLab_AnalyzeNavigateFindExportCompare']),
    'App.BinaryLabPage.CleanPath': ('пробелы и кавычки по краям; пустая строка; пустые кавычки; одна кавычка',
                                    ['BinaryLab_CheckButtonAndPathField']),
    'App.BinaryLabPage.OpenFile': ('пустой путь; отсутствующий файл; повторное открытие во время работы',
                                   ['BinaryLab_PageMethods_WithoutDataAreSafe', 'BinaryLab_ErrorsCancelAndCloseWhileBusy']),
    'App.BinaryLabPage.ParseOffset': ('пусто; посторонние символы; hex и десятичная запись',
                                      ['BinaryLab_AnalyzeNavigateFindExportCompare']),
    'App.BinaryLabPage.ShowOffset': ('без файла; отрицательное смещение; длина меньше 1; смещение 0; '
                                     'двойной щелчок без выделения и по строке «0x…» в сравнении',
                                     ['BinaryLab_PageMethods_WithoutDataAreSafe', 'BinaryLab_DoubleClickEdgeCases']),
}
