# BinaryLab: матрица «функция → тесты»

Создаётся `python tools/binarylab_test_matrix.py` из исходников: для каждой публичной функции и
метода BinaryLab — граничные и ошибочные случаи из реестра `tools/binarylab_cases.py` и тесты, которые их
проверяют. Генератор сверяет каждую запись с кодом: тест существует, вызывает функцию и содержит Assert.
Внутренние методы отрисовки и потоков проверяются через публичное поведение страницы и элементов.

## Требования ТЗ → тесты

Колонка «Прогон» — итоги последнего запуска всех тестов (`build/tests-Debug.xml`,
`build/tests-Release.xml`, отчёты NUnit XML DUnitX): сколько тестов случаев выполнено и пройдено.

| Требование | Тесты (граничные и ошибочные случаи) | Прогон |
|---|---|---|
| 1. Типы файлов по содержимому (EXE, DLL, SYS, BIN, DAT…) | `Detect_PeKinds`, `Detect_ArchivesImagesDocuments`, `Detect_TextAndScripts`, `Detect_EmptyAndUnknown`, `Detect_ExtensionMismatch`, `Detect_DamagedPe_IsMsDos`, `IdentifyAt_StrictRejectsWeakSignatures`, `Extensions_ExpectedAndInList` | Debug 8/8, Release 8/8 |
| 2. PE Analyzer (заголовки, секции, импорт, экспорт, ресурсы, точка входа, подпись, PE32/PE32+) | `Pe64_HeadersSectionsImportsExports`, `Pe32_OrdinalImportsAndImageBase`, `Resources_TreeTypesLanguagesAndContent`, `TlsDotNetCertificateOverlay`, `EntryPoint_OffsetSectionAndRvaMapping`, `Checksum_MatchesBuilderIncludingOddLength`, `NotPe_IsInvalidWithReason`, `Truncated_AtEveryLength_NeverRaises`, `HugeCounts_AreClampedWithWarnings`, `ImportOutsideFile_AndUnterminatedThunks`, `ResourceCycle_DoesNotHang`, `Limits_ImportsAndExports`, `Fuzz_RandomHeaderCorruption_NeverRaises`, `Signature_FromFileApi_AndApiFailure`, `RealSystemFiles_SignedAndParsed` | Debug 15/15, Release 15/15 |
| 3. Энтропия, упакованные и шифрованные области, карта | `Entropy_AllZero_NoHighRegions`, `Entropy_AutoBlockSize`, `Entropy_Cancel_Raises`, `Entropy_EmptyAndNilSource`, `RangeEntropy_BoundsAndClipping`, `Entropy_ShannonBounds`, `Cells_ConsistentWithBlockAtPoint`, `ManyBlocks_Aggregated`, `Click_RaisesBlockOffset`, `EntropyColor_ScaleMonotonicAndDistinctEnds` | Debug 10/10, Release 10/10 |
| 4. Hex Viewer (просмотр, поиск байтов и строк, смещения, подсветка) | `Goto_ScrollsIntoViewAndSelects`, `Keys_MoveCaret`, `Highlights_LookupAndHint`, `FindNext_FindsWrapsAndKeepsPositionWhenMissing`, `FindNext_IgnoreCase`, `NilSource_Safe`, `BigVirtualSource_ScrollsToEndAndReadsOnlyPage`, `FindBytes_FoundCaseLimitAndBoundary`, `FindBytes_EdgeAndErrorCases`, `ParseHexPattern_ValidAndInvalid`, `BinaryLab_ButtonsDialogsAndDoubleClicks` | Debug 11/11, Release 11/11 |
| 5. Строки ASCII/Unicode, URL, IP, пути, команды, индикаторы | `Classify_Mining`, `Classify_Ip`, `Classify_Domain`, `Classify_Base64AndPlain`, `Strings_MiningWalletCommands` | Debug 5/5, Release 5/5 |
| 6. Вложенные EXE, DLL, архивы, сценарии | `Embedded_RandomData_NoFalsePositives`, `Embedded_Cancel_Raises`, `Embedded_LocateAndMaxScanBytes`, `Embedded_ExecutableArchiveScript` | Debug 4/4, Release 4/4 |
| 7. BinaryDiff (секции, импорт, строки, ресурсы, блоки) | `Identical_Files`, `Modified_Pe_SectionsImportsExportsResourcesBlocks`, `DifferentSizes_TailIsChanged`, `NonPe_StringsCompared`, `Limits_Truncated`, `NilAndCancel` | Debug 6/6, Release 6/6 |
| 8. Аномалии PE, необычные секции, скрытые данные, несоответствия формата | `CleanProgram_NoThreatVerdict`, `EntryOutsideSections`, `UpxLikePacking`, `PackedCodeAndEncryptedData`, `Imports_NoneDynamicFewInjectionAntiDebug`, `DotNet_NoImportsIsNormal`, `Driver_UnsignedAndChecksum`, `Signature_InvalidAndTrustedHalvesScore`, `Overlay_EncryptedVsInstaller`, `Score_ClampedAndLevelFromThresholds` | Debug 10/10, Release 10/10 |
| 9. Открыть файл процесса в BinaryLab; результаты — в движок угроз | `Menu_OpenInBinaryLab`, `BinaryLab_PageAndMenus`, `FromReport_WeightsSignalsAndCap`, `Store_MatchByPathAndHash`, `Store_EvictsOldest`, `Store_ConcurrentAccess`, `Engine_AddsBinaryLabEvidenceToProcessFinding`, `Engine_IgnoresVerdictForChangedFile` | Debug 8/8, Release 8/8 |
| 10. Отчёты JSON и HTML | `Json_RoundTripStructure`, `Html_EscapesFileData`, `Save_ByExtension`, `Diff_JsonAndHtml`, `DiffTitles_AndSaveDiff` | Debug 5/5, Release 5/5 |
| Без запуска и изменения файла | `File_AnalysedWithoutModification`, `FileSource_ReadsAndKeepsFileUnchanged`, `FileSource_OpenWhileFileIsLockedForWrite` | Debug 3/3, Release 3/3 |
| Асинхронно, без зависания интерфейса | `BinaryLab_AnalyzeNavigateFindExportCompare`, `BinaryLab_ErrorsCancelAndCloseWhileBusy`, `Progress_AndCancel` | Debug 3/3, Release 3/3 |
| Лимиты памяти, повреждённые файлы | `Partial_WhenLargerThanScanLimit`, `Chunks_LimitAndCancel`, `Reader_BoundsAreChecked`, `Truncated_AtEveryLength_NeverRaises`, `Fuzz_RandomHeaderCorruption_NeverRaises` | Debug 5/5, Release 5/5 |

## Публичные функции → тесты

| Модуль | Функция | Граничные и ошибочные случаи | Тесты этих случаев | Прогон | Все тесты с вызовом |
|---|---|---|---|---|---|
| `BinaryLab.Analyzer` | `MHAnalyzeBinaryFile` | нет файла → EMHBinaryLabError; файл не изменяется и не блокируется после анализа; сбой и отключение проверки подписи; настоящие системные файлы | `File_Missing_Raises`, `File_AnalysedWithoutModification`, `Signature_FromFileApi_AndApiFailure`, `RealSystemFiles_SignedAndParsed` | Debug 4/4, Release 4/4 | TBinaryLabAnalyzerTests.File_AnalysedWithoutModification, TBinaryLabAnalyzerTests.File_Missing_Raises, TBinaryLabAnalyzerTests.RealSystemFiles_SignedAndParsed, TBinaryLabAnalyzerTests.Signature_FromFileApi_AndApiFailure |
| `BinaryLab.Analyzer` | `MHAnalyzeBinarySource` | nil-источник → EArgumentNilException; пустой файл; случайные данные; файл больше лимита сканирования; отмена на середине; ход выполнения только растёт | `File_Missing_Raises`, `TextEmptyAndUnknown`, `Partial_WhenLargerThanScanLimit`, `Progress_AndCancel` | Debug 4/4, Release 4/4 | TBinaryLabAnalyzerTests.CleanPe_LowScore, TBinaryLabAnalyzerTests.File_Missing_Raises, TBinaryLabAnalyzerTests.Partial_WhenLargerThanScanLimit, TBinaryLabAnalyzerTests.Progress_AndCancel и ещё 9 |
| `BinaryLab.Anomalies` | `MHDetectAnomalies` | чистая программа без признаков; не-PE и повреждённый заголовок; .NET без импорта; драйвер без подписи; установщик со сжатым оверлеем; пустой отчёт | `CleanProgram_NoThreatVerdict`, `DamagedHeader_NonPeData`, `DotNet_NoImportsIsNormal`, `Driver_UnsignedAndChecksum`, `Overlay_EncryptedVsInstaller`, `ExtensionMismatch_ExecutableVsData` | Debug 6/6, Release 6/6 | TBinaryLabAnomalyTests.CleanProgram_NoThreatVerdict, TBinaryLabAnomalyTests.DamagedHeader_NonPeData, TBinaryLabAnomalyTests.DotNet_NoImportsIsNormal, TBinaryLabAnomalyTests.Driver_UnsignedAndChecksum и ещё 10 |
| `BinaryLab.Anomalies` | `MHDetectInstaller` | нет строк → пусто; строка установщика → имя | `Overlay_EncryptedVsInstaller` | Debug 1/1, Release 1/1 | TBinaryLabAnomalyTests.Overlay_EncryptedVsInstaller |
| `BinaryLab.Anomalies` | `MHPackerBySectionName` | регистр не важен; обычная секция → пусто | `UpxLikePacking` | Debug 1/1, Release 1/1 | TBinaryLabAnomalyTests.UpxLikePacking |
| `BinaryLab.Anomalies` | `MHScoreBinaryReport` | сумма больше 100 → 100; только сведения → 0; доверенная подпись делит пополам | `Score_ClampedAndLevelFromThresholds`, `Signature_InvalidAndTrustedHalvesScore`, `DamagedHeader_NonPeData` | Debug 3/3, Release 3/3 | TBinaryLabAnomalyTests.CleanProgram_NoThreatVerdict, TBinaryLabAnomalyTests.DamagedHeader_NonPeData, TBinaryLabAnomalyTests.Score_ClampedAndLevelFromThresholds, TBinaryLabAnomalyTests.Signature_InvalidAndTrustedHalvesScore и ещё 2 |
| `BinaryLab.Diff` | `MHCompareBinaries` | идентичные файлы; разный размер (хвост); не-PE; предел элементов и лимит байтов → Truncated; nil-источник → исключение; отмена | `Identical_Files`, `DifferentSizes_TailIsChanged`, `NonPe_StringsCompared`, `Limits_Truncated`, `NilAndCancel` | Debug 5/5, Release 5/5 | TBinaryLabDiffTests.DifferentSizes_TailIsChanged, TBinaryLabDiffTests.Identical_Files, TBinaryLabDiffTests.Limits_Truncated, TBinaryLabDiffTests.Modified_Pe_SectionsImportsExportsResourcesBlocks и ещё 2 |
| `BinaryLab.Diff` | `MHDiffAreaTitle` | все области переведены; неизвестная область — как есть | `DiffTitles_AndSaveDiff` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.DiffTitles_AndSaveDiff |
| `BinaryLab.Embedded` | `MHFindEmbedded` | случайные данные без ложных срабатываний; слабые сигнатуры в тексте; смещение 0 не считается; ложный размер не прячет остаток; предел числа объектов; границы блоков; лимит сканирования; отмена | `Embedded_RandomData_NoFalsePositives`, `Embedded_WeakSignaturesInText_Ignored`, `Embedded_OffsetZero_NotReported`, `Embedded_BogusSize_DoesNotHideRest`, `Embedded_MaxEmbeddedLimit`, `Embedded_ChunkBoundaries`, `Embedded_LocateAndMaxScanBytes`, `Embedded_Cancel_Raises` | Debug 8/8, Release 8/8 | TBinaryLabEmbeddedTests.Embedded_ArchivesAndDocuments, TBinaryLabEmbeddedTests.Embedded_BogusSize_DoesNotHideRest, TBinaryLabEmbeddedTests.Embedded_Cancel_Raises, TBinaryLabEmbeddedTests.Embedded_ChunkBoundaries и ещё 8 |
| `BinaryLab.Entropy` | `MHAnalyzeEntropy` | пустой и nil-источник; файл в несколько байт; неполный последний блок; одни нули; блоки через границу чтения; лимит сканирования; отмена | `Entropy_EmptyAndNilSource`, `Entropy_TinyFile`, `Entropy_ExplicitBlockSize_LastPartialBlock`, `Entropy_AllZero_NoHighRegions`, `Entropy_BlocksAcrossReadChunks`, `Entropy_MaxScanBytesRespected`, `Entropy_Cancel_Raises` | Debug 7/7, Release 7/7 | TBinaryLabEntropyTests.Entropy_AllZero_NoHighRegions, TBinaryLabEntropyTests.Entropy_AutoBlockSize, TBinaryLabEntropyTests.Entropy_BlocksAcrossReadChunks, TBinaryLabEntropyTests.Entropy_Cancel_Raises и ещё 6 |
| `BinaryLab.Entropy` | `MHRangeEntropy` | диапазон за концом и отрицательный → -1; обрезка у конца файла | `RangeEntropy_BoundsAndClipping` | Debug 1/1, Release 1/1 | TBinaryLabEntropyTests.Entropy_BlocksAcrossReadChunks, TBinaryLabEntropyTests.RangeEntropy_BoundsAndClipping |
| `BinaryLab.FileType` | `MHDetectBinaryType` | пустой файл; один байт; случайные данные; повреждённый PE и e_lfanew за концом; несоответствие расширения и его отсутствие | `Detect_EmptyAndUnknown`, `Detect_DamagedPe_IsMsDos`, `Detect_ExtensionMismatch` | Debug 3/3, Release 3/3 | TBinaryLabBasicsTests.Detect_ArchivesImagesDocuments, TBinaryLabBasicsTests.Detect_DamagedPe_IsMsDos, TBinaryLabBasicsTests.Detect_EmptyAndUnknown, TBinaryLabBasicsTests.Detect_ExtensionMismatch и ещё 2 |
| `BinaryLab.FileType` | `MHExpectedExtensions` | пустой список для неизвестных и пустых файлов | `Extensions_ExpectedAndInList` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Extensions_ExpectedAndInList |
| `BinaryLab.FileType` | `MHExtensionInList` | пустое расширение; пустой список; регистр | `Extensions_ExpectedAndInList` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Extensions_ExpectedAndInList |
| `BinaryLab.FileType` | `MHIdentifyAt` | строгий режим отбрасывает слабые сигнатуры; смещение за концом | `IdentifyAt_StrictRejectsWeakSignatures` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.IdentifyAt_StrictRejectsWeakSignatures |
| `BinaryLab.FileType` | `MHMachineName` | неизвестная архитектура → код | `MachineSubsystemAndPeKindNames` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.MachineSubsystemAndPeKindNames |
| `BinaryLab.FileType` | `MHProbePe` | огромный e_lfanew → False; оверлей не входит в образ | `ProbePe_ImageEndAndHugeLfanew` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.ProbePe_ImageEndAndHugeLfanew |
| `BinaryLab.Pe` | `MHComputePeChecksum` | пустой и однобайтовый файл; поле за концом и в начале; перенос разряда; отмена | `Checksum_EmptyTinyFieldOutsideAndCancel`, `Checksum_MatchesBuilderIncludingOddLength` | Debug 2/2, Release 2/2 | TBinaryLabApiTests.Checksum_EmptyTinyFieldOutsideAndCancel, TBinaryLabPeTests.Checksum_MatchesBuilderIncludingOddLength |
| `BinaryLab.Pe` | `MHParsePe` | не-PE и неизвестный формат; обрезка на каждой длине; огромные счётчики; импорт вне файла и без завершающего нуля; цикл в ресурсах; лимиты; отмена; 400 испорченных заголовков | `NotPe_IsInvalidWithReason`, `Truncated_AtEveryLength_NeverRaises`, `HugeCounts_AreClampedWithWarnings`, `ImportOutsideFile_AndUnterminatedThunks`, `ResourceCycle_DoesNotHang`, `Limits_ImportsAndExports`, `Cancel_Raises`, `Fuzz_RandomHeaderCorruption_NeverRaises` | Debug 8/8, Release 8/8 | TBinaryLabAnomalyTests.CleanProgram_NoThreatVerdict, TBinaryLabAnomalyTests.DotNet_NoImportsIsNormal, TBinaryLabAnomalyTests.Driver_UnsignedAndChecksum, TBinaryLabAnomalyTests.EntryOutsideSections и ещё 21 |
| `BinaryLab.Pe` | `MHPeLocate` | отрицательное смещение; не-PE → пусто; оверлей и подпись различаются | `Locate_DescribesOffsets` | Debug 1/1, Release 1/1 | TBinaryLabPeTests.Locate_DescribesOffsets |
| `BinaryLab.Pe` | `MHPeRvaToOffset` | адрес без данных в файле; адрес вне секций; не-PE → MH_NO_OFFSET | `EntryPoint_OffsetSectionAndRvaMapping` | Debug 1/1, Release 1/1 | TBinaryLabPeTests.EntryPoint_OffsetSectionAndRvaMapping |
| `BinaryLab.Pe` | `MHRangeSha256` | обрезка у конца; диапазон за концом, отрицательный, нулевой; nil-источник → пусто | `RangeSha256_Bounds` | Debug 1/1, Release 1/1 | TBinaryLabPeTests.RangeSha256_Bounds |
| `BinaryLab.Pe` | `MHResourceTypeName` | нестандартный тип → пусто | `Resources_TreeTypesLanguagesAndContent` | Debug 1/1, Release 1/1 | TBinaryLabPeTests.Resources_TreeTypesLanguagesAndContent |
| `BinaryLab.Pe` | `MHSubsystemName` | неизвестная подсистема → с номером | `MachineSubsystemAndPeKindNames` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.MachineSubsystemAndPeKindNames |
| `BinaryLab.Report` | `MHBinaryDiffToHtml` | данные с разметкой экранируются | `Diff_JsonAndHtml` | Debug 1/1, Release 1/1 | TBinaryLabReportTests.Diff_JsonAndHtml |
| `BinaryLab.Report` | `MHBinaryDiffToJson` | корректный JSON с диапазонами | `Diff_JsonAndHtml` | Debug 1/1, Release 1/1 | TBinaryLabReportTests.Diff_JsonAndHtml |
| `BinaryLab.Report` | `MHBinaryReportToHtml` | имена секций, функций, путь и строки с разметкой экранируются | `Html_EscapesFileData` | Debug 1/1, Release 1/1 | TBinaryLabReportTests.Html_EscapesFileData |
| `BinaryLab.Report` | `MHBinaryReportToJson` | пустой отчёт (не PE) — корректный JSON; данные с разметкой сохраняются как текст | `Json_RoundTripStructure` | Debug 1/1, Release 1/1 | TBinaryLabReportTests.Json_RoundTripStructure |
| `BinaryLab.Report` | `MHSaveBinaryDiff` | расширение без учёта регистра; недостающие папки создаются; недопустимое имя → исключение | `DiffTitles_AndSaveDiff` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.DiffTitles_AndSaveDiff |
| `BinaryLab.Report` | `MHSaveBinaryReport` | выбор формата по расширению; имя файла кириллицей | `Save_ByExtension` | Debug 1/1, Release 1/1 | TBinaryLabReportTests.Save_ByExtension |
| `BinaryLab.Source` | `GetName` | путь файла как имя источника | `FileSource_ReadsAndKeepsFileUnchanged` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Sections_FlagsFindAndRva, TBinaryLabBasicsTests.FileSource_ReadsAndKeepsFileUnchanged, TBinaryLabDiffTests.Modified_Pe_SectionsImportsExportsResourcesBlocks, TBinaryLabDiffTests.NonPe_StringsCompared и ещё 8 |
| `BinaryLab.Source` | `GetSize` | пустой источник — 0; размер файла | `Reader_EmptySource`, `FileSource_ReadsAndKeepsFileUnchanged` | Debug 2/2, Release 2/2 | TBinaryLabAnalyzerTests.SuspiciousPe_FullPipeline, TBinaryLabAnomalyTests.CleanProgram_NoThreatVerdict, TBinaryLabAnomalyTests.DamagedHeader_NonPeData, TBinaryLabAnomalyTests.DotNet_NoImportsIsNormal и ещё 37 |
| `BinaryLab.Source` | `InRange` | диапазон длиннее остатка; отрицательная длина | `Reader_BoundsAreChecked` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.Reader_BoundsAreChecked |
| `BinaryLab.Source` | `MHCheckCancel` | nil; ложь; истина → EMHBinaryLabCancelled | `CheckCancel_NilFalseTrue` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.CheckCancel_NilFalseTrue |
| `BinaryLab.Source` | `MHFindBytes` | граница блока 1 МБ; регистр; лимит; пустой шаблон и данные; начало за концом и отрицательное; nil; отмена | `FindBytes_FoundCaseLimitAndBoundary`, `FindBytes_EdgeAndErrorCases` | Debug 2/2, Release 2/2 | TBinaryLabApiTests.FindBytes_EdgeAndErrorCases, TBinaryLabApiTests.FindBytes_FoundCaseLimitAndBoundary |
| `BinaryLab.Source` | `MHParseHexPattern` | пусто; только пробелы; нечётное число цифр; посторонние символы | `ParseHexPattern_ValidAndInvalid` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.ParseHexPattern_ValidAndInvalid |
| `BinaryLab.Source` | `MHReadChunks` | сигнатура на границе блоков; лимит; остановка обработчиком; отмена; начало за концом; пустой источник | `Chunks_OverlapCoversBoundaries`, `Chunks_LimitAndCancel` | Debug 2/2, Release 2/2 | TBinaryLabBasicsTests.Chunks_LimitAndCancel, TBinaryLabBasicsTests.Chunks_OverlapCoversBoundaries |
| `BinaryLab.Source` | `MHTextPattern` | символы вне ASCII → «?»; пустой текст | `TextPattern_AsciiAndUtf16` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.TextPattern_AsciiAndUtf16, TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare |
| `BinaryLab.Source` | `MatchesAt` | сигнатура за концом; пустая сигнатура | `Reader_StringsAndSignatures`, `Reader_EmptySource` | Debug 2/2, Release 2/2 | TBinaryLabBasicsTests.Reader_EmptySource, TBinaryLabBasicsTests.Reader_StringsAndSignatures |
| `BinaryLab.Source` | `ReadAnsiZ` | ограничение длины; непечатаемые символы; смещение за концом; пустой источник | `Reader_StringsAndSignatures`, `Reader_EmptySource` | Debug 2/2, Release 2/2 | TBinaryLabBasicsTests.Reader_EmptySource, TBinaryLabBasicsTests.Reader_StringsAndSignatures |
| `BinaryLab.Source` | `ReadAt` | обрезка у конца; за концом и отрицательное смещение → 0 | `FileSource_ReadsAndKeepsFileUnchanged` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.FileSource_ReadsAndKeepsFileUnchanged |
| `BinaryLab.Source` | `ReadBytes` | за концом → пусто; обрезка у конца; отрицательная длина | `Reader_BoundsAreChecked` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.Reader_BoundsAreChecked |
| `BinaryLab.Source` | `ReadUtf16` | обрезка у конца файла | `Reader_StringsAndSignatures` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.Reader_StringsAndSignatures |
| `BinaryLab.Source` | `TryRead` | через границу окна кэша; крупное чтение; частично за концом; нулевая и отрицательная длина | `Reader_TryReadCacheAndLargeReads` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Reader_TryReadCacheAndLargeReads |
| `BinaryLab.Source` | `TryReadByte` | пустой источник → False | `Reader_EmptySource` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.Reader_EmptySource |
| `BinaryLab.Source` | `TryReadDWord` | частично за концом → False | `Reader_BoundsAreChecked` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.Reader_BoundsAreChecked |
| `BinaryLab.Source` | `TryReadQWord` | больше файла → False | `Reader_BoundsAreChecked` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.Reader_BoundsAreChecked |
| `BinaryLab.Source` | `TryReadWord` | отрицательное смещение и переполнение смещения → False | `Reader_BoundsAreChecked` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.Reader_BoundsAreChecked |
| `BinaryLab.Strings` | `MHClassifyString` | версии не IP; имена файлов не домены; обычные слова не Base64; маркер внутри слова не майнинг; служебные таблицы не пути | `Classify_Ip`, `Classify_Domain`, `Classify_Base64AndPlain`, `Classify_Mining`, `Classify_Path` | Debug 5/5, Release 5/5 | TBinaryLabStringsTests.Classify_Base64AndPlain, TBinaryLabStringsTests.Classify_Domain, TBinaryLabStringsTests.Classify_Ip, TBinaryLabStringsTests.Classify_Mining и ещё 5 |
| `BinaryLab.Strings` | `MHScanStrings` | пустой и nil-источник; граница блока; минимальная длина ±1; обрезка длинной строки; предел числа строк (и 0); лимит сканирования; отмена | `Strings_EmptyAndNilSource`, `Strings_ChunkBoundary_FoundOnce`, `Strings_MinLengthBoundary`, `Strings_TruncatedToMaxLength`, `Strings_MaxStrings_KeepsCategorized`, `Strings_MaxStringsZero`, `Strings_MaxScanBytesRespected`, `Strings_Cancel_Raises` | Debug 8/8, Release 8/8 | TBinaryLabStringsTests.Strings_AsciiUtf16AndCyrillic, TBinaryLabStringsTests.Strings_Cancel_Raises, TBinaryLabStringsTests.Strings_ChunkBoundary_FoundOnce, TBinaryLabStringsTests.Strings_EmptyAndNilSource и ещё 5 |
| `BinaryLab.Types` | `AccessText` | секция без флагов → «---»; RWX | `Sections_FlagsFindAndRva` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Sections_FlagsFindAndRva, TBinaryLabPeTests.Pe64_HeadersSectionsImportsExports |
| `BinaryLab.Types` | `ContainsCode` | без флагов → False | `Sections_FlagsFindAndRva` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Sections_FlagsFindAndRva, TBinaryLabPeTests.Pe64_HeadersSectionsImportsExports |
| `BinaryLab.Types` | `CountOf` | пустое сравнение → 0 | `Report_HasAnomalyAndDiffCountOf` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Report_HasAnomalyAndDiffCountOf, TBinaryLabDiffTests.DifferentSizes_TailIsChanged, TBinaryLabDiffTests.Limits_Truncated, TBinaryLabDiffTests.Modified_Pe_SectionsImportsExportsResourcesBlocks и ещё 1 |
| `BinaryLab.Types` | `Default` | значения по умолчанию не меняются нормализацией | `Options_NormalizedLimitsBothSides` | Debug 1/1, Release 1/1 | TBinaryLabAnalyzerTests.CleanPe_LowScore, TBinaryLabAnalyzerTests.File_AnalysedWithoutModification, TBinaryLabAnalyzerTests.File_Missing_Raises, TBinaryLabAnalyzerTests.Partial_WhenLargerThanScanLimit и ещё 91 |
| `BinaryLab.Types` | `FindSection` | регистр; не найдено → пустая запись | `Sections_FlagsFindAndRva` | Debug 1/1, Release 1/1 | TBinaryLabAnalyzerTests.SuspiciousPe_FullPipeline, TBinaryLabApiTests.Sections_FlagsFindAndRva, TBinaryLabPeTests.Pe64_HeadersSectionsImportsExports |
| `BinaryLab.Types` | `HasAnomaly` | пустой отчёт; регистр кода | `Report_HasAnomalyAndDiffCountOf` | Debug 1/1, Release 1/1 | TBinaryLabAnalyzerTests.CleanPe_LowScore, TBinaryLabAnalyzerTests.Partial_WhenLargerThanScanLimit, TBinaryLabAnalyzerTests.SuspiciousPe_FullPipeline, TBinaryLabApiTests.Report_HasAnomalyAndDiffCountOf и ещё 1 |
| `BinaryLab.Types` | `ImportsFunction` | регистр; отсутствующая функция | `Pe64_HeadersSectionsImportsExports` | Debug 1/1, Release 1/1 | TBinaryLabPeTests.Pe64_HeadersSectionsImportsExports |
| `BinaryLab.Types` | `IsExecutable` | без флагов → False | `Sections_FlagsFindAndRva` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Sections_FlagsFindAndRva |
| `BinaryLab.Types` | `IsReadable` | без флагов → False | `Sections_FlagsFindAndRva` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Sections_FlagsFindAndRva |
| `BinaryLab.Types` | `IsWritable` | без флагов → False | `Sections_FlagsFindAndRva` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Sections_FlagsFindAndRva |
| `BinaryLab.Types` | `MHAnomalySeverityTitle` | все значения непустые | `EnumTitlesAndNames_AllValuesDistinct` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct |
| `BinaryLab.Types` | `MHAnomalySeverityToName` | все значения различны | `EnumTitlesAndNames_AllValuesDistinct` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct |
| `BinaryLab.Types` | `MHBinaryKindTitle` | все значения непустые | `EnumTitlesAndNames_AllValuesDistinct` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct |
| `BinaryLab.Types` | `MHBinaryKindToName` | все значения различны | `EnumTitlesAndNames_AllValuesDistinct` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct, TBinaryLabBasicsTests.Detect_ArchivesImagesDocuments |
| `BinaryLab.Types` | `MHDiffChangeTitle` | все значения непустые | `EnumTitlesAndNames_AllValuesDistinct` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct |
| `BinaryLab.Types` | `MHDiffChangeToName` | все значения различны | `EnumTitlesAndNames_AllValuesDistinct` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct |
| `BinaryLab.Types` | `MHEntropyClassOf` | границы классов | `Entropy_ShannonBounds` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.Entropy_ShannonBounds, TEntropyMapTests.Hint_RangeEntropyAndBand |
| `BinaryLab.Types` | `MHEntropyClassTitle` | все значения различны | `EnumTitlesAndNames_AllValuesDistinct` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct, TEntropyMapTests.Hint_RangeEntropyAndBand |
| `BinaryLab.Types` | `MHHexOffset` | отрицательное смещение → «—» | `Entropy_ShannonBounds` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.Entropy_ShannonBounds, TEntropyMapTests.Hint_RangeEntropyAndBand, THexViewTests.BigVirtualSource_ScrollsToEndAndReadsOnlyPage, TRangeStripTests.Click_OnRangeGivesStart_ElsewhereComputed |
| `BinaryLab.Types` | `MHPeKindTitle` | pkNone → пусто | `MachineSubsystemAndPeKindNames` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.MachineSubsystemAndPeKindNames |
| `BinaryLab.Types` | `MHShannonEntropy` | нет данных → 0; один байт → 0; равномерно → 8 | `Entropy_ShannonBounds` | Debug 1/1, Release 1/1 | TBinaryLabBasicsTests.Entropy_ShannonBounds |
| `BinaryLab.Types` | `MHStringCategoryTitle` | все значения непустые | `EnumTitlesAndNames_AllValuesDistinct` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct |
| `BinaryLab.Types` | `MHStringCategoryToName` | все значения различны | `EnumTitlesAndNames_AllValuesDistinct` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct, TBinaryLabStringsTests.Classify_Base64AndPlain, TBinaryLabStringsTests.Classify_Domain, TBinaryLabStringsTests.Classify_Ip и ещё 6 |
| `BinaryLab.Types` | `Normalized` | все пределы сверху и снизу; 0 — автоматический размер блока | `Options_NormalizedLimitsBothSides`, `Options_Normalized` | Debug 2/2, Release 2/2 | TBinaryLabApiTests.Options_NormalizedLimitsBothSides, TBinaryLabBasicsTests.Options_Normalized |
| `BinaryLab.Types` | `SectionOfRva` | сразу за секцией; заголовки; предельный адрес; нет секций | `Sections_FlagsFindAndRva` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Sections_FlagsFindAndRva |
| `BinaryLab.Verdicts` | `Clear` | после очистки — 0 | `Store_MatchByPathAndHash` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct, TBinaryLabVerdictTests.Store_MatchByPathAndHash, TMainFormSmokeTests.Pages_TablesShownWholeAndWheelScrollsPage |
| `BinaryLab.Verdicts` | `Count` | замена вердикта не увеличивает число; вытеснение | `Store_MatchByPathAndHash`, `Store_EvictsOldest` | Debug 2/2, Release 2/2 | TBinaryLabReportTests.Diff_JsonAndHtml, TBinaryLabReportTests.Json_RoundTripStructure, TBinaryLabVerdictTests.Store_ConcurrentAccess, TBinaryLabVerdictTests.Store_EvictsOldest и ещё 30 |
| `BinaryLab.Verdicts` | `MHVerdictFromReport` | сведения и слабые признаки не передаются; предел суммы 40; доверенная подпись; пустой отчёт | `FromReport_WeightsSignalsAndCap` | Debug 1/1, Release 1/1 | TBinaryLabVerdictTests.FromReport_WeightsSignalsAndCap |
| `BinaryLab.Verdicts` | `Put` | пустой путь не сохраняется; повтор заменяет; больше предела вытесняет старые; параллельный доступ | `Store_MatchByPathAndHash`, `Store_EvictsOldest`, `Store_ConcurrentAccess` | Debug 3/3, Release 3/3 | TBinaryLabEmbeddedTests.Embedded_ChunkBoundaries, TBinaryLabEmbeddedTests.Embedded_LocateAndMaxScanBytes, TBinaryLabStringsTests.Strings_ChunkBoundary_FoundOnce, TBinaryLabStringsTests.Strings_MaxScanBytesRespected и ещё 5 |
| `BinaryLab.Verdicts` | `TryGet` | другой SHA-256 → False; пустой хеш запроса; пустой путь; регистр пути | `Store_MatchByPathAndHash`, `Store_EvictsOldest` | Debug 2/2, Release 2/2 | TBinaryLabVerdictTests.Store_ConcurrentAccess, TBinaryLabVerdictTests.Store_EvictsOldest, TBinaryLabVerdictTests.Store_MatchByPathAndHash, TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare |
| `App.BinaryLab.Controls` | `AddHighlight` | до создания окна; поиск подсветки вне диапазонов | `Highlights_LookupAndHint`, `BeforeHandle_Safe` | Debug 2/2, Release 2/2 | TBinaryLabDarkThemeTests.AllControls_PaintInDarkTheme, THexViewTests.BeforeHandle_Safe, THexViewTests.Highlights_LookupAndHint, THexViewTests.Paint_NormalAndTiny |
| `App.BinaryLab.Controls` | `BarFraction` | пустая гистограмма; нулевой и максимальный столбец; шкалы | `Histogram_BarFractionEdges` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.Histogram_BarFractionEdges, THistogramTests.Scale_LogarithmicAndLinear |
| `App.BinaryLab.Controls` | `BarRect` | крошечный размер окна | `Paint_NormalEmptyTiny` | Debug 1/1, Release 1/1 | THistogramTests.ByteAtPoint_MatchesBars, THistogramTests.ByteAtPoint_UnevenWidth_EveryByteReachable, THistogramTests.Hint_ByteCountPercent, THistogramTests.Paint_NormalEmptyTiny |
| `App.BinaryLab.Controls` | `BlockAtPoint` | точка вне карты; блоков больше, чем клеток | `Cells_ConsistentWithBlockAtPoint`, `ManyBlocks_Aggregated` | Debug 2/2, Release 2/2 | TEntropyMapTests.Cells_ConsistentWithBlockAtPoint, TEntropyMapTests.ManyBlocks_Aggregated, TEntropyMapTests.Paint_CellColourAndEmptyAndTiny |
| `App.BinaryLab.Controls` | `BlockCount` | до данных и после пустых данных — 0 | `EntropyMap_BlockCountEmptyAndData` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EntropyMap_BlockCountEmptyAndData, TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare |
| `App.BinaryLab.Controls` | `BlocksPerCell` | блоков больше, чем клеток | `ManyBlocks_Aggregated` | Debug 1/1, Release 1/1 | TEntropyMapTests.Cells_ConsistentWithBlockAtPoint, TEntropyMapTests.ManyBlocks_Aggregated |
| `App.BinaryLab.Controls` | `ByteAtPoint` | неровная ширина — каждый байт достижим; точка вне графика | `ByteAtPoint_UnevenWidth_EveryByteReachable`, `ByteAtPoint_MatchesBars` | Debug 2/2, Release 2/2 | THistogramTests.ByteAtPoint_MatchesBars, THistogramTests.ByteAtPoint_UnevenWidth_EveryByteReachable, THistogramTests.Paint_NormalEmptyTiny |
| `App.BinaryLab.Controls` | `CellCount` | блоков больше, чем клеток | `ManyBlocks_Aggregated` | Debug 1/1, Release 1/1 | TEntropyMapTests.Cells_ConsistentWithBlockAtPoint, TEntropyMapTests.ManyBlocks_Aggregated, TEntropyMapTests.Paint_CellColourAndEmptyAndTiny |
| `App.BinaryLab.Controls` | `CellRect` | крайние клетки и агрегирование | `Cells_ConsistentWithBlockAtPoint`, `ManyBlocks_Aggregated` | Debug 2/2, Release 2/2 | TEntropyMapTests.Cells_ConsistentWithBlockAtPoint, TEntropyMapTests.Click_RaisesBlockOffset, TEntropyMapTests.Hint_RangeEntropyAndBand, TEntropyMapTests.ManyBlocks_Aggregated и ещё 2 |
| `App.BinaryLab.Controls` | `ClearHighlights` | после очистки подсветки нет | `Highlights_LookupAndHint` | Debug 1/1, Release 1/1 | THexViewTests.Highlights_LookupAndHint |
| `App.BinaryLab.Controls` | `ContentWidth` | точки правее данных | `OffsetAtPoint_OutsideColumns_False` | Debug 1/1, Release 1/1 | THexViewTests.OffsetAtPoint_OutsideColumns_False, THexViewTests.Rows_CountAndVisible |
| `App.BinaryLab.Controls` | `EntropyColor` | концы шкалы различны, монотонность | `EntropyColor_ScaleMonotonicAndDistinctEnds` | Debug 1/1, Release 1/1 | TEntropyMapTests.EntropyColor_ScaleMonotonicAndDistinctEnds, TEntropyMapTests.Paint_CellColourAndEmptyAndTiny |
| `App.BinaryLab.Controls` | `FindNext` | не найдено — позиция прежняя; переход в начало; регистр; без источника | `FindNext_FindsWrapsAndKeepsPositionWhenMissing`, `FindNext_IgnoreCase`, `NilSource_Safe` | Debug 3/3, Release 3/3 | THexViewTests.BeforeHandle_Safe, THexViewTests.FindNext_FindsWrapsAndKeepsPositionWhenMissing, THexViewTests.FindNext_IgnoreCase, THexViewTests.NilSource_Safe |
| `App.BinaryLab.Controls` | `GotoOffset` | смещение уже на экране; за концом; без окна | `Goto_VisibleOffset_DoesNotScroll`, `Goto_ScrollsIntoViewAndSelects`, `BeforeHandle_Safe` | Debug 3/3, Release 3/3 | TBinaryLabDarkThemeTests.AllControls_PaintInDarkTheme, THexViewTests.BeforeHandle_Safe, THexViewTests.BigVirtualSource_ScrollsToEndAndReadsOnlyPage, THexViewTests.FindNext_FindsWrapsAndKeepsPositionWhenMissing и ещё 6 |
| `App.BinaryLab.Controls` | `HighlightAt` | смещение вне подсветки → False | `Highlights_LookupAndHint` | Debug 1/1, Release 1/1 | THexViewTests.Highlights_LookupAndHint |
| `App.BinaryLab.Controls` | `HighlightCount` | после очистки — 0 | `Highlights_LookupAndHint` | Debug 1/1, Release 1/1 | THexViewTests.Highlights_LookupAndHint |
| `App.BinaryLab.Controls` | `HintTextAt` | точка вне данных | `Hint_RangeEntropyAndBand`, `Hint_ByteCountPercent` | Debug 2/2, Release 2/2 | TEntropyMapTests.Hint_RangeEntropyAndBand, TEntropyMapTests.ManyBlocks_Aggregated, TEntropyMapTests.Paint_CellColourAndEmptyAndTiny, THexViewTests.BigVirtualSource_ScrollsToEndAndReadsOnlyPage и ещё 7 |
| `App.BinaryLab.Controls` | `InvalidateData` | сброс кэша после прокрутки | `BinaryLab_ButtonsDialogsAndDoubleClicks` | Debug 1/1, Release 1/1 | TMainFormSmokeTests.BinaryLab_ButtonsDialogsAndDoubleClicks |
| `App.BinaryLab.Controls` | `MHBlendColor` | доли 0, 1 и 0,5 | `BinaryLab_ButtonsDialogsAndDoubleClicks` | Debug 1/1, Release 1/1 | TMainFormSmokeTests.BinaryLab_ButtonsDialogsAndDoubleClicks |
| `App.BinaryLab.Controls` | `OffsetAtPoint` | точки вне колонок; без источника; без окна | `OffsetAtPoint_OutsideColumns_False`, `NilSource_Safe`, `BeforeHandle_Safe` | Debug 3/3, Release 3/3 | THexViewTests.BeforeHandle_Safe, THexViewTests.BigVirtualSource_ScrollsToEndAndReadsOnlyPage, THexViewTests.NilSource_Safe, THexViewTests.OffsetAtPoint_InverseOfPointOfOffset и ещё 1 |
| `App.BinaryLab.Controls` | `OffsetAtX` | края полосы; нулевой размер файла | `OffsetAtX_Endpoints`, `ZeroFileSize_Safe` | Debug 2/2, Release 2/2 | TRangeStripTests.Click_OnRangeGivesStart_ElsewhereComputed, TRangeStripTests.OffsetAtX_Endpoints, TRangeStripTests.ZeroFileSize_Safe |
| `App.BinaryLab.Controls` | `OffsetDigits` | ровно 4 ГБ и на байт больше; без источника | `HexView_OffsetDigitsAtFourGigabytes` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.HexView_OffsetDigitsAtFourGigabytes, THexViewTests.BigVirtualSource_ScrollsToEndAndReadsOnlyPage, THexViewTests.Rows_CountAndVisible |
| `App.BinaryLab.Controls` | `PointOfOffset` | смещение вне экрана; без источника | `OffsetAtPoint_InverseOfPointOfOffset`, `NilSource_Safe` | Debug 2/2, Release 2/2 | THexViewTests.BeforeHandle_Safe, THexViewTests.BigVirtualSource_ScrollsToEndAndReadsOnlyPage, THexViewTests.Goto_ScrollsIntoViewAndSelects, THexViewTests.Highlights_LookupAndHint и ещё 4 |
| `App.BinaryLab.Controls` | `RangeAtX` | вне диапазонов; нулевой размер файла | `Click_OnRangeGivesStart_ElsewhereComputed`, `ZeroFileSize_Safe` | Debug 2/2, Release 2/2 | TRangeStripTests.Click_OnRangeGivesStart_ElsewhereComputed, TRangeStripTests.NarrowRange_AtLeastOnePixel, TRangeStripTests.ZeroFileSize_Safe |
| `App.BinaryLab.Controls` | `RowCount` | без источника — 0 | `NilSource_Safe` | Debug 1/1, Release 1/1 | THexViewTests.BigVirtualSource_ScrollsToEndAndReadsOnlyPage, THexViewTests.NilSource_Safe, THexViewTests.Rows_CountAndVisible, THexViewTests.ScrollBarMessages_Scroll и ещё 1 |
| `App.BinaryLab.Controls` | `ScrollRows` | не выше начала | `BinaryLab_ButtonsDialogsAndDoubleClicks` | Debug 1/1, Release 1/1 | TMainFormSmokeTests.BinaryLab_ButtonsDialogsAndDoubleClicks |
| `App.BinaryLab.Controls` | `SetBands` | полоса в подсказке | `Hint_RangeEntropyAndBand` | Debug 1/1, Release 1/1 | TEntropyMapTests.Hint_RangeEntropyAndBand |
| `App.BinaryLab.Controls` | `SetData` | пустые данные; крошечное окно | `Paint_CellColourAndEmptyAndTiny` | Debug 1/1, Release 1/1 | TBinaryLabApiTests.EntropyMap_BlockCountEmptyAndData, TBinaryLabDarkThemeTests.AllControls_PaintInDarkTheme, TEntropyMapTests.Cells_ConsistentWithBlockAtPoint, TEntropyMapTests.Click_RaisesBlockOffset и ещё 19 |
| `App.BinaryLab.Controls` | `SetHistogram` | пустой массив; меньше 256 значений | `Histogram_BarFractionEdges`, `Paint_NormalEmptyTiny` | Debug 2/2, Release 2/2 | TBinaryLabApiTests.Histogram_BarFractionEdges, TBinaryLabDarkThemeTests.AllControls_PaintInDarkTheme, THistogramTests.ByteAtPoint_MatchesBars, THistogramTests.ByteAtPoint_UnevenWidth_EveryByteReachable и ещё 3 |
| `App.BinaryLab.Controls` | `SetRanges` | нулевой размер файла | `ZeroFileSize_Safe` | Debug 1/1, Release 1/1 | TBinaryLabDarkThemeTests.AllControls_PaintInDarkTheme, TRangeStripTests.ZeroFileSize_Safe |
| `App.BinaryLab.Controls` | `VisibleRows` | огромный виртуальный файл | `BigVirtualSource_ScrollsToEndAndReadsOnlyPage` | Debug 1/1, Release 1/1 | THexViewTests.BigVirtualSource_ScrollsToEndAndReadsOnlyPage, THexViewTests.FindNext_FindsWrapsAndKeepsPositionWhenMissing, THexViewTests.Goto_ScrollsIntoViewAndSelects, THexViewTests.HugeSource_ScrollBarScaled и ещё 7 |
| `App.BinaryLabPage` | `Busy` | после ошибки, отмены и закрытия окна — False | `BinaryLab_ErrorsCancelAndCloseWhileBusy`, `BinaryLab_PageMethods_WithoutDataAreSafe` | Debug 2/2, Release 2/2 | TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare, TMainFormSmokeTests.BinaryLab_ButtonsDialogsAndDoubleClicks, TMainFormSmokeTests.BinaryLab_ErrorsCancelAndCloseWhileBusy, TMainFormSmokeTests.BinaryLab_PageAndMenus и ещё 1 |
| `App.BinaryLabPage` | `Cancel` | в простое; во время анализа; закрытие окна во время анализа | `BinaryLab_PageMethods_WithoutDataAreSafe`, `BinaryLab_ErrorsCancelAndCloseWhileBusy` | Debug 2/2, Release 2/2 | TMainFormSmokeTests.BinaryLab_ErrorsCancelAndCloseWhileBusy, TMainFormSmokeTests.BinaryLab_PageMethods_WithoutDataAreSafe |
| `App.BinaryLabPage` | `CompareWith` | без отчёта; пустой путь; отсутствующий файл — ошибка, отчёт сохранён | `BinaryLab_PageMethods_WithoutDataAreSafe` | Debug 1/1, Release 1/1 | TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare, TMainFormSmokeTests.BinaryLab_PageMethods_WithoutDataAreSafe |
| `App.BinaryLabPage` | `ExportDiff` | без сравнения — файла нет | `BinaryLab_PageMethods_WithoutDataAreSafe` | Debug 1/1, Release 1/1 | TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare, TMainFormSmokeTests.BinaryLab_PageMethods_WithoutDataAreSafe |
| `App.BinaryLabPage` | `ExportReport` | без отчёта — файла нет | `BinaryLab_PageMethods_WithoutDataAreSafe` | Debug 1/1, Release 1/1 | TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare, TMainFormSmokeTests.BinaryLab_PageMethods_WithoutDataAreSafe, TMainFormSmokeTests.Findings_ListCardAndExport |
| `App.BinaryLabPage` | `FindPattern` | без файла; пустой шаблон; не найдено → -1 | `BinaryLab_PageMethods_WithoutDataAreSafe`, `BinaryLab_AnalyzeNavigateFindExportCompare` | Debug 2/2, Release 2/2 | TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare, TMainFormSmokeTests.BinaryLab_PageMethods_WithoutDataAreSafe |
| `App.BinaryLabPage` | `OpenFile` | пустой путь; отсутствующий файл; повторное открытие во время работы | `BinaryLab_PageMethods_WithoutDataAreSafe`, `BinaryLab_ErrorsCancelAndCloseWhileBusy` | Debug 2/2, Release 2/2 | TMainFormSmokeTests.BinaryLab_ErrorsCancelAndCloseWhileBusy, TMainFormSmokeTests.BinaryLab_PageMethods_WithoutDataAreSafe |
| `App.BinaryLabPage` | `ParseOffset` | пусто; посторонние символы; hex и десятичная запись | `BinaryLab_AnalyzeNavigateFindExportCompare` | Debug 1/1, Release 1/1 | TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare |
| `App.BinaryLabPage` | `ShowOffset` | без файла; отрицательное смещение; длина меньше 1 | `BinaryLab_PageMethods_WithoutDataAreSafe` | Debug 1/1, Release 1/1 | TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare, TMainFormSmokeTests.BinaryLab_PageMethods_WithoutDataAreSafe |

## Проверки по функциям

Строки `Assert`, которые проверяют функцию в тестах её граничных и ошибочных случаев: строка с
вызовом функции или проверка сразу после вызова (файл:строка — текст проверки).

DUnitX прерывает тест на первой неудачной проверке, поэтому пройденный тест означает, что каждая
выполненная строка `Assert` в нём прошла. Строки под условием `if` перечислены ниже: для каждой тест
отдельно проверяет, что ветка выполнялась (счётчик или предусловие).

- условная: `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:419` (Truncated_AtEveryLength_NeverRaises) под `if LPe.Valid and (LLength < Length(LFull)) and (LLength > $400) then`
- условная: `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:923` (EntropyColor_ScaleMonotonicAndDistinctEnds) под `while E <= 8.0001 do`

### `BinaryLab.Analyzer.MHAnalyzeBinaryFile` — проверок: 11

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:382` (File_Missing_Raises): `Assert.WillRaise(`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:362` (File_AnalysedWithoutModification): `Assert.AreEqual(LPath, LReport.Path);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:363` (File_AnalysedWithoutModification): `Assert.IsTrue(LReport.LastWriteUtc > 0);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:403` (Signature_FromFileApi_AndApiFailure): `Assert.AreEqual(Ord(sgSignedTrusted), Ord(LReport.Signature.State));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:404` (Signature_FromFileApi_AndApiFailure): `Assert.AreEqual('Test Publisher', LReport.Signature.Signer);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:409` (Signature_FromFileApi_AndApiFailure): `Assert.AreEqual(Ord(sgCheckFailed), Ord(LReport.Signature.State));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:410` (Signature_FromFileApi_AndApiFailure): `Assert.IsTrue(LReport.Signature.Error.Contains('сбой'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:417` (Signature_FromFileApi_AndApiFailure): `Assert.AreEqual(0, LApi.Calls);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:418` (Signature_FromFileApi_AndApiFailure): `Assert.AreEqual(Ord(sgNotChecked), Ord(LReport.Signature.State));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:431` (RealSystemFiles_SignedAndParsed): `Assert.AreEqual(0, Integer(Length(LReport.Errors)), string.Join('; ', LReport.Errors));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:432` (RealSystemFiles_SignedAndParsed): `Assert.IsTrue(LReport.Pe.Valid);`

### `BinaryLab.Analyzer.MHAnalyzeBinarySource` — проверок: 9

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:284` (TextEmptyAndUnknown): `Assert.AreEqual(Ord(bkScript), Ord(LReport.FileType.Kind));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:285` (TextEmptyAndUnknown): `Assert.IsFalse(LReport.Pe.Valid);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:288` (TextEmptyAndUnknown): `Assert.AreEqual(Ord(bkEmpty), Ord(LReport.FileType.Kind));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:289` (TextEmptyAndUnknown): `Assert.AreEqual(0, LReport.Score);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:293` (TextEmptyAndUnknown): `Assert.AreEqual(Ord(bkUnknown), Ord(LReport.FileType.Kind));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:294` (TextEmptyAndUnknown): `Assert.IsTrue(LReport.Entropy.Overall > 7.9);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:306` (Partial_WhenLargerThanScanLimit): `Assert.IsTrue(LReport.Partial);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:307` (Partial_WhenLargerThanScanLimit): `Assert.IsTrue(Length(LReport.Notes) > 0);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:325` (Progress_AndCancel): `Assert.IsTrue(AStage <> '');`

### `BinaryLab.Anomalies.MHDetectAnomalies` — проверок: 18

- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:659` (CleanProgram_NoThreatVerdict): `Assert.AreEqual(0, LReport.Score, Codes(LReport));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:660` (CleanProgram_NoThreatVerdict): `Assert.AreEqual(Ord(rlNone), Ord(LReport.Level));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:1028` (DamagedHeader_NonPeData): `Assert.IsTrue(LCodes.Contains(BL_PE_DAMAGED), LCodes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:1033` (DamagedHeader_NonPeData): `Assert.IsTrue(LCodes.Contains(BL_HIGH_ENTROPY_FILE), LCodes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:1036` (DamagedHeader_NonPeData): `Assert.AreEqual(0, LReport.Score, 'Сжатый архив — не угроза');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:791` (DotNet_NoImportsIsNormal): `Assert.IsTrue(LCodes.Contains(BL_DOTNET), LCodes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:792` (DotNet_NoImportsIsNormal): `Assert.IsFalse(LCodes.Contains(BL_FEW_IMPORTS), LCodes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:814` (Driver_UnsignedAndChecksum): `Assert.IsTrue(LCodes.Contains(BL_UNSIGNED_DRIVER), LCodes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:815` (Driver_UnsignedAndChecksum): `Assert.IsTrue(LCodes.Contains(BL_CHECKSUM_MISMATCH), LCodes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:974` (Overlay_EncryptedVsInstaller): `Assert.IsTrue(LCodes.Contains(BL_ENCRYPTED_OVERLAY), LCodes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:981` (Overlay_EncryptedVsInstaller): `Assert.IsFalse(LCodes.Contains(BL_ENCRYPTED_OVERLAY), LCodes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:982` (Overlay_EncryptedVsInstaller): `Assert.IsTrue(LCodes.Contains(BL_OVERLAY), LCodes);`
- … и ещё 6

### `BinaryLab.Anomalies.MHDetectInstaller` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:989` (Overlay_EncryptedVsInstaller): `Assert.AreEqual('Inno Setup', MHDetectInstaller(LReport));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:994` (Overlay_EncryptedVsInstaller): `Assert.AreEqual('', MHDetectInstaller(LReport));`

### `BinaryLab.Anomalies.MHPackerBySectionName` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:708` (UpxLikePacking): `Assert.AreEqual('UPX', MHPackerBySectionName('upx1'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:709` (UpxLikePacking): `Assert.AreEqual('', MHPackerBySectionName('.text'));`

### `BinaryLab.Anomalies.MHScoreBinaryReport` — проверок: 7

- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:1049` (Score_ClampedAndLevelFromThresholds): `Assert.AreEqual(100, LReport.Score);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:1050` (Score_ClampedAndLevelFromThresholds): `Assert.AreEqual(Ord(rlHighlySuspicious), Ord(LReport.Level));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:1054` (Score_ClampedAndLevelFromThresholds): `Assert.AreEqual(0, LReport.Score);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:1055` (Score_ClampedAndLevelFromThresholds): `Assert.AreEqual(Ord(rlNone), Ord(LReport.Level));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:845` (Signature_InvalidAndTrustedHalvesScore): `Assert.IsTrue(LReport.Score > 0);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:846` (Signature_InvalidAndTrustedHalvesScore): `Assert.AreEqual(LReport.Score div 2, LTrusted.Score);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:1036` (DamagedHeader_NonPeData): `Assert.AreEqual(0, LReport.Score, 'Сжатый архив — не угроза');`

### `BinaryLab.Diff.MHCompareBinaries` — проверок: 7

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:456` (Identical_Files): `Assert.IsTrue(LDiff.Identical);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:457` (Identical_Files): `Assert.AreEqual(100.0, LDiff.SimilarityPercent, 0.001);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:536` (DifferentSizes_TailIsChanged): `Assert.IsFalse(LDiff.Identical);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:537` (DifferentSizes_TailIsChanged): `Assert.AreEqual(1, Integer(Length(LDiff.ChangedRanges)), 'Один непрерывный хвост');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:591` (Limits_Truncated): `Assert.IsTrue(LDiff.Truncated);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:592` (Limits_Truncated): `Assert.AreEqual(MH_DIFF_MAX_ITEMS_PER_AREA, LDiff.CountOf(MH_DIFF_AREA_STRING));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:608` (NilAndCancel): `Assert.WillRaise(`

### `BinaryLab.Diff.MHDiffAreaTitle` — проверок: 3

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:360` (DiffTitles_AndSaveDiff): `Assert.IsTrue(MHDiffAreaTitle(LArea) <> '');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:361` (DiffTitles_AndSaveDiff): `Assert.AreNotEqual(LArea, MHDiffAreaTitle(LArea), 'Область переведена: ' + LArea);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:363` (DiffTitles_AndSaveDiff): `Assert.AreEqual('other', MHDiffAreaTitle('other'), 'Неизвестная область — как есть');`

### `BinaryLab.Embedded.MHFindEmbedded` — проверок: 23

- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:769` (Embedded_RandomData_NoFalsePositives): `Assert.AreEqual(0, Integer(Length(Find(TestRandomBytes(256 * 1024, 777), Options))));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:770` (Embedded_RandomData_NoFalsePositives): `Assert.AreEqual(0, Integer(Length(Find(TestRandomBytes(2 * MB, 4242), Options))), 'Случайные 2 МБ');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:771` (Embedded_RandomData_NoFalsePositives): `Assert.AreEqual(0, Integer(Length(Find(TestCodeBytes(512 * 1024), Options))), 'Машинный код');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:772` (Embedded_RandomData_NoFalsePositives): `Assert.AreEqual(0, Integer(Length(Find(nil, Options))), 'Пустой источник');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:773` (Embedded_RandomData_NoFalsePositives): `Assert.AreEqual(0, Integer(Length(MHFindEmbedded(nil, Options, nil, nil))), 'Источник nil');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:774` (Embedded_RandomData_NoFalsePositives): `Assert.AreEqual(0, Integer(Length(Find(TestBytes([$4D]), Options))), 'Один байт');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:785` (Embedded_WeakSignaturesInText_Ignored): `Assert.AreEqual(0, Integer(Length(Find(LData, Options))),`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:791` (Embedded_OffsetZero_NotReported): `Assert.AreEqual(0, Integer(Length(Find(TestMinimalPe, Options))), 'Сам файл — не вложение');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:792` (Embedded_OffsetZero_NotReported): `Assert.AreEqual(0, Integer(Length(Find(TestConcat([TestBytes([$1F, $8B, $08, 0]), TestRandomBytes(100)]), Options))));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:793` (Embedded_OffsetZero_NotReported): `Assert.AreEqual(0, Integer(Length(Find(TestConcat([TestAscii('@echo off'), TestRandomBytes(100)]), Options))));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:794` (Embedded_OffsetZero_NotReported): `Assert.AreEqual(1, Integer(Length(Find(TestConcat([TestBytes([0]), TestAscii('%PDF-1.5'), Zeros(10)]), Options))),`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:837` (Embedded_BogusSize_DoesNotHideRest): `Assert.AreEqual(2, Integer(Length(LFound)));`
- … и ещё 11

### `BinaryLab.Entropy.MHAnalyzeEntropy` — проверок: 15

- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:123` (Entropy_EmptyAndNilSource): `Assert.AreEqual(256, LInfo.BlockSize, 'Размер блока задан и для пустого файла');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:124` (Entropy_EmptyAndNilSource): `Assert.AreEqual(0, Integer(Length(LInfo.Blocks)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:131` (Entropy_EmptyAndNilSource): `Assert.AreEqual(0, Integer(Length(LInfo.Blocks)), 'Источник nil — пустой результат');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:141` (Entropy_TinyFile): `Assert.AreEqual(1, Integer(Length(LInfo.Blocks)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:142` (Entropy_TinyFile): `Assert.AreEqual<Int64>(0, LInfo.Blocks[0].Offset);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:186` (Entropy_ExplicitBlockSize_LastPartialBlock): `Assert.AreEqual(300, LInfo.BlockSize);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:187` (Entropy_ExplicitBlockSize_LastPartialBlock): `Assert.AreEqual(4, Integer(Length(LInfo.Blocks)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:195` (Entropy_ExplicitBlockSize_LastPartialBlock): `Assert.AreEqual(64, LInfo.BlockSize);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:196` (Entropy_ExplicitBlockSize_LastPartialBlock): `Assert.AreEqual(16, Integer(Length(LInfo.Blocks)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:205` (Entropy_AllZero_NoHighRegions): `Assert.AreEqual(0.0, LInfo.Overall, 1e-12);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:206` (Entropy_AllZero_NoHighRegions): `Assert.AreEqual<Int64>(65536, LInfo.Histogram[0]);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:280` (Entropy_BlocksAcrossReadChunks): `Assert.AreEqual<Int64>(3 * MB, LInfo.BytesScanned);`
- … и ещё 3

### `BinaryLab.Entropy.MHRangeEntropy` — проверок: 11

- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:346` (RangeEntropy_BoundsAndClipping): `Assert.AreEqual(0.0, MHRangeEntropy(LSource, 0, 1000), 1e-12, 'Нули');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:347` (RangeEntropy_BoundsAndClipping): `Assert.IsTrue(MHRangeEntropy(LSource, 1000, 100000) > 7.9, 'Случайные данные');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:348` (RangeEntropy_BoundsAndClipping): `Assert.AreEqual(0.0, MHRangeEntropy(LSource, 0, 100000, 1000), 1e-12, 'Лимит AMaxBytes');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:349` (RangeEntropy_BoundsAndClipping): `Assert.AreEqual(2.0, MHRangeEntropy(LSource, 101000, 1000000), 1e-9, 'Обрезано по концу файла');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:350` (RangeEntropy_BoundsAndClipping): `Assert.AreEqual(-1.0, MHRangeEntropy(LSource, 101004, 10), 'Начало за концом файла');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:351` (RangeEntropy_BoundsAndClipping): `Assert.AreEqual(-1.0, MHRangeEntropy(LSource, 5000000, 10), 'Далеко за концом');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:352` (RangeEntropy_BoundsAndClipping): `Assert.AreEqual(-1.0, MHRangeEntropy(LSource, -1, 10), 'Отрицательное смещение');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:353` (RangeEntropy_BoundsAndClipping): `Assert.AreEqual(-1.0, MHRangeEntropy(LSource, 0, 0), 'Пустой диапазон');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:354` (RangeEntropy_BoundsAndClipping): `Assert.AreEqual(-1.0, MHRangeEntropy(LSource, 0, 10, 0), 'Нулевой лимит');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:355` (RangeEntropy_BoundsAndClipping): `Assert.AreEqual(-1.0, MHRangeEntropy(Src(nil), 0, 10), 'Пустой источник');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:356` (RangeEntropy_BoundsAndClipping): `Assert.AreEqual(-1.0, MHRangeEntropy(nil, 0, 10), 'Источник nil');`

### `BinaryLab.FileType.MHDetectBinaryType` — проверок: 17

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:392` (Detect_EmptyAndUnknown): `Assert.AreEqual(Ord(bkEmpty), Ord(LInfo.Kind));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:393` (Detect_EmptyAndUnknown): `Assert.IsFalse(LInfo.ExtensionMismatch);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:395` (Detect_EmptyAndUnknown): `Assert.AreEqual(Ord(bkUnknown), Ord(LInfo.Kind));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:396` (Detect_EmptyAndUnknown): `Assert.IsFalse(LInfo.ExtensionMismatch, 'Неизвестные данные не сравниваются с расширением');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:397` (Detect_EmptyAndUnknown): `Assert.AreEqual(Ord(bkUnknown), Ord(Detect([0], 'x').Kind), 'Один нулевой байт');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:398` (Detect_EmptyAndUnknown): `Assert.AreEqual(Ord(bkText), Ord(Detect([$4D], 'x').Kind), 'Один печатный символ — текст');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:431` (Detect_DamagedPe_IsMsDos): `Assert.AreEqual(Ord(bkMsDos), Ord(Detect(LData, 'x.exe').Kind));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:435` (Detect_DamagedPe_IsMsDos): `Assert.AreEqual(Ord(bkMsDos), Ord(Detect(LData, 'x.exe').Kind));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:437` (Detect_DamagedPe_IsMsDos): `Assert.AreEqual(Ord(bkMsDos), Ord(Detect(Copy(TestMinimalPe, 0, 64), 'x.exe').Kind));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:406` (Detect_ExtensionMismatch): `Assert.IsTrue(LInfo.ExtensionMismatch, 'Программа под видом картинки');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:407` (Detect_ExtensionMismatch): `Assert.AreEqual('.jpg', LInfo.Extension);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:408` (Detect_ExtensionMismatch): `Assert.IsTrue(Detect(TestMinimalPe, 'update.dat').ExtensionMismatch, 'Программа с расширением .dat');`
- … и ещё 5

### `BinaryLab.FileType.MHExpectedExtensions` — проверок: 9

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:297` (Extensions_ExpectedAndInList): `Assert.IsTrue(MHExtensionInList('.dll', MHExpectedExtensions(bkPE)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:298` (Extensions_ExpectedAndInList): `Assert.IsTrue(MHExtensionInList('.SYS', MHExpectedExtensions(bkPE)), 'Без учёта регистра');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:299` (Extensions_ExpectedAndInList): `Assert.IsFalse(MHExtensionInList('.dat', MHExpectedExtensions(bkPE)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:300` (Extensions_ExpectedAndInList): `Assert.IsFalse(MHExtensionInList('.bin', MHExpectedExtensions(bkPE)), '.bin — не расширение программ Windows');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:301` (Extensions_ExpectedAndInList): `Assert.IsTrue(MHExtensionInList('.docx', MHExpectedExtensions(bkZip)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:302` (Extensions_ExpectedAndInList): `Assert.IsTrue(MHExtensionInList('.ps1', MHExpectedExtensions(bkScript)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:303` (Extensions_ExpectedAndInList): `Assert.IsFalse(MHExtensionInList('', MHExpectedExtensions(bkPE)), 'Пустое расширение');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:305` (Extensions_ExpectedAndInList): `Assert.AreEqual('', MHExpectedExtensions(bkUnknown));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:306` (Extensions_ExpectedAndInList): `Assert.AreEqual('', MHExpectedExtensions(bkEmpty));`

### `BinaryLab.FileType.MHExtensionInList` — проверок: 8

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:297` (Extensions_ExpectedAndInList): `Assert.IsTrue(MHExtensionInList('.dll', MHExpectedExtensions(bkPE)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:298` (Extensions_ExpectedAndInList): `Assert.IsTrue(MHExtensionInList('.SYS', MHExpectedExtensions(bkPE)), 'Без учёта регистра');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:299` (Extensions_ExpectedAndInList): `Assert.IsFalse(MHExtensionInList('.dat', MHExpectedExtensions(bkPE)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:300` (Extensions_ExpectedAndInList): `Assert.IsFalse(MHExtensionInList('.bin', MHExpectedExtensions(bkPE)), '.bin — не расширение программ Windows');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:301` (Extensions_ExpectedAndInList): `Assert.IsTrue(MHExtensionInList('.docx', MHExpectedExtensions(bkZip)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:302` (Extensions_ExpectedAndInList): `Assert.IsTrue(MHExtensionInList('.ps1', MHExpectedExtensions(bkScript)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:303` (Extensions_ExpectedAndInList): `Assert.IsFalse(MHExtensionInList('', MHExpectedExtensions(bkPE)), 'Пустое расширение');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:304` (Extensions_ExpectedAndInList): `Assert.IsFalse(MHExtensionInList('.exe', ''), 'Пустой список');`

### `BinaryLab.FileType.MHIdentifyAt` — проверок: 7

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:453` (IdentifyAt_StrictRejectsWeakSignatures): `Assert.IsFalse(MHIdentifyAt(LReader, 100, True, LKind, LDescription, LSize), 'MZ без PE');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:454` (IdentifyAt_StrictRejectsWeakSignatures): `Assert.IsTrue(MHIdentifyAt(LReader, 100, False, LKind, LDescription, LSize), 'Нестрого — MS-DOS');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:456` (IdentifyAt_StrictRejectsWeakSignatures): `Assert.IsFalse(MHIdentifyAt(LReader, 107, True, LKind, LDescription, LSize), 'BM');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:457` (IdentifyAt_StrictRejectsWeakSignatures): `Assert.IsFalse(MHIdentifyAt(LReader, 113, True, LKind, LDescription, LSize), 'Текст');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:458` (IdentifyAt_StrictRejectsWeakSignatures): `Assert.IsFalse(MHIdentifyAt(LReader, 128, True, LKind, LDescription, LSize), 'JPEG без маркера');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:459` (IdentifyAt_StrictRejectsWeakSignatures): `Assert.IsFalse(MHIdentifyAt(LReader, Length(LData) + 10, False, LKind, LDescription, LSize), 'За концом');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:467` (IdentifyAt_StrictRejectsWeakSignatures): `Assert.IsTrue(MHIdentifyAt(LReader, 1000, True, LKind, LDescription, LSize));`

### `BinaryLab.FileType.MHMachineName` — проверок: 5

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:281` (MachineSubsystemAndPeKindNames): `Assert.AreEqual('x86', MHMachineName(IMAGE_FILE_MACHINE_I386));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:282` (MachineSubsystemAndPeKindNames): `Assert.AreEqual('x64', MHMachineName(IMAGE_FILE_MACHINE_AMD64));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:283` (MachineSubsystemAndPeKindNames): `Assert.AreEqual('ARM64', MHMachineName(IMAGE_FILE_MACHINE_ARM64));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:284` (MachineSubsystemAndPeKindNames): `Assert.AreEqual('ARM', MHMachineName(IMAGE_FILE_MACHINE_ARMNT));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:285` (MachineSubsystemAndPeKindNames): `Assert.AreEqual('0x1234', MHMachineName($1234), 'Неизвестная архитектура — код');`

### `BinaryLab.FileType.MHProbePe` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:489` (ProbePe_ImageEndAndHugeLfanew): `Assert.IsTrue(MHProbePe(LReader, 0, LInfo));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:502` (ProbePe_ImageEndAndHugeLfanew): `Assert.IsFalse(MHProbePe(LReader, 0, LInfo), 'Огромный e_lfanew');`

### `BinaryLab.Pe.MHComputePeChecksum` — проверок: 7

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:400` (Checksum_EmptyTinyFieldOutsideAndCancel): `Assert.AreEqual<Cardinal>(0, MHComputePeChecksum(TMHBytesSource.Create(nil), 64));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:402` (Checksum_EmptyTinyFieldOutsideAndCancel): `Assert.AreEqual<Cardinal>($41 + 1, MHComputePeChecksum(TMHBytesSource.Create(TestBytes([$41])), 64));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:404` (Checksum_EmptyTinyFieldOutsideAndCancel): `Assert.AreEqual<Cardinal>($0201 + $0403 + 4, MHComputePeChecksum(TMHBytesSource.Create(TestBytes([1, 2, 3, 4])), 1000));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:406` (Checksum_EmptyTinyFieldOutsideAndCancel): `Assert.AreEqual<Cardinal>(0 + 6, MHComputePeChecksum(TMHBytesSource.Create(TestBytes([9, 9, 9, 9, 0, 0])), 0));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:408` (Checksum_EmptyTinyFieldOutsideAndCancel): `Assert.AreEqual<Cardinal>(1 + 4, MHComputePeChecksum(TMHBytesSource.Create(TestBytes([$FF, $FF, 1, 0])), 1000));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:338` (Checksum_MatchesBuilderIncludingOddLength): `Assert.AreEqual<Cardinal>(LPe.CheckSum, MHComputePeChecksum(TMHBytesSource.Create(LData),`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:342` (Checksum_MatchesBuilderIncludingOddLength): `Assert.AreNotEqual<Cardinal>(LPe.CheckSum, MHComputePeChecksum(TMHBytesSource.Create(LData),`

### `BinaryLab.Pe.MHParsePe` — проверок: 17

- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:381` (NotPe_IsInvalidWithReason): `Assert.IsFalse(LPe.Valid);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:382` (NotPe_IsInvalidWithReason): `Assert.AreEqual(1, Integer(Length(LPe.Warnings)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:384` (NotPe_IsInvalidWithReason): `Assert.IsFalse(LPe.Valid);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:388` (NotPe_IsInvalidWithReason): `Assert.IsFalse(LPe.Valid);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:389` (NotPe_IsInvalidWithReason): `Assert.IsTrue(HasWarning(LPe, 'Magic'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:419` (Truncated_AtEveryLength_NeverRaises): `Assert.IsTrue(Length(LPe.Warnings) > 0, Format('Обрезка до %d байт без предупреждений', [LLength]));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:426` (Truncated_AtEveryLength_NeverRaises): `Assert.IsTrue(Parse(LFull).Valid and (Length(Parse(LFull).Warnings) = 0), 'Целый файл — без предупреждений');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:445` (HugeCounts_AreClampedWithWarnings): `Assert.IsTrue(LPe.Valid);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:446` (HugeCounts_AreClampedWithWarnings): `Assert.IsTrue(Length(LPe.Sections) <= PE_MAX_SECTIONS);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:471` (ImportOutsideFile_AndUnterminatedThunks): `Assert.IsTrue(LPe.Valid);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:472` (ImportOutsideFile_AndUnterminatedThunks): `Assert.AreEqual(0, Integer(Length(LPe.Imports)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:477` (ImportOutsideFile_AndUnterminatedThunks): `Assert.IsTrue(LPe.Valid);`
- … и ещё 5

### `BinaryLab.Pe.MHPeLocate` — проверок: 6

- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:362` (Locate_DescribesOffsets): `Assert.IsTrue(MHPeLocate(LPe, Length(LData), 10).Contains('заголов') or`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:364` (Locate_DescribesOffsets): `Assert.IsTrue(MHPeLocate(LPe, Length(LData), LBuilder.SectionRawOffset('.text') + 3).Contains('.text'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:365` (Locate_DescribesOffsets): `Assert.IsTrue(MHPeLocate(LPe, Length(LData), LBuilder.ImageEnd + 5) <> '');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:366` (Locate_DescribesOffsets): `Assert.AreNotEqual(MHPeLocate(LPe, Length(LData), LBuilder.ImageEnd + 5),`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:368` (Locate_DescribesOffsets): `Assert.AreEqual('', MHPeLocate(LPe, Length(LData), -1));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:369` (Locate_DescribesOffsets): `Assert.AreEqual('', MHPeLocate(Default(TMHPeInfo), 100, 5));`

### `BinaryLab.Pe.MHPeRvaToOffset` — проверок: 5

- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:313` (EntryPoint_OffsetSectionAndRvaMapping): `Assert.AreEqual<Int64>($40, MHPeRvaToOffset(LPe, $40));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:314` (EntryPoint_OffsetSectionAndRvaMapping): `Assert.AreEqual<Int64>(LTextRaw + 5, MHPeRvaToOffset(LPe, LTextRva + 5));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:315` (EntryPoint_OffsetSectionAndRvaMapping): `Assert.AreEqual<Int64>(MH_NO_OFFSET, MHPeRvaToOffset(LPe, LTextRva + $2000), 'Нули в памяти, нет данных в файле');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:316` (EntryPoint_OffsetSectionAndRvaMapping): `Assert.AreEqual<Int64>(MH_NO_OFFSET, MHPeRvaToOffset(LPe, $7FFFFFF0));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:317` (EntryPoint_OffsetSectionAndRvaMapping): `Assert.AreEqual<Int64>(MH_NO_OFFSET, MHPeRvaToOffset(Default(TMHPeInfo), $10), 'Не PE');`

### `BinaryLab.Pe.MHRangeSha256` — проверок: 6

- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:593` (RangeSha256_Bounds): `Assert.AreEqual('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', MHRangeSha256(LSource, 0, 3));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:594` (RangeSha256_Bounds): `Assert.AreEqual('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', MHRangeSha256(LSource, 0, 100),`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:596` (RangeSha256_Bounds): `Assert.AreEqual('', MHRangeSha256(LSource, 3, 10));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:597` (RangeSha256_Bounds): `Assert.AreEqual('', MHRangeSha256(LSource, -1, 10));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:598` (RangeSha256_Bounds): `Assert.AreEqual('', MHRangeSha256(LSource, 0, 0));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:599` (RangeSha256_Bounds): `Assert.AreEqual('', MHRangeSha256(nil, 0, 10));`

### `BinaryLab.Pe.MHResourceTypeName` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:253` (Resources_TreeTypesLanguagesAndContent): `Assert.AreEqual('ICON', MHResourceTypeName(3));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:254` (Resources_TreeTypesLanguagesAndContent): `Assert.AreEqual('', MHResourceTypeName(999));`

### `BinaryLab.Pe.MHSubsystemName` — проверок: 3

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:286` (MachineSubsystemAndPeKindNames): `Assert.IsTrue(MHSubsystemName(2) <> MHSubsystemName(3));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:287` (MachineSubsystemAndPeKindNames): `Assert.IsTrue(MHSubsystemName(1).Contains('Native'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:288` (MachineSubsystemAndPeKindNames): `Assert.IsTrue(MHSubsystemName(999).Contains('999'), 'Неизвестная подсистема — с номером');`

### `BinaryLab.Report.MHBinaryDiffToHtml` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:763` (Diff_JsonAndHtml): `Assert.IsFalse(LHtml.Contains('<CreateRemoteThread>'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:764` (Diff_JsonAndHtml): `Assert.IsFalse(LHtml.Contains('a<1>'));`

### `BinaryLab.Report.MHBinaryDiffToJson` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:755` (Diff_JsonAndHtml): `Assert.IsNotNull(LJson);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:756` (Diff_JsonAndHtml): `Assert.AreEqual(1, (LJson as TJSONObject).GetValue<TJSONArray>('items').Count);`

### `BinaryLab.Report.MHBinaryReportToHtml` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:699` (Html_EscapesFileData): `Assert.IsTrue(LHtml.StartsWith('<!DOCTYPE html>'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:700` (Html_EscapesFileData): `Assert.IsTrue(LHtml.Contains('<svg'), 'Карта энтропии');`

### `BinaryLab.Report.MHBinaryReportToJson` — проверок: 3

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:668` (Json_RoundTripStructure): `Assert.IsNotNull(LJson, 'Корректный JSON');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:670` (Json_RoundTripStructure): `Assert.AreEqual(LReport.Score, LRoot.GetValue<Integer>('score'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:688` (Json_RoundTripStructure): `Assert.IsNotNull(LJson);`

### `BinaryLab.Report.MHSaveBinaryDiff` — проверок: 4

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:378` (DiffTitles_AndSaveDiff): `Assert.IsNotNull(LJson, 'Расширение .JSON — без учёта регистра');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:379` (DiffTitles_AndSaveDiff): `Assert.IsTrue((LJson as TJSONObject).GetValue<Boolean>('identical'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:386` (DiffTitles_AndSaveDiff): `Assert.IsTrue(TFile.Exists(TPath.Combine(LDir, 'новая папка\x\diff.json')));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:387` (DiffTitles_AndSaveDiff): `Assert.WillRaiseDescendant(`

### `BinaryLab.Report.MHSaveBinaryReport` — проверок: 1

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:723` (Save_ByExtension): `Assert.IsNotNull(LJson);`

### `BinaryLab.Source.GetName` — проверок: 1

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:177` (FileSource_ReadsAndKeepsFileUnchanged): `Assert.AreEqual(LPath, LSource.Name);`

### `BinaryLab.Source.GetSize` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:151` (Reader_EmptySource): `Assert.AreEqual<Int64>(0, LReader.Size);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:176` (FileSource_ReadsAndKeepsFileUnchanged): `Assert.AreEqual<Int64>(200000, LSource.Size);`

### `BinaryLab.Source.InRange` — проверок: 3

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:116` (Reader_BoundsAreChecked): `Assert.IsTrue(LReader.InRange(0, 6));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:117` (Reader_BoundsAreChecked): `Assert.IsFalse(LReader.InRange(1, 6));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:118` (Reader_BoundsAreChecked): `Assert.IsFalse(LReader.InRange(0, -1));`

### `BinaryLab.Source.MHCheckCancel` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:182` (CheckCancel_NilFalseTrue): `Assert.WillRaise(`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:191` (CheckCancel_NilFalseTrue): `Assert.IsTrue(EMHBinaryLabCancelled.InheritsFrom(EMHBinaryLabError), 'Отмена — разновидность ошибки BinaryLab');`

### `BinaryLab.Source.MHFindBytes` — проверок: 17

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:98` (FindBytes_FoundCaseLimitAndBoundary): `Assert.AreEqual<Int64>(1024 * 1024 - 3, MHFindBytes(LSource, TestAscii('NeedleXY'), 0), 'На границе блока');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:99` (FindBytes_FoundCaseLimitAndBoundary): `Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('NeedleXY'), 1024 * 1024),`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:101` (FindBytes_FoundCaseLimitAndBoundary): `Assert.AreEqual<Int64>(2 * 1024 * 1024 + 100, MHFindBytes(LSource, TestAscii('NeedleXY'), 1024 * 1024, True),`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:103` (FindBytes_FoundCaseLimitAndBoundary): `Assert.AreEqual<Int64>(1024 * 1024 - 3, MHFindBytes(LSource, TestAscii('nEEDLExy'), 0, True), 'Без учёта регистра');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:104` (FindBytes_FoundCaseLimitAndBoundary): `Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('NeedleXY'), 0, False, nil, 1000), 'Лимит просмотра');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:105` (FindBytes_FoundCaseLimitAndBoundary): `Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('NeedleXY'), 0, False, nil, 1024 * 1024 + 4),`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:107` (FindBytes_FoundCaseLimitAndBoundary): `Assert.AreEqual<Int64>(1024 * 1024 - 3, MHFindBytes(LSource, TestAscii('NeedleXY'), 0, False, nil, 1024 * 1024 + 5));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:115` (FindBytes_EdgeAndErrorCases): `Assert.AreEqual<Int64>(0, MHFindBytes(LSource, TestAscii('abc'), 0));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:116` (FindBytes_EdgeAndErrorCases): `Assert.AreEqual<Int64>(3, MHFindBytes(LSource, TestAscii('abc'), 1));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:117` (FindBytes_EdgeAndErrorCases): `Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('abc'), 4), 'Хвост короче шаблона');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:118` (FindBytes_EdgeAndErrorCases): `Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('abcabcx'), 0), 'Шаблон длиннее данных');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:119` (FindBytes_EdgeAndErrorCases): `Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, nil, 0), 'Пустой шаблон');`
- … и ещё 5

### `BinaryLab.Source.MHParseHexPattern` — проверок: 9

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:140` (ParseHexPattern_ValidAndInvalid): `Assert.IsTrue(MHParseHexPattern('4D 5A 90', LPattern));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:143` (ParseHexPattern_ValidAndInvalid): `Assert.IsTrue(MHParseHexPattern('4d5a', LPattern));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:145` (ParseHexPattern_ValidAndInvalid): `Assert.IsTrue(MHParseHexPattern('0x4D,0x5A', LPattern));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:147` (ParseHexPattern_ValidAndInvalid): `Assert.IsTrue(MHParseHexPattern('de-ad:be'#9'ef', LPattern), 'Разделители');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:149` (ParseHexPattern_ValidAndInvalid): `Assert.IsFalse(MHParseHexPattern('', LPattern), 'Пусто');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:151` (ParseHexPattern_ValidAndInvalid): `Assert.IsFalse(MHParseHexPattern(' ', LPattern), 'Только пробелы');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:152` (ParseHexPattern_ValidAndInvalid): `Assert.IsFalse(MHParseHexPattern('4D 5', LPattern), 'Нечётное число цифр');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:153` (ParseHexPattern_ValidAndInvalid): `Assert.IsFalse(MHParseHexPattern('4G', LPattern), 'Не шестнадцатеричная цифра');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:154` (ParseHexPattern_ValidAndInvalid): `Assert.IsFalse(MHParseHexPattern('MZ', LPattern), 'Текст вместо байтов');`

### `BinaryLab.Source.MHReadChunks` — проверок: 3

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:277` (Chunks_LimitAndCancel): `Assert.IsTrue(ABase >= 1000);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:290` (Chunks_LimitAndCancel): `Assert.AreEqual(1, LCalls);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:322` (Chunks_LimitAndCancel): `Assert.AreEqual(0, LCalls);`

### `BinaryLab.Source.MHTextPattern` — проверок: 7

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:162` (TextPattern_AsciiAndUtf16): `Assert.AreEqual(2, Integer(Length(LPattern)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:163` (TextPattern_AsciiAndUtf16): `Assert.AreEqual<Byte>(Ord('A'), LPattern[0]);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:165` (TextPattern_AsciiAndUtf16): `Assert.AreEqual<Byte>(Ord('?'), LPattern[0], 'Не ASCII — «?»');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:167` (TextPattern_AsciiAndUtf16): `Assert.AreEqual(4, Integer(Length(LPattern)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:168` (TextPattern_AsciiAndUtf16): `Assert.AreEqual<Byte>($2F, LPattern[0]);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:170` (TextPattern_AsciiAndUtf16): `Assert.AreEqual(0, Integer(Length(MHTextPattern('', False))));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:171` (TextPattern_AsciiAndUtf16): `Assert.AreEqual(0, Integer(Length(MHTextPattern('', True))));`

### `BinaryLab.Source.MatchesAt` — проверок: 4

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:136` (Reader_StringsAndSignatures): `Assert.IsTrue(LReader.MatchesAt(0, TestBytes([$61, $62])));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:137` (Reader_StringsAndSignatures): `Assert.IsFalse(LReader.MatchesAt(0, TestBytes([$61, $63])));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:138` (Reader_StringsAndSignatures): `Assert.IsFalse(LReader.MatchesAt(19, TestBytes([0, 0, 0])), 'Сигнатура за концом');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:154` (Reader_EmptySource): `Assert.IsTrue(LReader.MatchesAt(0, []), 'Пустая сигнатура совпадает всегда');`

### `BinaryLab.Source.ReadAnsiZ` — проверок: 5

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:130` (Reader_StringsAndSignatures): `Assert.AreEqual('abc', LReader.ReadAnsiZ(0, 100));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:131` (Reader_StringsAndSignatures): `Assert.AreEqual('ab', LReader.ReadAnsiZ(0, 2), 'Ограничение длины');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:132` (Reader_StringsAndSignatures): `Assert.AreEqual('?d?', LReader.ReadAnsiZ(4, 100), 'Непечатаемые символы заменены');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:133` (Reader_StringsAndSignatures): `Assert.AreEqual('', LReader.ReadAnsiZ(1000, 10));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:153` (Reader_EmptySource): `Assert.AreEqual('', LReader.ReadAnsiZ(0, 10));`

### `BinaryLab.Source.ReadAt` — проверок: 4

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:179` (FileSource_ReadsAndKeepsFileUnchanged): `Assert.AreEqual(16, LSource.ReadAt(150000, LBuf[0], 16));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:182` (FileSource_ReadsAndKeepsFileUnchanged): `Assert.AreEqual(5, LSource.ReadAt(199995, LBuf[0], 16), 'Обрезается у конца');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:183` (FileSource_ReadsAndKeepsFileUnchanged): `Assert.AreEqual(0, LSource.ReadAt(200000, LBuf[0], 16));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:184` (FileSource_ReadsAndKeepsFileUnchanged): `Assert.AreEqual(0, LSource.ReadAt(-1, LBuf[0], 16));`

### `BinaryLab.Source.ReadBytes` — проверок: 3

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:113` (Reader_BoundsAreChecked): `Assert.AreEqual(0, Integer(Length(LReader.ReadBytes(6, 10))));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:114` (Reader_BoundsAreChecked): `Assert.AreEqual(2, Integer(Length(LReader.ReadBytes(4, 10))), 'Обрезается у конца');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:115` (Reader_BoundsAreChecked): `Assert.AreEqual(0, Integer(Length(LReader.ReadBytes(0, -5))));`

### `BinaryLab.Source.ReadUtf16` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:134` (Reader_StringsAndSignatures): `Assert.AreEqual('Привет', LReader.ReadUtf16(8, 6));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:135` (Reader_StringsAndSignatures): `Assert.AreEqual('Привет', LReader.ReadUtf16(8, 100), 'Обрезается у конца');`

### `BinaryLab.Source.TryRead` — проверок: 7

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:204` (Reader_TryReadCacheAndLargeReads): `Assert.IsTrue(LReader.TryRead(10, LBuffer[0], 16));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:206` (Reader_TryReadCacheAndLargeReads): `Assert.IsTrue(LReader.TryRead(65536 - 8, LBuffer[0], 16), 'Через границу окна кэша');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:209` (Reader_TryReadCacheAndLargeReads): `Assert.IsTrue(LReader.TryRead(50000, LBuffer[0], 100000), 'Крупное чтение');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:211` (Reader_TryReadCacheAndLargeReads): `Assert.IsFalse(LReader.TryRead(150000, LBuffer[0], 100000), 'Частично за концом');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:212` (Reader_TryReadCacheAndLargeReads): `Assert.IsTrue(LReader.TryRead(200000, LBuffer[0], 0), 'Нулевая длина у конца');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:213` (Reader_TryReadCacheAndLargeReads): `Assert.IsFalse(LReader.TryRead(200001, LBuffer[0], 0), 'Нулевая длина за концом');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:214` (Reader_TryReadCacheAndLargeReads): `Assert.IsFalse(LReader.TryRead(0, LBuffer[0], -1), 'Отрицательная длина');`

### `BinaryLab.Source.TryReadByte` — проверок: 1

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:152` (Reader_EmptySource): `Assert.IsFalse(LReader.TryReadByte(0, LByte));`

### `BinaryLab.Source.TryReadDWord` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:106` (Reader_BoundsAreChecked): `Assert.IsTrue(LReader.TryReadDWord(2, LDWord));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:109` (Reader_BoundsAreChecked): `Assert.IsFalse(LReader.TryReadDWord(3, LDWord), 'Частично за концом');`

### `BinaryLab.Source.TryReadQWord` — проверок: 1

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:110` (Reader_BoundsAreChecked): `Assert.IsFalse(LReader.TryReadQWord(0, LQWord), 'Больше файла');`

### `BinaryLab.Source.TryReadWord` — проверок: 3

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:104` (Reader_BoundsAreChecked): `Assert.IsTrue(LReader.TryReadWord(0, LWord));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:111` (Reader_BoundsAreChecked): `Assert.IsFalse(LReader.TryReadWord(-1, LWord), 'Отрицательное смещение');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:112` (Reader_BoundsAreChecked): `Assert.IsFalse(LReader.TryReadWord(High(Int64) - 1, LWord), 'Переполнение смещения');`

### `BinaryLab.Strings.MHClassifyString` — проверок: 5

- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:567` (Classify_Ip): `Assert.AreEqual(MHStringCategoryToName(ACategory), MHStringCategoryToName(MHClassifyString(AText)), AText);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:567` (Classify_Domain): `Assert.AreEqual(MHStringCategoryToName(ACategory), MHStringCategoryToName(MHClassifyString(AText)), AText);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:567` (Classify_Base64AndPlain): `Assert.AreEqual(MHStringCategoryToName(ACategory), MHStringCategoryToName(MHClassifyString(AText)), AText);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:567` (Classify_Mining): `Assert.AreEqual(MHStringCategoryToName(ACategory), MHStringCategoryToName(MHClassifyString(AText)), AText);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:567` (Classify_Path): `Assert.AreEqual(MHStringCategoryToName(ACategory), MHStringCategoryToName(MHClassifyString(AText)), AText);`

### `BinaryLab.Strings.MHScanStrings` — проверок: 21

- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:366` (Strings_EmptyAndNilSource): `Assert.AreEqual(0, Integer(Length(LInfo.Items)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:367` (Strings_EmptyAndNilSource): `Assert.AreEqual(0, LInfo.TotalFound);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:370` (Strings_EmptyAndNilSource): `Assert.AreEqual(0, Integer(Length(LInfo.Items)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:372` (Strings_EmptyAndNilSource): `Assert.AreEqual(0, Integer(Length(LInfo.Items)), 'Крошечный файл');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:426` (Strings_ChunkBoundary_FoundOnce): `Assert.AreEqual(3, Integer(Length(LInfo.Items)), 'Каждая строка найдена ровно один раз');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:427` (Strings_ChunkBoundary_FoundOnce): `Assert.AreEqual(ASCII_TEXT, LInfo.Items[0].Text);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:447` (Strings_MinLengthBoundary): `Assert.AreEqual(2, Integer(Length(LInfo.Items)), 'Длина min-1 не находится, min — находится');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:448` (Strings_MinLengthBoundary): `Assert.AreEqual('abcde', LInfo.Items[0].Text);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:453` (Strings_MinLengthBoundary): `Assert.AreEqual(4, Integer(Length(MHScanStrings(Src(LData), LOptions, nil).Items)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:467` (Strings_TruncatedToMaxLength): `Assert.AreEqual(3, Integer(Length(LInfo.Items)), 'Длинная строка — один элемент');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:468` (Strings_TruncatedToMaxLength): `Assert.AreEqual(StringOfChar('A', 16), LInfo.Items[0].Text, 'Текст обрезан до MaxStringLength');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Content.pas:489` (Strings_MaxStrings_KeepsCategorized): `Assert.AreEqual(5, Integer(Length(LInfo.Items)));`
- … и ещё 9

### `BinaryLab.Types.AccessText` — проверок: 3

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:315` (Sections_FlagsFindAndRva): `Assert.AreEqual('---', LSection.AccessText);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:320` (Sections_FlagsFindAndRva): `Assert.AreEqual('R-X', LSection.AccessText);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:322` (Sections_FlagsFindAndRva): `Assert.AreEqual('RWX', LSection.AccessText);`

### `BinaryLab.Types.ContainsCode` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:316` (Sections_FlagsFindAndRva): `Assert.IsFalse(LSection.IsReadable or LSection.IsWritable or LSection.IsExecutable or LSection.ContainsCode);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:318` (Sections_FlagsFindAndRva): `Assert.IsTrue(LSection.IsReadable and LSection.IsExecutable and LSection.ContainsCode);`

### `BinaryLab.Types.CountOf` — проверок: 3

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:562` (Report_HasAnomalyAndDiffCountOf): `Assert.AreEqual(0, LDiff.CountOf(MH_DIFF_AREA_IMPORT));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:568` (Report_HasAnomalyAndDiffCountOf): `Assert.AreEqual(2, LDiff.CountOf(MH_DIFF_AREA_IMPORT));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:569` (Report_HasAnomalyAndDiffCountOf): `Assert.AreEqual(1, LDiff.CountOf(MH_DIFF_AREA_STRING));`

### `BinaryLab.Types.Default` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:464` (Options_NormalizedLimitsBothSides): `Assert.AreEqual<Int64>(TMHBinaryLabOptions.Default.MaxScanBytes, TMHBinaryLabOptions.Default.Normalized.MaxScanBytes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:465` (Options_NormalizedLimitsBothSides): `Assert.AreEqual(TMHBinaryLabOptions.Default.MaxStrings, TMHBinaryLabOptions.Default.Normalized.MaxStrings);`

### `BinaryLab.Types.FindSection` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:336` (Sections_FlagsFindAndRva): `Assert.IsTrue(LPe.FindSection('.TEXT', LSection), 'Без учёта регистра');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:337` (Sections_FlagsFindAndRva): `Assert.IsFalse(LPe.FindSection('.rsrc', LSection));`

### `BinaryLab.Types.HasAnomaly` — проверок: 3

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:554` (Report_HasAnomalyAndDiffCountOf): `Assert.IsFalse(LReport.HasAnomaly('X'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:556` (Report_HasAnomalyAndDiffCountOf): `Assert.IsTrue(LReport.HasAnomaly('X'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:557` (Report_HasAnomalyAndDiffCountOf): `Assert.IsFalse(LReport.HasAnomaly('x'), 'Коды сравниваются точно');`

### `BinaryLab.Types.ImportsFunction` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:158` (Pe64_HeadersSectionsImportsExports): `Assert.IsTrue(LPe.ImportsFunction('closehandle'), 'Без учёта регистра');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Pe.pas:159` (Pe64_HeadersSectionsImportsExports): `Assert.IsFalse(LPe.ImportsFunction('WriteFile'));`

### `BinaryLab.Types.IsExecutable` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:316` (Sections_FlagsFindAndRva): `Assert.IsFalse(LSection.IsReadable or LSection.IsWritable or LSection.IsExecutable or LSection.ContainsCode);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:318` (Sections_FlagsFindAndRva): `Assert.IsTrue(LSection.IsReadable and LSection.IsExecutable and LSection.ContainsCode);`

### `BinaryLab.Types.IsReadable` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:316` (Sections_FlagsFindAndRva): `Assert.IsFalse(LSection.IsReadable or LSection.IsWritable or LSection.IsExecutable or LSection.ContainsCode);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:318` (Sections_FlagsFindAndRva): `Assert.IsTrue(LSection.IsReadable and LSection.IsExecutable and LSection.ContainsCode);`

### `BinaryLab.Types.IsWritable` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:316` (Sections_FlagsFindAndRva): `Assert.IsFalse(LSection.IsReadable or LSection.IsWritable or LSection.IsExecutable or LSection.ContainsCode);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:319` (Sections_FlagsFindAndRva): `Assert.IsFalse(LSection.IsWritable);`

### `BinaryLab.Types.MHAnomalySeverityTitle` — проверок: 1

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:250` (EnumTitlesAndNames_AllValuesDistinct): `Assert.IsTrue(MHAnomalySeverityTitle(LSeverity) <> '');`

### `BinaryLab.Types.MHAnomalySeverityToName` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:252` (EnumTitlesAndNames_AllValuesDistinct): `Assert.IsFalse(LNames.ContainsKey(LName), LName);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:275` (EnumTitlesAndNames_AllValuesDistinct): `Assert.AreEqual('high', MHAnomalySeverityToName(asHigh));`

### `BinaryLab.Types.MHBinaryKindTitle` — проверок: 1

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:234` (EnumTitlesAndNames_AllValuesDistinct): `Assert.IsTrue(MHBinaryKindTitle(LKind) <> '');`

### `BinaryLab.Types.MHBinaryKindToName` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:236` (EnumTitlesAndNames_AllValuesDistinct): `Assert.IsFalse(LNames.ContainsKey(LName), 'Имена вида различаются: ' + LName);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:273` (EnumTitlesAndNames_AllValuesDistinct): `Assert.AreEqual('pe', MHBinaryKindToName(bkPE));`

### `BinaryLab.Types.MHDiffChangeTitle` — проверок: 1

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:265` (EnumTitlesAndNames_AllValuesDistinct): `Assert.IsTrue(MHDiffChangeTitle(LChange) <> '');`

### `BinaryLab.Types.MHDiffChangeToName` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:267` (EnumTitlesAndNames_AllValuesDistinct): `Assert.IsFalse(LNames.ContainsKey(LName), LName);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:276` (EnumTitlesAndNames_AllValuesDistinct): `Assert.AreEqual('added', MHDiffChangeToName(dcAdded));`

### `BinaryLab.Types.MHEntropyClassOf` — проверок: 5

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:522` (Entropy_ShannonBounds): `Assert.AreEqual(Ord(ecEmpty), Ord(MHEntropyClassOf(0.2)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:523` (Entropy_ShannonBounds): `Assert.AreEqual(Ord(ecText), Ord(MHEntropyClassOf(4.5)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:524` (Entropy_ShannonBounds): `Assert.AreEqual(Ord(ecCode), Ord(MHEntropyClassOf(6.0)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:525` (Entropy_ShannonBounds): `Assert.AreEqual(Ord(ecCompressed), Ord(MHEntropyClassOf(7.2)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:526` (Entropy_ShannonBounds): `Assert.AreEqual(Ord(ecEncrypted), Ord(MHEntropyClassOf(7.95)));`

### `BinaryLab.Types.MHEntropyClassTitle` — проверок: 1

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:259` (EnumTitlesAndNames_AllValuesDistinct): `Assert.IsFalse(LNames.ContainsKey(LName), LName);`

### `BinaryLab.Types.MHHexOffset` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:527` (Entropy_ShannonBounds): `Assert.AreEqual('0x0001F400', MHHexOffset($1F400));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:528` (Entropy_ShannonBounds): `Assert.AreEqual('—', MHHexOffset(-1));`

### `BinaryLab.Types.MHPeKindTitle` — проверок: 4

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:289` (MachineSubsystemAndPeKindNames): `Assert.AreEqual('', MHPeKindTitle(pkNone));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:290` (MachineSubsystemAndPeKindNames): `Assert.IsTrue(MHPeKindTitle(pkDll).Contains('DLL'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:291` (MachineSubsystemAndPeKindNames): `Assert.IsTrue(MHPeKindTitle(pkDriver).Contains('SYS'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:292` (MachineSubsystemAndPeKindNames): `Assert.IsTrue(MHPeKindTitle(pkExe).Contains('EXE'));`

### `BinaryLab.Types.MHShannonEntropy` — проверок: 4

- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:514` (Entropy_ShannonBounds): `Assert.AreEqual(0.0, MHShannonEntropy(LCounts, 0), 'Нет данных');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:516` (Entropy_ShannonBounds): `Assert.AreEqual(0.0, MHShannonEntropy(LCounts, 1000), 1e-9, 'Один байт');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:518` (Entropy_ShannonBounds): `Assert.AreEqual(1.0, MHShannonEntropy(LCounts, 2000), 1e-9, 'Два равновероятных');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:521` (Entropy_ShannonBounds): `Assert.AreEqual(8.0, MHShannonEntropy(LCounts, 2560), 1e-9, 'Равномерное распределение');`

### `BinaryLab.Types.MHStringCategoryTitle` — проверок: 1

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:242` (EnumTitlesAndNames_AllValuesDistinct): `Assert.IsTrue(MHStringCategoryTitle(LCategory) <> '');`

### `BinaryLab.Types.MHStringCategoryToName` — проверок: 2

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:244` (EnumTitlesAndNames_AllValuesDistinct): `Assert.IsFalse(LNames.ContainsKey(LName), LName);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:274` (EnumTitlesAndNames_AllValuesDistinct): `Assert.AreEqual('suspicious_api', MHStringCategoryToName(scSuspiciousApi));`

### `BinaryLab.Types.Normalized` — проверок: 9

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:436` (Options_NormalizedLimitsBothSides): `Assert.AreEqual<Int64>(Int64(4) * 1024 * 1024 * 1024, LOptions.MaxScanBytes, 'Верхний предел сканирования — 4 ГБ');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:437` (Options_NormalizedLimitsBothSides): `Assert.AreEqual(16 * 1024 * 1024, LOptions.EntropyBlockSize);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:455` (Options_NormalizedLimitsBothSides): `Assert.AreEqual<Int64>(4096, LOptions.MaxScanBytes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:456` (Options_NormalizedLimitsBothSides): `Assert.AreEqual(64, LOptions.EntropyBlockSize, 'Явный размер блока — не меньше 64');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:464` (Options_NormalizedLimitsBothSides): `Assert.AreEqual<Int64>(TMHBinaryLabOptions.Default.MaxScanBytes, TMHBinaryLabOptions.Default.Normalized.MaxScanBytes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:465` (Options_NormalizedLimitsBothSides): `Assert.AreEqual(TMHBinaryLabOptions.Default.MaxStrings, TMHBinaryLabOptions.Default.Normalized.MaxStrings);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:543` (Options_Normalized): `Assert.AreEqual<Int64>(4096, LOptions.MaxScanBytes);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:544` (Options_Normalized): `Assert.AreEqual(3, LOptions.MinStringLength);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Basics.pas:549` (Options_Normalized): `Assert.AreEqual(0, LOptions.Normalized.EntropyBlockSize, '0 — подбирается автоматически');`

### `BinaryLab.Types.SectionOfRva` — проверок: 7

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:339` (Sections_FlagsFindAndRva): `Assert.IsTrue(LPe.SectionOfRva($1000, LSection) and (LSection.Name = '.text'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:340` (Sections_FlagsFindAndRva): `Assert.IsTrue(LPe.SectionOfRva($13FF, LSection), 'Размер — максимум из размеров в памяти и в файле');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:341` (Sections_FlagsFindAndRva): `Assert.IsFalse(LPe.SectionOfRva($1400, LSection), 'Сразу за секцией');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:342` (Sections_FlagsFindAndRva): `Assert.IsTrue(LPe.SectionOfRva($2FFF, LSection) and (LSection.Name = '.bss'));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:343` (Sections_FlagsFindAndRva): `Assert.IsFalse(LPe.SectionOfRva($500, LSection), 'Заголовки — вне секций');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:344` (Sections_FlagsFindAndRva): `Assert.IsFalse(LPe.SectionOfRva($FFFFFFFF, LSection), 'Предельный адрес');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:345` (Sections_FlagsFindAndRva): `Assert.IsFalse(Default(TMHPeInfo).SectionOfRva(0, LSection), 'Нет секций');`

### `BinaryLab.Verdicts.Clear` — проверок: 1

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:853` (Store_MatchByPathAndHash): `Assert.AreEqual(0, LStore.Count);`

### `BinaryLab.Verdicts.Count` — проверок: 5

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:835` (Store_MatchByPathAndHash): `Assert.AreEqual(1, LStore.Count);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:845` (Store_MatchByPathAndHash): `Assert.AreEqual(1, LStore.Count);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:851` (Store_MatchByPathAndHash): `Assert.AreEqual(1, LStore.Count);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:853` (Store_MatchByPathAndHash): `Assert.AreEqual(0, LStore.Count);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:869` (Store_EvictsOldest): `Assert.AreEqual(TMHBinaryVerdictStore.MaxVerdicts, LStore.Count);`

### `BinaryLab.Verdicts.MHVerdictFromReport` — проверок: 7

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:793` (FromReport_WeightsSignalsAndCap): `Assert.AreEqual(1, Integer(Length(LVerdict.Evidence)), 'Только средние и высокие');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:794` (FromReport_WeightsSignalsAndCap): `Assert.AreEqual('BINARYLAB:' + BL_RWX_SECTION, LVerdict.Evidence[0].Code);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:806` (FromReport_WeightsSignalsAndCap): `Assert.IsTrue(LVerdict.MiningSignal);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:807` (FromReport_WeightsSignalsAndCap): `Assert.IsTrue(LVerdict.ThreatSignal);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:817` (FromReport_WeightsSignalsAndCap): `Assert.AreEqual(6, LVerdict.Evidence[0].Weight);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:820` (FromReport_WeightsSignalsAndCap): `Assert.AreEqual(0, Integer(Length(LVerdict.Evidence)));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:821` (FromReport_WeightsSignalsAndCap): `Assert.AreEqual(70, LVerdict.Score);`

### `BinaryLab.Verdicts.Put` — проверок: 8

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:835` (Store_MatchByPathAndHash): `Assert.AreEqual(1, LStore.Count);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:836` (Store_MatchByPathAndHash): `Assert.IsTrue(LStore.TryGet('c:\tools\MINER.EXE', 'aa11', LFound), 'Без учёта регистра');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:845` (Store_MatchByPathAndHash): `Assert.AreEqual(1, LStore.Count);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:846` (Store_MatchByPathAndHash): `Assert.IsTrue(LStore.TryGet('C:\Tools\Miner.exe', 'aa11', LFound));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:851` (Store_MatchByPathAndHash): `Assert.AreEqual(1, LStore.Count);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:853` (Store_MatchByPathAndHash): `Assert.AreEqual(0, LStore.Count);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:869` (Store_EvictsOldest): `Assert.AreEqual(TMHBinaryVerdictStore.MaxVerdicts, LStore.Count);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:870` (Store_EvictsOldest): `Assert.IsFalse(LStore.TryGet('C:\Files\f1.exe', '', LFound), 'Самый старый вытеснен');`

### `BinaryLab.Verdicts.TryGet` — проверок: 8

- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:836` (Store_MatchByPathAndHash): `Assert.IsTrue(LStore.TryGet('c:\tools\MINER.EXE', 'aa11', LFound), 'Без учёта регистра');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:838` (Store_MatchByPathAndHash): `Assert.IsTrue(LStore.TryGet('C:\Tools\Miner.exe', '', LFound), 'Хеш процесса неизвестен — по пути');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:839` (Store_MatchByPathAndHash): `Assert.IsFalse(LStore.TryGet('C:\Tools\Miner.exe', 'bb22', LFound), 'Файл изменился');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:840` (Store_MatchByPathAndHash): `Assert.IsFalse(LStore.TryGet('C:\Tools\Other.exe', 'aa11', LFound));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:841` (Store_MatchByPathAndHash): `Assert.IsFalse(LStore.TryGet('', '', LFound));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:846` (Store_MatchByPathAndHash): `Assert.IsTrue(LStore.TryGet('C:\Tools\Miner.exe', 'aa11', LFound));`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:870` (Store_EvictsOldest): `Assert.IsFalse(LStore.TryGet('C:\Files\f1.exe', '', LFound), 'Самый старый вытеснен');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Integration.pas:871` (Store_EvictsOldest): `Assert.IsTrue(LStore.TryGet(Format('C:\Files\f%d.exe', [TMHBinaryVerdictStore.MaxVerdicts + 5]), '', LFound));`

### `App.BinaryLab.Controls.AddHighlight` — проверок: 5

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:564` (Highlights_LookupAndHint): `Assert.AreEqual(2, FView.HighlightCount, 'Неверные диапазоны не добавляются');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:565` (Highlights_LookupAndHint): `Assert.IsTrue(FView.HighlightAt(100, LCaption));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:585` (Highlights_LookupAndHint): `Assert.AreEqual(0, FView.HighlightCount);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:766` (BeforeHandle_Safe): `Assert.IsTrue(LView.FindNext(TBytes.Create(0)));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:767` (BeforeHandle_Safe): `Assert.IsTrue(LView.PointOfOffset(LView.TopOffset, P));`

### `App.BinaryLab.Controls.BarFraction` — проверок: 9

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:476` (Histogram_BarFractionEdges): `Assert.AreEqual(0.0, LHistogram.BarFraction(0), 1e-12);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:477` (Histogram_BarFractionEdges): `Assert.AreEqual(0.0, LHistogram.BarFraction(255), 1e-12);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:479` (Histogram_BarFractionEdges): `Assert.AreEqual(0.0, LHistogram.BarFraction(7), 1e-12);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:484` (Histogram_BarFractionEdges): `Assert.AreEqual(1.0, LHistogram.BarFraction(0), 1e-12, 'Наибольший столбец — вся высота');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:485` (Histogram_BarFractionEdges): `Assert.AreEqual(0.0, LHistogram.BarFraction(2), 1e-12, 'Нулевой счётчик — нет столбца');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:487` (Histogram_BarFractionEdges): `Assert.AreEqual(Ln(11) / Ln(1001), LHistogram.BarFraction(1), 1e-9, 'Логарифмическая шкала');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:489` (Histogram_BarFractionEdges): `Assert.AreEqual(0.01, LHistogram.BarFraction(1), 1e-9, 'Линейная шкала');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:492` (Histogram_BarFractionEdges): `Assert.AreEqual(1.0, LHistogram.BarFraction(0), 1e-12);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:493` (Histogram_BarFractionEdges): `Assert.AreEqual(0.0, LHistogram.BarFraction(1), 1e-12);`

### `App.BinaryLab.Controls.BarRect` — проверок: 1

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1137` (Paint_NormalEmptyTiny): `Assert.IsTrue(FHistogram.BarRect(10).IsEmpty);`

### `App.BinaryLab.Controls.BlockAtPoint` — проверок: 5

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:840` (Cells_ConsistentWithBlockAtPoint): `Assert.IsTrue(FMap.BlockAtPoint(Center(R).X, Center(R).Y, LIndex));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:842` (Cells_ConsistentWithBlockAtPoint): `Assert.IsTrue(FMap.BlockAtPoint(R.Left, R.Top, LIndex));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:850` (Cells_ConsistentWithBlockAtPoint): `Assert.IsFalse(FMap.BlockAtPoint(0, 0, LIndex), 'Поле вокруг карты');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:851` (Cells_ConsistentWithBlockAtPoint): `Assert.IsFalse(FMap.BlockAtPoint(FMap.Width - 1, FMap.Height - 1, LIndex), 'Легенда');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:871` (ManyBlocks_Aggregated): `Assert.IsTrue(FMap.BlockAtPoint(Center(R).X, Center(R).Y, LIndex));`

### `App.BinaryLab.Controls.BlockCount` — проверок: 4

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:527` (EntropyMap_BlockCountEmptyAndData): `Assert.AreEqual(0, LMap.BlockCount, 'До данных');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:529` (EntropyMap_BlockCountEmptyAndData): `Assert.AreEqual(0, LMap.BlockCount, 'Пустые данные');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:538` (EntropyMap_BlockCountEmptyAndData): `Assert.AreEqual(3, LMap.BlockCount);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:541` (EntropyMap_BlockCountEmptyAndData): `Assert.AreEqual(0, LMap.BlockCount, 'Данные сброшены');`

### `App.BinaryLab.Controls.BlocksPerCell` — проверок: 2

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:863` (ManyBlocks_Aggregated): `Assert.IsTrue(LPer > 1, 'Блоков больше, чем клеток — сведение');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:864` (ManyBlocks_Aggregated): `Assert.IsTrue(Int64(FMap.CellCount) * LPer >= N);`

### `App.BinaryLab.Controls.ByteAtPoint` — проверок: 6

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1069` (ByteAtPoint_UnevenWidth_EveryByteReachable): `Assert.IsTrue(FHistogram.ByteAtPoint(Center(R).X, Center(R).Y, B));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1046` (ByteAtPoint_MatchesBars): `Assert.IsTrue(FHistogram.ByteAtPoint(R.Left, Center(R).Y, B));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1048` (ByteAtPoint_MatchesBars): `Assert.IsTrue(FHistogram.ByteAtPoint(R.Right - 1, Center(R).Y, B));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1052` (ByteAtPoint_MatchesBars): `Assert.IsFalse(FHistogram.ByteAtPoint(0, 50, B), 'Поле слева');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1053` (ByteAtPoint_MatchesBars): `Assert.IsFalse(FHistogram.ByteAtPoint(FHistogram.Width - 1, 50, B), 'Поле справа');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1054` (ByteAtPoint_MatchesBars): `Assert.IsFalse(FHistogram.ByteAtPoint(100, -1, B));`

### `App.BinaryLab.Controls.CellCount` — проверок: 2

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:864` (ManyBlocks_Aggregated): `Assert.IsTrue(Int64(FMap.CellCount) * LPer >= N);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:865` (ManyBlocks_Aggregated): `Assert.IsTrue(Int64(FMap.CellCount - 1) * LPer < N);`

### `App.BinaryLab.Controls.CellRect` — проверок: 11

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:838` (Cells_ConsistentWithBlockAtPoint): `Assert.IsFalse(R.IsEmpty, Format('Клетка %d', [I]));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:839` (Cells_ConsistentWithBlockAtPoint): `Assert.IsTrue(FMap.ClientRect.Contains(R.TopLeft));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:845` (Cells_ConsistentWithBlockAtPoint): `Assert.IsFalse(FMap.CellRect(0).IntersectsWith(FMap.CellRect(1)));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:846` (Cells_ConsistentWithBlockAtPoint): `Assert.IsTrue(FMap.CellRect(1).Left > FMap.CellRect(0).Left, 'Слева направо');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:847` (Cells_ConsistentWithBlockAtPoint): `Assert.IsTrue(FMap.CellRect(99).Top > FMap.CellRect(0).Top, 'Сверху вниз');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:848` (Cells_ConsistentWithBlockAtPoint): `Assert.IsTrue(FMap.CellRect(100).IsEmpty);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:849` (Cells_ConsistentWithBlockAtPoint): `Assert.IsTrue(FMap.CellRect(-1).IsEmpty);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:869` (ManyBlocks_Aggregated): `Assert.IsFalse(R.IsEmpty);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:870` (ManyBlocks_Aggregated): `Assert.IsTrue(R.Width >= 1);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:874` (ManyBlocks_Aggregated): `Assert.IsTrue(FMap.CellRect(N - 1).Bottom <= FMap.Height, 'Все клетки внутри элемента');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:875` (ManyBlocks_Aggregated): `Assert.Contains(FMap.HintTextAt(Center(FMap.CellRect(0)).X, Center(FMap.CellRect(0)).Y),`

### `App.BinaryLab.Controls.ClearHighlights` — проверок: 2

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:581` (Highlights_LookupAndHint): `Assert.IsFalse(FView.HighlightAt(112, LCaption));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:585` (Highlights_LookupAndHint): `Assert.AreEqual(0, FView.HighlightCount);`

### `App.BinaryLab.Controls.ContentWidth` — проверок: 1

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:476` (OffsetAtPoint_OutsideColumns_False): `Assert.IsFalse(FView.OffsetAtPoint(FView.ContentWidth + 50, 2, LOffset));`

### `App.BinaryLab.Controls.EntropyColor` — проверок: 7

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:923` (EntropyColor_ScaleMonotonicAndDistinctEnds): `Assert.IsTrue(LRed >= LPrev, Format('Красный не убывает: %.2f', [E]));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:929` (EntropyColor_ScaleMonotonicAndDistinctEnds): `Assert.AreNotEqual(Integer(C0), Integer(C8));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:930` (EntropyColor_ScaleMonotonicAndDistinctEnds): `Assert.IsTrue(GetBValue(C0) > GetRValue(C0), '0 — синий');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:932` (EntropyColor_ScaleMonotonicAndDistinctEnds): `Assert.IsTrue(GetGValue(TMHEntropyMap.EntropyColor(4.5)) > GetRValue(TMHEntropyMap.EntropyColor(4.5)), '4.5 — зелёный');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:933` (EntropyColor_ScaleMonotonicAndDistinctEnds): `Assert.AreEqual(Integer(C0), Integer(TMHEntropyMap.EntropyColor(-3)));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:934` (EntropyColor_ScaleMonotonicAndDistinctEnds): `Assert.AreEqual(Integer(C8), Integer(TMHEntropyMap.EntropyColor(12)));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:935` (EntropyColor_ScaleMonotonicAndDistinctEnds): `Assert.AreEqual(Integer(C0), Integer(TMHEntropyMap.EntropyColor(NaN)));`

### `App.BinaryLab.Controls.FindNext` — проверок: 9

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:599` (FindNext_FindsWrapsAndKeepsPositionWhenMissing): `Assert.IsTrue(FView.FindNext(TEncoding.ASCII.GetBytes('MZ')));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:602` (FindNext_FindsWrapsAndKeepsPositionWhenMissing): `Assert.IsTrue(FView.FindNext(TEncoding.ASCII.GetBytes('MZ')));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:605` (FindNext_FindsWrapsAndKeepsPositionWhenMissing): `Assert.IsTrue(FView.FindNext(TEncoding.ASCII.GetBytes('MZ')), 'Переход в начало');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:608` (FindNext_FindsWrapsAndKeepsPositionWhenMissing): `Assert.IsFalse(FView.FindNext(TEncoding.ASCII.GetBytes('QQQ')));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:611` (FindNext_FindsWrapsAndKeepsPositionWhenMissing): `Assert.IsFalse(FView.FindNext(nil), 'Пустой шаблон');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:616` (FindNext_FindsWrapsAndKeepsPositionWhenMissing): `Assert.IsTrue(FView.FindNext(TEncoding.ASCII.GetBytes('MZ')));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:626` (FindNext_IgnoreCase): `Assert.IsFalse(FView.FindNext(TEncoding.ASCII.GetBytes('this program')));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:628` (FindNext_IgnoreCase): `Assert.IsTrue(FView.FindNext(TEncoding.ASCII.GetBytes('this program'), True));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:662` (NilSource_Safe): `Assert.IsFalse(FView.FindNext(TEncoding.ASCII.GetBytes('MZ')));`

### `App.BinaryLab.Controls.GotoOffset` — проверок: 11

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:324` (Goto_VisibleOffset_DoesNotScroll): `Assert.AreEqual<Int64>(LTop, FView.TopOffset, 'Видимое смещение — без прокрутки');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:325` (Goto_VisibleOffset_DoesNotScroll): `Assert.AreEqual<Int64>(LTop + 37, FView.SelStart);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:296` (Goto_ScrollsIntoViewAndSelects): `Assert.AreEqual<Int64>(50000, FView.SelStart);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:297` (Goto_ScrollsIntoViewAndSelects): `Assert.AreEqual<Int64>(4, FView.SelLength);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:307` (Goto_ScrollsIntoViewAndSelects): `Assert.AreEqual<Int64>(100 * 1024 - 2, FView.SelStart);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:308` (Goto_ScrollsIntoViewAndSelects): `Assert.AreEqual<Int64>(2, FView.SelLength);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:310` (Goto_ScrollsIntoViewAndSelects): `Assert.AreEqual<Int64>(100 * 1024 - 1, FView.SelStart);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:312` (Goto_ScrollsIntoViewAndSelects): `Assert.AreEqual<Int64>(0, FView.SelStart);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:313` (Goto_ScrollsIntoViewAndSelects): `Assert.AreEqual<Int64>(0, FView.TopOffset);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:766` (BeforeHandle_Safe): `Assert.IsTrue(LView.FindNext(TBytes.Create(0)));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:767` (BeforeHandle_Safe): `Assert.IsTrue(LView.PointOfOffset(LView.TopOffset, P));`

### `App.BinaryLab.Controls.HighlightAt` — проверок: 6

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:565` (Highlights_LookupAndHint): `Assert.IsTrue(FView.HighlightAt(100, LCaption));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:567` (Highlights_LookupAndHint): `Assert.IsTrue(FView.HighlightAt(112, LCaption));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:569` (Highlights_LookupAndHint): `Assert.IsTrue(FView.HighlightAt(119, LCaption));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:571` (Highlights_LookupAndHint): `Assert.IsFalse(FView.HighlightAt(120, LCaption));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:572` (Highlights_LookupAndHint): `Assert.IsFalse(FView.HighlightAt(99, LCaption));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:581` (Highlights_LookupAndHint): `Assert.IsFalse(FView.HighlightAt(112, LCaption));`

### `App.BinaryLab.Controls.HighlightCount` — проверок: 2

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:564` (Highlights_LookupAndHint): `Assert.AreEqual(2, FView.HighlightCount, 'Неверные диапазоны не добавляются');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:585` (Highlights_LookupAndHint): `Assert.AreEqual(0, FView.HighlightCount);`

### `App.BinaryLab.Controls.HintTextAt` — проверок: 12

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:957` (Hint_RangeEntropyAndBand): `Assert.Contains(LHint, MHHexOffset(10 * 4096));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:958` (Hint_RangeEntropyAndBand): `Assert.Contains(LHint, MHHexOffset(11 * 4096));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:964` (Hint_RangeEntropyAndBand): `Assert.Contains(LHint, FormatFloat('0.00', 8));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:965` (Hint_RangeEntropyAndBand): `Assert.Contains(LHint, LBands[1].Caption);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:967` (Hint_RangeEntropyAndBand): `Assert.IsFalse(FMap.HintTextAt(P.X, P.Y).Contains('.text'), 'Вне раздела');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:968` (Hint_RangeEntropyAndBand): `Assert.AreEqual('', FMap.HintTextAt(0, 0));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:971` (Hint_RangeEntropyAndBand): `Assert.Contains(FMap.HintTextAt(10, 10), '.text');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1110` (Hint_ByteCountPercent): `Assert.Contains(LHint, '0x41');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1111` (Hint_ByteCountPercent): `Assert.Contains(LHint, '(''A'')');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1116` (Hint_ByteCountPercent): `Assert.Contains(LHint, '0x00');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1117` (Hint_ByteCountPercent): `Assert.IsFalse(LHint.Contains(''''), 'Непечатный байт — без символа');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1118` (Hint_ByteCountPercent): `Assert.AreEqual('', FHistogram.HintTextAt(0, 0));`

### `App.BinaryLab.Controls.InvalidateData` — проверок: 2

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:551` (BinaryLab_ButtonsDialogsAndDoubleClicks): `Assert.AreEqual(Integer($00FF00), Integer(MHBlendColor($00FF00, $000000, 1.0)));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:552` (BinaryLab_ButtonsDialogsAndDoubleClicks): `Assert.AreEqual(Integer($000000), Integer(MHBlendColor($00FF00, $000000, 0.0)));`

### `App.BinaryLab.Controls.MHBlendColor` — проверок: 4

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:551` (BinaryLab_ButtonsDialogsAndDoubleClicks): `Assert.AreEqual(Integer($00FF00), Integer(MHBlendColor($00FF00, $000000, 1.0)));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:552` (BinaryLab_ButtonsDialogsAndDoubleClicks): `Assert.AreEqual(Integer($000000), Integer(MHBlendColor($00FF00, $000000, 0.0)));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:555` (BinaryLab_ButtonsDialogsAndDoubleClicks): `Assert.IsTrue((LCaret >= $7E) and (LCaret <= $81), IntToStr(LCaret));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:556` (BinaryLab_ButtonsDialogsAndDoubleClicks): `Assert.AreEqual(0, Integer(MHBlendColor($00FF00, $000000, 0.5)) and $FF00FF);`

### `App.BinaryLab.Controls.OffsetAtPoint` — проверок: 7

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:474` (OffsetAtPoint_OutsideColumns_False): `Assert.IsFalse(FView.OffsetAtPoint(2, 2, LOffset));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:475` (OffsetAtPoint_OutsideColumns_False): `Assert.IsFalse(FView.OffsetAtPoint(-1, 2, LOffset));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:476` (OffsetAtPoint_OutsideColumns_False): `Assert.IsFalse(FView.OffsetAtPoint(FView.ContentWidth + 50, 2, LOffset));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:479` (OffsetAtPoint_OutsideColumns_False): `Assert.IsTrue(FView.OffsetAtPoint(P.X, P.Y, LOffset));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:482` (OffsetAtPoint_OutsideColumns_False): `Assert.IsFalse(FView.OffsetAtPoint(P.X, P.Y + 20 * FView.Height div FView.VisibleRows, LOffset),`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:663` (NilSource_Safe): `Assert.IsFalse(FView.OffsetAtPoint(200, 10, LOffset));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:768` (BeforeHandle_Safe): `Assert.IsTrue(LView.OffsetAtPoint(P.X, P.Y, LOffset));`

### `App.BinaryLab.Controls.OffsetAtX` — проверок: 11

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1192` (OffsetAtX_Endpoints): `Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(0));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1193` (OffsetAtX_Endpoints): `Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(1));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1194` (OffsetAtX_Endpoints): `Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(-50));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1195` (OffsetAtX_Endpoints): `Assert.AreEqual<Int64>(99999, FStrip.OffsetAtX(FStrip.Width - 2));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1196` (OffsetAtX_Endpoints): `Assert.AreEqual<Int64>(99999, FStrip.OffsetAtX(FStrip.Width + 100));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1198` (OffsetAtX_Endpoints): `Assert.IsTrue(Abs(LOffset - 50000) < 1000, 'Середина полосы — середина файла');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1203` (OffsetAtX_Endpoints): `Assert.IsTrue(LOffset >= LPrev, 'Смещение растёт слева направо');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1206` (OffsetAtX_Endpoints): `Assert.Contains(FStrip.HintTextAt(FStrip.Width div 2, 10), '0x0000');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1253` (ZeroFileSize_Safe): `Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(100));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1261` (ZeroFileSize_Safe): `Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(0));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1265` (ZeroFileSize_Safe): `Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(0), 'Нулевая ширина');`

### `App.BinaryLab.Controls.OffsetDigits` — проверок: 5

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:505` (HexView_OffsetDigitsAtFourGigabytes): `Assert.AreEqual(8, LHex.OffsetDigits, 'Без источника');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:507` (HexView_OffsetDigitsAtFourGigabytes): `Assert.AreEqual(8, LHex.OffsetDigits, 'Пустой файл');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:509` (HexView_OffsetDigitsAtFourGigabytes): `Assert.AreEqual(8, LHex.OffsetDigits, 'Ровно 4 ГБ: последнее смещение FFFFFFFF');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:511` (HexView_OffsetDigitsAtFourGigabytes): `Assert.AreEqual(12, LHex.OffsetDigits, 'На байт больше 4 ГБ');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:513` (HexView_OffsetDigitsAtFourGigabytes): `Assert.AreEqual(8, LHex.OffsetDigits, 'Источник снят');`

### `App.BinaryLab.Controls.PointOfOffset` — проверок: 5

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:457` (OffsetAtPoint_InverseOfPointOfOffset): `Assert.IsTrue(FView.PointOfOffset(LOffset, P, LAscii), Format('Точка для %d', [LOffset]));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:462` (OffsetAtPoint_InverseOfPointOfOffset): `Assert.IsFalse(FView.PointOfOffset(LTop - 1, P));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:463` (OffsetAtPoint_InverseOfPointOfOffset): `Assert.IsFalse(FView.PointOfOffset(LTop + Int64(FView.VisibleRows) * 16, P));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:464` (OffsetAtPoint_InverseOfPointOfOffset): `Assert.IsFalse(FView.PointOfOffset(-1, P));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:664` (NilSource_Safe): `Assert.IsFalse(FView.PointOfOffset(0, P));`

### `App.BinaryLab.Controls.RangeAtX` — проверок: 4

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1217` (Click_OnRangeGivesStart_ElsewhereComputed): `Assert.IsTrue(X < FStrip.Width, 'Диапазон нарисован');`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1219` (Click_OnRangeGivesStart_ElsewhereComputed): `Assert.AreEqual(1, FClicks);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1225` (Click_OnRangeGivesStart_ElsewhereComputed): `Assert.IsFalse(FStrip.RangeAtX(300, LIndex));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1254` (ZeroFileSize_Safe): `Assert.IsFalse(FStrip.RangeAtX(100, LIndex));`

### `App.BinaryLab.Controls.RowCount` — проверок: 1

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:640` (NilSource_Safe): `Assert.AreEqual<Int64>(0, FView.RowCount);`

### `App.BinaryLab.Controls.ScrollRows` — проверок: 3

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:547` (BinaryLab_ButtonsDialogsAndDoubleClicks): `Assert.AreEqual<Int64>(3 * LPage.HexView.BytesPerRow, LPage.HexView.TopOffset);`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:549` (BinaryLab_ButtonsDialogsAndDoubleClicks): `Assert.AreEqual<Int64>(0, LPage.HexView.TopOffset, 'Не выше начала');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:551` (BinaryLab_ButtonsDialogsAndDoubleClicks): `Assert.AreEqual(Integer($00FF00), Integer(MHBlendColor($00FF00, $000000, 1.0)));`

### `App.BinaryLab.Controls.SetBands` — проверок: 2

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:957` (Hint_RangeEntropyAndBand): `Assert.Contains(LHint, MHHexOffset(10 * 4096));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:958` (Hint_RangeEntropyAndBand): `Assert.Contains(LHint, MHHexOffset(11 * 4096));`

### `App.BinaryLab.Controls.SetData` — проверок: 7

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:985` (Paint_CellColourAndEmptyAndTiny): `Assert.AreEqual(Integer(ColorToRGB(TMHEntropyMap.EntropyColor(0))), Integer(LBitmap.Canvas.Pixels[P.X, P.Y]));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:987` (Paint_CellColourAndEmptyAndTiny): `Assert.AreEqual(Integer(ColorToRGB(TMHEntropyMap.EntropyColor(8))), Integer(LBitmap.Canvas.Pixels[P.X, P.Y]));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:992` (Paint_CellColourAndEmptyAndTiny): `Assert.AreEqual(0, FMap.CellCount);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:993` (Paint_CellColourAndEmptyAndTiny): `Assert.IsTrue(FMap.CellRect(0).IsEmpty);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1000` (Paint_CellColourAndEmptyAndTiny): `Assert.AreEqual(1, FMap.CellCount);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1005` (Paint_CellColourAndEmptyAndTiny): `Assert.AreEqual(0, FMap.CellCount);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1006` (Paint_CellColourAndEmptyAndTiny): `Assert.IsFalse(FMap.BlockAtPoint(0, 0, LIndex));`

### `App.BinaryLab.Controls.SetHistogram` — проверок: 7

- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:479` (Histogram_BarFractionEdges): `Assert.AreEqual(0.0, LHistogram.BarFraction(7), 1e-12);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:484` (Histogram_BarFractionEdges): `Assert.AreEqual(1.0, LHistogram.BarFraction(0), 1e-12, 'Наибольший столбец — вся высота');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:485` (Histogram_BarFractionEdges): `Assert.AreEqual(0.0, LHistogram.BarFraction(2), 1e-12, 'Нулевой счётчик — нет столбца');`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:492` (Histogram_BarFractionEdges): `Assert.AreEqual(1.0, LHistogram.BarFraction(0), 1e-12);`
- `tests/Unit/MineHunter.Tests.BinaryLab.Api.pas:493` (Histogram_BarFractionEdges): `Assert.AreEqual(0.0, LHistogram.BarFraction(1), 1e-12);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1136` (Paint_NormalEmptyTiny): `Assert.IsFalse(FHistogram.ByteAtPoint(0, 0, B));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1144` (Paint_NormalEmptyTiny): `Assert.AreEqual<Int64>(0, FHistogram.Total);`

### `App.BinaryLab.Controls.SetRanges` — проверок: 3

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1253` (ZeroFileSize_Safe): `Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(100));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1254` (ZeroFileSize_Safe): `Assert.IsFalse(FStrip.RangeAtX(100, LIndex));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:1265` (ZeroFileSize_Safe): `Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(0), 'Нулевая ширина');`

### `App.BinaryLab.Controls.VisibleRows` — проверок: 6

- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:693` (BigVirtualSource_ScrollsToEndAndReadsOnlyPage): `Assert.AreEqual<Int64>((FView.RowCount - FView.VisibleRows) * 16, FView.TopOffset);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:696` (BigVirtualSource_ScrollsToEndAndReadsOnlyPage): `Assert.IsTrue(FView.PointOfOffset(SIZE_6GB + 4, P));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:697` (BigVirtualSource_ScrollsToEndAndReadsOnlyPage): `Assert.IsTrue(FView.OffsetAtPoint(P.X, P.Y, LOffset));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:704` (BigVirtualSource_ScrollsToEndAndReadsOnlyPage): `Assert.IsTrue(LSource.MaxRead <= 64 * 1024, Format('Читается только видимая страница (%d байт)', [LSource.MaxRead]));`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:705` (BigVirtualSource_ScrollsToEndAndReadsOnlyPage): `Assert.IsTrue(LSource.Reads > 0);`
- `tests/UI/MineHunter.Tests.UI.BinaryLabControls.pas:271` (BigVirtualSource_ScrollsToEndAndReadsOnlyPage): `Assert.IsTrue((LRow >= LTopRow) and (LRow < LTopRow + FView.VisibleRows),`

### `App.BinaryLabPage.Busy` — проверок: 14

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:616` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsTrue(WaitForBinaryLab(10000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:625` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsTrue(WaitForBinaryLab(30000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:626` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsFalse(LPage.Busy);`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:629` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsTrue(LPage.Busy);`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:566` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy);`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:568` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Отмена в простое');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:571` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Пустой путь не открывается');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:573` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Сравнивать не с чем');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:576` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Поиск без файла');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:586` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsTrue(WaitForBinaryLab(30000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:589` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Пустой путь сравнения');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:591` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Пустой шаблон');`
- … и ещё 2

### `App.BinaryLabPage.Cancel` — проверок: 4

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:568` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Отмена в простое');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:571` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Пустой путь не открывается');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:625` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsTrue(WaitForBinaryLab(30000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:626` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsFalse(LPage.Busy);`

### `App.BinaryLabPage.CompareWith` — проверок: 6

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:573` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Сравнивать не с чем');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:574` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.HasDiff);`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:589` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Пустой путь сравнения');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:591` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Пустой шаблон');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:598` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsTrue(WaitForBinaryLab(30000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:599` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsTrue(LPage.LastError <> '');`

### `App.BinaryLabPage.ExportDiff` — проверок: 2

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:582` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(TFile.Exists(LPath), 'Нет отчёта — нет файла');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:583` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(TFile.Exists(TPath.Combine(FTempDir, 'none-diff.html')));`

### `App.BinaryLabPage.ExportReport` — проверок: 2

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:582` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(TFile.Exists(LPath), 'Нет отчёта — нет файла');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:583` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(TFile.Exists(TPath.Combine(FTempDir, 'none-diff.html')));`

### `App.BinaryLabPage.FindPattern` — проверок: 8

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:576` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Поиск без файла');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:578` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.AreEqual(TMHBinaryLabPage.TabOverview, LPage.Tabs.ActivePageIndex, 'Без файла Hex не открывается');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:591` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Пустой шаблон');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:593` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.AreEqual(TMHBinaryLabPage.TabOverview, LPage.Tabs.ActivePageIndex, 'Отрицательное смещение');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:360` (BinaryLab_AnalyzeNavigateFindExportCompare): `Assert.IsTrue(WaitForBinaryLab(10000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:361` (BinaryLab_AnalyzeNavigateFindExportCompare): `Assert.IsTrue(LPage.LastFindOffset > 0, 'Найдено без учёта регистра');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:364` (BinaryLab_AnalyzeNavigateFindExportCompare): `Assert.IsTrue(WaitForBinaryLab(10000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:365` (BinaryLab_AnalyzeNavigateFindExportCompare): `Assert.AreEqual<Int64>(-1, LPage.LastFindOffset);`

### `App.BinaryLabPage.OpenFile` — проверок: 12

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:571` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Пустой путь не открывается');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:573` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(LPage.Busy, 'Сравнивать не с чем');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:586` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsTrue(WaitForBinaryLab(30000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:587` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsTrue(LPage.HasReport);`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:605` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsTrue(WaitForBinaryLab(30000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:606` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsTrue(LPage.Report.Path.EndsWith('edge3.exe'), LPage.Report.Path);`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:616` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsTrue(WaitForBinaryLab(10000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:617` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsTrue(LPage.LastError <> '', 'Ошибка открытия показана');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:625` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsTrue(WaitForBinaryLab(30000));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:626` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsFalse(LPage.Busy);`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:629` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.IsTrue(LPage.Busy);`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:632` (BinaryLab_ErrorsCancelAndCloseWhileBusy): `Assert.Pass('Окно закрыто во время анализа без ошибок');`

### `App.BinaryLabPage.ParseOffset` — проверок: 6

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:346` (BinaryLab_AnalyzeNavigateFindExportCompare): `Assert.IsTrue(TMHBinaryLabPage.ParseOffset('0x40', LOffset));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:348` (BinaryLab_AnalyzeNavigateFindExportCompare): `Assert.IsTrue(TMHBinaryLabPage.ParseOffset('1F4h', LOffset));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:350` (BinaryLab_AnalyzeNavigateFindExportCompare): `Assert.IsTrue(TMHBinaryLabPage.ParseOffset('128', LOffset));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:352` (BinaryLab_AnalyzeNavigateFindExportCompare): `Assert.IsTrue(TMHBinaryLabPage.ParseOffset('ff', LOffset), 'Буквы — шестнадцатеричное');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:353` (BinaryLab_AnalyzeNavigateFindExportCompare): `Assert.IsFalse(TMHBinaryLabPage.ParseOffset('', LOffset));`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:354` (BinaryLab_AnalyzeNavigateFindExportCompare): `Assert.IsFalse(TMHBinaryLabPage.ParseOffset('12x', LOffset));`

### `App.BinaryLabPage.ShowOffset` — проверок: 5

- `tests/UI/MineHunter.Tests.UI.Smoke.pas:578` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.AreEqual(TMHBinaryLabPage.TabOverview, LPage.Tabs.ActivePageIndex, 'Без файла Hex не открывается');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:582` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsFalse(TFile.Exists(LPath), 'Нет отчёта — нет файла');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:593` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.AreEqual(TMHBinaryLabPage.TabOverview, LPage.Tabs.ActivePageIndex, 'Отрицательное смещение');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:595` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.AreEqual<Int64>(1, LPage.HexView.SelLength, 'Длина выделения не меньше 1');`
- `tests/UI/MineHunter.Tests.UI.Smoke.pas:598` (BinaryLab_PageMethods_WithoutDataAreSafe): `Assert.IsTrue(WaitForBinaryLab(30000));`

Функций: 120, проверок: 635 (под условием: 2), пропусков: 0. Прогоны: Debug — 976 тестов, пройдено 976, Release — 976 тестов, пройдено 976.
