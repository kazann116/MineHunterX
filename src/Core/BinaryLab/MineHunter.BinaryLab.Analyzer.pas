unit MineHunter.BinaryLab.Analyzer;

{
  BinaryLab: полный анализ файла.

  Порядок: вид файла по содержимому → SHA-256 → разбор PE (секции: энтропия
  и хеши, ресурсы, контрольная сумма) → подпись Authenticode → энтропия по
  блокам → строки → вложенные объекты → аномалии и оценка.

  - Файл только читается (TMHFileSource) и никогда не запускается.
  - Каждый этап независим: ошибка этапа записывается в Errors, остальные
    продолжаются. Отмена (ACancel) прерывает анализ EMHBinaryLabCancelled.
  - Ход выполнения сообщается через AProgress (из потока анализа — вызывающий
    сам переносит его в поток интерфейса).
  - Память ограничена лимитами TMHBinaryLabOptions и не зависит от размера
    файла: данные читаются блоками.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Collectors.Files,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

/// Анализ данных ASource. APath — путь (для отчёта, проверки подписи и
/// сравнения расширения); AFileApi = nil — подпись не проверяется.
function MHAnalyzeBinarySource(const ASource: IMHBinarySource; const APath: string;
  const AOptions: TMHBinaryLabOptions; const AFileApi: IMHFileApi; ANowUtc: TDateTime;
  const AThresholds: TMHRiskThresholds; const ACancel: TMHCancelCheck = nil;
  const AProgress: TMHBinaryProgress = nil): TMHBinaryReport;

/// Анализ файла на диске. EMHBinaryLabError — файл не открывается.
function MHAnalyzeBinaryFile(const APath: string; const AOptions: TMHBinaryLabOptions;
  const AFileApi: IMHFileApi; ANowUtc: TDateTime; const AThresholds: TMHRiskThresholds;
  const ACancel: TMHCancelCheck = nil; const AProgress: TMHBinaryProgress = nil): TMHBinaryReport;

const
  /// Сколько ресурсов получают оценку энтропии (остальные — без неё).
  MH_MAX_RESOURCE_ENTROPY = 1024;

implementation

uses
  System.Math, System.Diagnostics,
  MineHunter.Core.Lang,
  MineHunter.BinaryLab.FileType, MineHunter.BinaryLab.Pe, MineHunter.BinaryLab.Entropy,
  MineHunter.BinaryLab.Strings, MineHunter.BinaryLab.Embedded, MineHunter.BinaryLab.Anomalies;

function MHAnalyzeBinarySource(const ASource: IMHBinarySource; const APath: string;
  const AOptions: TMHBinaryLabOptions; const AFileApi: IMHFileApi; ANowUtc: TDateTime;
  const AThresholds: TMHRiskThresholds; const ACancel: TMHCancelCheck;
  const AProgress: TMHBinaryProgress): TMHBinaryReport;
var
  LOptions: TMHBinaryLabOptions;
  LReader: TMHBinaryReader;
  LReport: TMHBinaryReport;
  LWatch: TStopwatch;
  LPe: TMHPeInfo;
  LSize: Int64;
  LLocate: TMHLocateFunc;
  I, LResourceCount: Integer;
  LState: TMHSignatureState;
  LSigner, LSource, LError: string;

  procedure Progress(const AStage: string; APercent: Integer);
  begin
    MHCheckCancel(ACancel);
    if Assigned(AProgress) then
      AProgress(AStage, APercent);
  end;

  procedure Fail(const AStage: string; E: Exception);
  begin
    LReport.Errors := LReport.Errors + [AStage + ': ' + E.Message];
  end;

var
  LHoldSource: IMHBinarySource;
begin
  // Ссылка на источник на время работы: объект, созданный прямо в аргументе,
  // иначе не освобождается (const-параметр интерфейса не увеличивает счётчик).
  LHoldSource := ASource;
  if ASource = nil then
    raise EArgumentNilException.Create('ASource');
  LOptions := AOptions.Normalized;
  LWatch := TStopwatch.StartNew;
  LReport := Default(TMHBinaryReport);
  LReport.Path := APath;
  LReport.FileName := ExtractFileName(APath);
  LReport.Size := ASource.Size;
  LReport.AnalyzedAtUtc := ANowUtc;
  LReport.RulesVersion := MH_BINARYLAB_VERSION;
  LReport.Pe.EntryPointOffset := MH_NO_OFFSET;
  LReport.Pe.OverlayOffset := MH_NO_OFFSET;
  LReport.Pe.CertificateOffset := MH_NO_OFFSET;
  LSize := ASource.Size;
  LReader := TMHBinaryReader.Create(ASource);
  try
    Progress(MHL('Определение вида файла', 'Detecting the file type'), 2);
    LReport.FileType := MHDetectBinaryType(LReader, APath);

    Progress(MHL('Вычисление SHA-256', 'Computing SHA-256'), 5);
    try
      LReport.Sha256 := MHRangeSha256(ASource, 0, LSize, ACancel);
    except
      on E: EMHBinaryLabCancelled do
        raise;
      on E: Exception do
        Fail('SHA-256', E);
    end;

    if LReport.FileType.Kind in [bkPE, bkMsDos] then
    begin
      Progress(MHL('Разбор структуры PE', 'Parsing the PE structure'), 20);
      try
        LReport.Pe := MHParsePe(LReader, LOptions, ACancel);
      except
        on E: EMHBinaryLabCancelled do
          raise;
        on E: Exception do
          Fail(MHL('Разбор PE', 'PE parsing'), E);
      end;
      if LReport.Pe.Valid then
      begin
        Progress(MHL('Энтропия и хеши секций', 'Section entropy and hashes'), 30);
        try
          for I := 0 to High(LReport.Pe.Sections) do
            if (LReport.Pe.Sections[I].RawSize > 0) and (LReport.Pe.Sections[I].RawOffset < LSize) then
            begin
              MHCheckCancel(ACancel);
              LReport.Pe.Sections[I].Entropy := MHRangeEntropy(ASource, LReport.Pe.Sections[I].RawOffset,
                LReport.Pe.Sections[I].RawSize, LOptions.MaxSectionHashBytes);
              if LReport.Pe.Sections[I].RawSize <= LOptions.MaxSectionHashBytes then
                LReport.Pe.Sections[I].Sha256 := MHRangeSha256(ASource, LReport.Pe.Sections[I].RawOffset,
                  LReport.Pe.Sections[I].RawSize, ACancel);
            end;
          LResourceCount := 0;
          for I := 0 to High(LReport.Pe.Resources) do
            if (LReport.Pe.Resources[I].Offset >= 0) and (LReport.Pe.Resources[I].Size >= 16) and
               (LResourceCount < MH_MAX_RESOURCE_ENTROPY) then
            begin
              MHCheckCancel(ACancel);
              LReport.Pe.Resources[I].Entropy := MHRangeEntropy(ASource, LReport.Pe.Resources[I].Offset,
                LReport.Pe.Resources[I].Size, LOptions.MaxSectionHashBytes);
              Inc(LResourceCount);
            end;
          if LOptions.ComputeChecksum and (LSize <= LOptions.MaxScanBytes) then
            LReport.Pe.ComputedCheckSum := MHComputePeChecksum(ASource, Int64(LReport.Pe.HeaderOffset) + 24 + 64,
              ACancel);
        except
          on E: EMHBinaryLabCancelled do
            raise;
          on E: Exception do
            Fail(MHL('Секции', 'Sections'), E);
        end;
        if LReport.Pe.IsDotNet then
          LReport.FileType.Description := LReport.FileType.Description + ', .NET';
      end;
    end;

    LReport.Signature.State := sgNotChecked;
    if (LReport.FileType.Kind = bkPE) and LOptions.VerifySignature and (AFileApi <> nil) and (APath <> '') and
       FileExists(APath) then
    begin
      Progress(MHL('Проверка цифровой подписи', 'Verifying the digital signature'), 40);
      try
        AFileApi.VerifySignature(APath, LState, LSigner, LSource, LError);
        LReport.Signature.State := LState;
        LReport.Signature.Signer := LSigner;
        LReport.Signature.Source := LSource;
        LReport.Signature.Error := LError;
      except
        on E: EMHBinaryLabCancelled do
          raise;
        on E: Exception do
        begin
          LReport.Signature.State := sgCheckFailed;
          LReport.Signature.Error := E.Message;
        end;
      end;
    end;

    // Местоположение смещения (секция, оверлей, подпись) — для областей энтропии и вложений.
    LPe := LReport.Pe;
    LLocate :=
      function(AOffset: Int64): string
      begin
        Result := MHPeLocate(LPe, LSize, AOffset);
      end;

    Progress(MHL('Энтропия по блокам', 'Block entropy'), 50);
    try
      LReport.Entropy := MHAnalyzeEntropy(ASource, LOptions, LLocate, ACancel);
      // Энтропия маленьких блоков занижена (по 256 байтам даже случайные данные
      // дают около 7.2): средние значения областей и оверлея считаются по всему диапазону.
      for I := 0 to High(LReport.Entropy.HighRegions) do
      begin
        MHCheckCancel(ACancel);
        LReport.Entropy.HighRegions[I].AverageEntropy := Max(LReport.Entropy.HighRegions[I].AverageEntropy,
          MHRangeEntropy(ASource, LReport.Entropy.HighRegions[I].Offset, LReport.Entropy.HighRegions[I].Size,
            LOptions.MaxSectionHashBytes));
        LReport.Entropy.HighRegions[I].EntropyClass := MHEntropyClassOf(LReport.Entropy.HighRegions[I].AverageEntropy);
      end;
      if LReport.Pe.Valid and (LReport.Pe.OverlaySize > 0) then
        LReport.Pe.OverlayEntropy := Max(0.0, MHRangeEntropy(ASource, LReport.Pe.OverlayOffset,
          LReport.Pe.OverlaySize, LOptions.MaxSectionHashBytes));
    except
      on E: EMHBinaryLabCancelled do
        raise;
      on E: Exception do
        Fail(MHL('Энтропия', 'Entropy'), E);
    end;

    Progress(MHL('Поиск строк', 'Scanning strings'), 65);
    try
      LReport.Strings := MHScanStrings(ASource, LOptions, ACancel);
    except
      on E: EMHBinaryLabCancelled do
        raise;
      on E: Exception do
        Fail(MHL('Строки', 'Strings'), E);
    end;

    Progress(MHL('Поиск вложенных файлов', 'Searching for embedded files'), 80);
    try
      LReport.Embedded := MHFindEmbedded(ASource, LOptions, LLocate, ACancel);
    except
      on E: EMHBinaryLabCancelled do
        raise;
      on E: Exception do
        Fail(MHL('Вложенные файлы', 'Embedded files'), E);
    end;

    if LSize > LOptions.MaxScanBytes then
    begin
      LReport.Partial := True;
      LReport.Notes := LReport.Notes + [Format(MHL('Файл больше лимита %s байт: энтропия, строки и вложения ' +
        'проверены только в начале файла.', 'The file exceeds the %s-byte limit: entropy, strings and embedded ' +
        'objects were checked only at the start.'), [FormatFloat('#,##0', LOptions.MaxScanBytes)])];
    end;
    if LReport.Strings.Truncated then
      LReport.Notes := LReport.Notes + [Format(MHL('Строк найдено %d, в отчёте — %d (лимит).',
        'Found %d strings, the report keeps %d (limit).'), [LReport.Strings.TotalFound, Length(LReport.Strings.Items)])];

    Progress(MHL('Поиск аномалий и оценка', 'Detecting anomalies and scoring'), 95);
    LReport.Anomalies := MHDetectAnomalies(LReport, ANowUtc);
    MHScoreBinaryReport(LReport, AThresholds);
    LReport.DurationMs := LWatch.ElapsedMilliseconds;
    if Assigned(AProgress) then
      AProgress(MHL('Готово', 'Done'), 100);
  finally
    LReader.Free;
  end;
  Result := LReport;
end;

function MHAnalyzeBinaryFile(const APath: string; const AOptions: TMHBinaryLabOptions;
  const AFileApi: IMHFileApi; ANowUtc: TDateTime; const AThresholds: TMHRiskThresholds;
  const ACancel: TMHCancelCheck; const AProgress: TMHBinaryProgress): TMHBinaryReport;
var
  LSource: TMHFileSource;
  LSourceIntf: IMHBinarySource;
begin
  LSource := TMHFileSource.Create(APath);
  LSourceIntf := LSource;
  Result := MHAnalyzeBinarySource(LSourceIntf, APath, AOptions, AFileApi, ANowUtc, AThresholds, ACancel, AProgress);
  Result.LastWriteUtc := LSource.LastWriteUtc;
end;

end.
