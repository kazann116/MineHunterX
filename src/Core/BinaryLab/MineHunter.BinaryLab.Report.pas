unit MineHunter.BinaryLab.Report;

{
  Отчёты BinaryLab: JSON (полные данные для обработки другими программами)
  и HTML (один самодостаточный документ для человека: встроенный CSS и SVG,
  без сценариев и внешних ресурсов — открывается без сети).

  Все строки из файла (имена секций, функций, ресурсов, строки, пути)
  экранируются: анализируемый файл не может внедрить разметку в отчёт.
  В HTML списки ограничены (строки — 2000, экспорт — 3000), полный список —
  в JSON.
}

interface

uses
  System.SysUtils,
  MineHunter.BinaryLab.Types;

function MHBinaryReportToJson(const AReport: TMHBinaryReport): string;
function MHBinaryReportToHtml(const AReport: TMHBinaryReport): string;
function MHBinaryDiffToJson(const ADiff: TMHBinaryDiff): string;
function MHBinaryDiffToHtml(const ADiff: TMHBinaryDiff): string;

/// Сохраняет отчёт: формат по расширению (.json — JSON, иначе HTML).
procedure MHSaveBinaryReport(const AReport: TMHBinaryReport; const AFileName: string);
procedure MHSaveBinaryDiff(const ADiff: TMHBinaryDiff; const AFileName: string);

const
  MH_HTML_MAX_STRINGS = 2000;
  MH_HTML_MAX_EXPORTS = 3000;

implementation

uses
  System.JSON, System.Math, System.DateUtils, System.StrUtils,
  MineHunter.Core.Types, MineHunter.Core.Lang, MineHunter.Core.Reports, MineHunter.BinaryLab.Diff;

const
  HTML_STYLE =
    'body{font-family:"Segoe UI",Arial,sans-serif;margin:24px;color:#1b1b1b;background:#fff;line-height:1.45}' +
    'h1{font-size:22px;margin:0 0 12px}h2{font-size:18px;margin:24px 0 8px;border-bottom:1px solid #ccc;' +
    'padding-bottom:4px}table{border-collapse:collapse;margin:6px 0 12px}' +
    'th,td{border:1px solid #c8c8c8;padding:4px 8px;text-align:left;vertical-align:top}th{background:#f0f0f0}' +
    '.verdict{border:1px solid #bbb;border-left:6px solid #888;padding:10px 14px;margin:12px 0}' +
    '.lvl-none{border-left-color:#8a8a8a}.lvl-low{border-left-color:#3a7bd5}' +
    '.lvl-needsReview{border-left-color:#c79100}.lvl-suspicious{border-left-color:#d9480f}' +
    '.lvl-highlySuspicious{border-left-color:#b00020}' +
    '.sev-high{color:#b00020;font-weight:600}.sev-medium{color:#d9480f;font-weight:600}' +
    '.sev-low{color:#c79100}.sev-info{color:#555}' +
    '.muted{color:#555}.mono{font-family:Consolas,monospace;word-break:break-all}' +
    '.added{background:#e8f5e9}.removed{background:#ffebee}.changed{background:#fff8e1}' +
    '.disclaimer{margin-top:28px;padding:10px;border:1px solid #c79100;background:#fff8e1}' +
    'svg{border:1px solid #ccc;background:#fafafa}details{margin:2px 0}' +
    '@media print{body{margin:0}}';

var
  GInvariant: TFormatSettings;

function Num(AValue: Double; ADigits: Integer = 2): string;
begin
  Result := FloatToStrF(AValue, ffFixed, 15, ADigits, GInvariant);
end;

function IsoUtc(AUtc: TDateTime): string;
begin
  if AUtc <= 0 then
    Exit('');
  Result := DateToISO8601(AUtc, True);
end;

function LevelClass(ALevel: TMHRiskLevel): string;
const
  NAMES: array[TMHRiskLevel] of string = ('none', 'low', 'needsReview', 'suspicious', 'highlySuspicious');
begin
  Result := 'lvl-' + NAMES[ALevel];
end;

function SignatureStateName(AState: TMHSignatureState): string;
const
  NAMES: array[TMHSignatureState] of string = ('notChecked', 'signedTrusted', 'signedUntrusted', 'unsigned',
    'checkFailed');
begin
  Result := NAMES[AState];
end;

function SignatureTitle(const ASignature: TMHBinarySignature): string;
begin
  case ASignature.State of
    sgSignedTrusted:   Result := MHL('Подписан доверенным издателем', 'Signed by a trusted publisher');
    sgSignedUntrusted: Result := MHL('Подпись недействительна', 'Invalid signature');
    sgUnsigned:        Result := MHL('Без цифровой подписи', 'Not digitally signed');
    sgCheckFailed:     Result := MHL('Подпись не удалось проверить', 'Signature could not be verified');
  else
    Result := MHL('Подпись не проверялась', 'Signature not checked');
  end;
end;

function H(const AText: string): string;
begin
  Result := MHHtmlEscape(AText);
end;

function JsonArrayOfStrings(const AItems: TArray<string>): TJSONArray;
var
  LItem: string;
begin
  Result := TJSONArray.Create;
  for LItem in AItems do
    Result.Add(LItem);
end;

{ JSON }

function PeToJson(const APe: TMHPeInfo): TJSONObject;
var
  LSections, LImports, LExports, LResources, LDirs: TJSONArray;
  LSection: TMHPeSection;
  LImport: TMHPeImport;
  LExport: TMHPeExport;
  LResource: TMHPeResource;
  LDir: TMHPeDataDirectory;
  LObject: TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('valid', TJSONBool.Create(APe.Valid));
  if not APe.Valid then
  begin
    Result.AddPair('warnings', JsonArrayOfStrings(APe.Warnings));
    Exit;
  end;
  Result.AddPair('is64', TJSONBool.Create(APe.Is64));
  Result.AddPair('kind', MHPeKindTitle(APe.Kind));
  Result.AddPair('machine', APe.MachineName);
  Result.AddPair('timeDateStamp', TJSONNumber.Create(APe.TimeDateStamp));
  Result.AddPair('linkerVersion', APe.LinkerVersion);
  Result.AddPair('osVersion', APe.OsVersion);
  Result.AddPair('subsystem', APe.SubsystemName);
  Result.AddPair('characteristics', '0x' + IntToHex(APe.Characteristics, 4));
  Result.AddPair('dllCharacteristics', '0x' + IntToHex(APe.DllCharacteristics, 4));
  Result.AddPair('imageBase', '0x' + IntToHex(APe.ImageBase, 8));
  Result.AddPair('sizeOfImage', TJSONNumber.Create(APe.SizeOfImage));
  Result.AddPair('fileAlignment', TJSONNumber.Create(APe.FileAlignment));
  Result.AddPair('sectionAlignment', TJSONNumber.Create(APe.SectionAlignment));
  LObject := TJSONObject.Create;
  LObject.AddPair('rva', '0x' + IntToHex(APe.EntryPointRva, 8));
  LObject.AddPair('offset', TJSONNumber.Create(APe.EntryPointOffset));
  LObject.AddPair('section', APe.EntryPointSection);
  Result.AddPair('entryPoint', LObject);
  LObject := TJSONObject.Create;
  LObject.AddPair('header', '0x' + IntToHex(APe.CheckSum, 8));
  LObject.AddPair('computed', '0x' + IntToHex(APe.ComputedCheckSum, 8));
  Result.AddPair('checksum', LObject);
  Result.AddPair('isDotNet', TJSONBool.Create(APe.IsDotNet));
  Result.AddPair('tlsCallbacks', TJSONNumber.Create(APe.TlsCallbackCount));
  LObject := TJSONObject.Create;
  LObject.AddPair('offset', TJSONNumber.Create(APe.OverlayOffset));
  LObject.AddPair('size', TJSONNumber.Create(APe.OverlaySize));
  Result.AddPair('overlay', LObject);
  LObject := TJSONObject.Create;
  LObject.AddPair('offset', TJSONNumber.Create(APe.CertificateOffset));
  LObject.AddPair('size', TJSONNumber.Create(APe.CertificateSize));
  Result.AddPair('certificate', LObject);
  LDirs := TJSONArray.Create;
  for LDir in APe.DataDirectories do
    if LDir.Size <> 0 then
    begin
      LObject := TJSONObject.Create;
      LObject.AddPair('name', LDir.Name);
      LObject.AddPair('rva', '0x' + IntToHex(LDir.Rva, 8));
      LObject.AddPair('size', TJSONNumber.Create(LDir.Size));
      LDirs.AddElement(LObject);
    end;
  Result.AddPair('dataDirectories', LDirs);
  LSections := TJSONArray.Create;
  for LSection in APe.Sections do
  begin
    LObject := TJSONObject.Create;
    LObject.AddPair('name', LSection.Name);
    LObject.AddPair('virtualAddress', '0x' + IntToHex(LSection.VirtualAddress, 8));
    LObject.AddPair('virtualSize', TJSONNumber.Create(LSection.VirtualSize));
    LObject.AddPair('rawOffset', TJSONNumber.Create(LSection.RawOffset));
    LObject.AddPair('rawSize', TJSONNumber.Create(LSection.RawSize));
    LObject.AddPair('characteristics', '0x' + IntToHex(LSection.Characteristics, 8));
    LObject.AddPair('access', LSection.AccessText);
    LObject.AddPair('entropy', TJSONNumber.Create(RoundTo(LSection.Entropy, -3)));
    LObject.AddPair('sha256', LSection.Sha256);
    LSections.AddElement(LObject);
  end;
  Result.AddPair('sections', LSections);
  LImports := TJSONArray.Create;
  for LImport in APe.Imports do
  begin
    LObject := TJSONObject.Create;
    LObject.AddPair('dll', LImport.Dll);
    LObject.AddPair('delayed', TJSONBool.Create(LImport.Delayed));
    LObject.AddPair('functions', JsonArrayOfStrings(LImport.Functions));
    LImports.AddElement(LObject);
  end;
  Result.AddPair('imports', LImports);
  Result.AddPair('exportName', APe.ExportName);
  LExports := TJSONArray.Create;
  for LExport in APe.ExportedFunctions do
  begin
    LObject := TJSONObject.Create;
    LObject.AddPair('ordinal', TJSONNumber.Create(LExport.Ordinal));
    LObject.AddPair('name', LExport.Name);
    LObject.AddPair('rva', '0x' + IntToHex(LExport.Rva, 8));
    if LExport.Forwarder <> '' then
      LObject.AddPair('forwarder', LExport.Forwarder);
    LExports.AddElement(LObject);
  end;
  Result.AddPair('exports', LExports);
  LResources := TJSONArray.Create;
  for LResource in APe.Resources do
  begin
    LObject := TJSONObject.Create;
    LObject.AddPair('type', LResource.TypeName);
    LObject.AddPair('name', LResource.Name);
    LObject.AddPair('language', TJSONNumber.Create(LResource.Language));
    LObject.AddPair('offset', TJSONNumber.Create(LResource.Offset));
    LObject.AddPair('size', TJSONNumber.Create(LResource.Size));
    LObject.AddPair('entropy', TJSONNumber.Create(RoundTo(LResource.Entropy, -3)));
    LObject.AddPair('content', MHBinaryKindToName(LResource.ContentKind));
    LResources.AddElement(LObject);
  end;
  Result.AddPair('resources', LResources);
  Result.AddPair('warnings', JsonArrayOfStrings(APe.Warnings));
end;

function MHBinaryReportToJson(const AReport: TMHBinaryReport): string;
var
  LRoot, LObject: TJSONObject;
  LArray, LPair: TJSONArray;
  LBlock: TMHEntropyBlock;
  LRegion: TMHEntropyRegion;
  LString: TMHBinaryString;
  LEmbedded: TMHEmbeddedObject;
  LAnomaly: TMHBinaryAnomaly;
  LCategory: TMHStringCategory;
  I: Integer;
begin
  LRoot := TJSONObject.Create;
  try
    LRoot.AddPair('tool', 'MineHunter X BinaryLab');
    LRoot.AddPair('rulesVersion', AReport.RulesVersion);
    LRoot.AddPair('analyzedAtUtc', IsoUtc(AReport.AnalyzedAtUtc));
    LRoot.AddPair('durationMs', TJSONNumber.Create(AReport.DurationMs));
    LObject := TJSONObject.Create;
    LObject.AddPair('path', AReport.Path);
    LObject.AddPair('name', AReport.FileName);
    LObject.AddPair('size', TJSONNumber.Create(AReport.Size));
    LObject.AddPair('sha256', AReport.Sha256);
    LObject.AddPair('lastWriteUtc', IsoUtc(AReport.LastWriteUtc));
    LRoot.AddPair('file', LObject);
    LObject := TJSONObject.Create;
    LObject.AddPair('kind', MHBinaryKindToName(AReport.FileType.Kind));
    LObject.AddPair('description', AReport.FileType.Description);
    LObject.AddPair('extension', AReport.FileType.Extension);
    LObject.AddPair('extensionMismatch', TJSONBool.Create(AReport.FileType.ExtensionMismatch));
    LRoot.AddPair('type', LObject);
    LObject := TJSONObject.Create;
    LObject.AddPair('state', SignatureStateName(AReport.Signature.State));
    LObject.AddPair('signer', AReport.Signature.Signer);
    LObject.AddPair('source', AReport.Signature.Source);
    LObject.AddPair('error', AReport.Signature.Error);
    LRoot.AddPair('signature', LObject);
    LRoot.AddPair('score', TJSONNumber.Create(AReport.Score));
    LRoot.AddPair('level', MHRiskLevelToString(AReport.Level));
    LRoot.AddPair('verdict', AReport.Verdict);
    LRoot.AddPair('partial', TJSONBool.Create(AReport.Partial));
    LRoot.AddPair('notes', JsonArrayOfStrings(AReport.Notes));
    LRoot.AddPair('errors', JsonArrayOfStrings(AReport.Errors));
    LArray := TJSONArray.Create;
    for LAnomaly in AReport.Anomalies do
    begin
      LObject := TJSONObject.Create;
      LObject.AddPair('code', LAnomaly.Code);
      LObject.AddPair('severity', MHAnomalySeverityToName(LAnomaly.Severity));
      LObject.AddPair('weight', TJSONNumber.Create(LAnomaly.Weight));
      LObject.AddPair('title', LAnomaly.Title);
      LObject.AddPair('details', LAnomaly.Details);
      LObject.AddPair('offset', TJSONNumber.Create(LAnomaly.Offset));
      LObject.AddPair('size', TJSONNumber.Create(LAnomaly.Size));
      LArray.AddElement(LObject);
    end;
    LRoot.AddPair('anomalies', LArray);
    LRoot.AddPair('pe', PeToJson(AReport.Pe));
    // Энтропия: блоки как пары [смещение, энтропия] — компактнее объектов.
    LObject := TJSONObject.Create;
    LObject.AddPair('overall', TJSONNumber.Create(RoundTo(AReport.Entropy.Overall, -3)));
    LObject.AddPair('blockSize', TJSONNumber.Create(AReport.Entropy.BlockSize));
    LObject.AddPair('bytesScanned', TJSONNumber.Create(AReport.Entropy.BytesScanned));
    LArray := TJSONArray.Create;
    for LBlock in AReport.Entropy.Blocks do
    begin
      LPair := TJSONArray.Create;
      LPair.Add(LBlock.Offset);
      LPair.Add(RoundTo(LBlock.Entropy, -3));
      LArray.AddElement(LPair);
    end;
    LObject.AddPair('blocks', LArray);
    LArray := TJSONArray.Create;
    for LRegion in AReport.Entropy.HighRegions do
    begin
      LPair := TJSONArray.Create;
      LPair.Add(LRegion.Offset);
      LPair.Add(LRegion.Size);
      LPair.Add(RoundTo(LRegion.AverageEntropy, -3));
      LPair.Add(LRegion.Location);
      LArray.AddElement(LPair);
    end;
    LObject.AddPair('highRegions', LArray);
    LArray := TJSONArray.Create;
    for I := 0 to 255 do
      LArray.Add(AReport.Entropy.Histogram[I]);
    LObject.AddPair('histogram', LArray);
    LRoot.AddPair('entropy', LObject);
    LObject := TJSONObject.Create;
    LObject.AddPair('totalFound', TJSONNumber.Create(AReport.Strings.TotalFound));
    LObject.AddPair('truncated', TJSONBool.Create(AReport.Strings.Truncated));
    LPair := TJSONArray.Create;
    for LCategory := Low(TMHStringCategory) to High(TMHStringCategory) do
      if AReport.Strings.CountByCategory[LCategory] > 0 then
      begin
        LArray := TJSONArray.Create;
        LArray.Add(MHStringCategoryToName(LCategory));
        LArray.Add(AReport.Strings.CountByCategory[LCategory]);
        LPair.AddElement(LArray);
      end;
    LObject.AddPair('byCategory', LPair);
    LArray := TJSONArray.Create;
    for LString in AReport.Strings.Items do
    begin
      LPair := TJSONArray.Create;
      LPair.Add(LString.Offset);
      if LString.Encoding = seUtf16 then
        LPair.Add('utf16')
      else
        LPair.Add('ascii');
      LPair.Add(MHStringCategoryToName(LString.Category));
      LPair.Add(LString.Text);
      LArray.AddElement(LPair);
    end;
    LObject.AddPair('items', LArray);
    LRoot.AddPair('strings', LObject);
    LArray := TJSONArray.Create;
    for LEmbedded in AReport.Embedded do
    begin
      LObject := TJSONObject.Create;
      LObject.AddPair('offset', TJSONNumber.Create(LEmbedded.Offset));
      LObject.AddPair('size', TJSONNumber.Create(LEmbedded.Size));
      LObject.AddPair('kind', MHBinaryKindToName(LEmbedded.Kind));
      LObject.AddPair('description', LEmbedded.Description);
      LObject.AddPair('location', LEmbedded.Location);
      LArray.AddElement(LObject);
    end;
    LRoot.AddPair('embedded', LArray);
    Result := LRoot.Format(2);
  finally
    LRoot.Free;
  end;
end;

function MHBinaryDiffToJson(const ADiff: TMHBinaryDiff): string;
var
  LRoot, LObject: TJSONObject;
  LArray, LPair: TJSONArray;
  LItem: TMHDiffItem;
  LRange: TMHByteRange;
begin
  LRoot := TJSONObject.Create;
  try
    LRoot.AddPair('tool', 'MineHunter X BinaryDiff');
    LObject := TJSONObject.Create;
    LObject.AddPair('path', ADiff.LeftPath);
    LObject.AddPair('size', TJSONNumber.Create(ADiff.LeftSize));
    LObject.AddPair('sha256', ADiff.LeftSha256);
    LRoot.AddPair('left', LObject);
    LObject := TJSONObject.Create;
    LObject.AddPair('path', ADiff.RightPath);
    LObject.AddPair('size', TJSONNumber.Create(ADiff.RightSize));
    LObject.AddPair('sha256', ADiff.RightSha256);
    LRoot.AddPair('right', LObject);
    LRoot.AddPair('identical', TJSONBool.Create(ADiff.Identical));
    LRoot.AddPair('similarityPercent', TJSONNumber.Create(RoundTo(ADiff.SimilarityPercent, -2)));
    LRoot.AddPair('changedBytes', TJSONNumber.Create(ADiff.ChangedBytes));
    LRoot.AddPair('blockSize', TJSONNumber.Create(ADiff.BlockSize));
    LRoot.AddPair('truncated', TJSONBool.Create(ADiff.Truncated));
    LArray := TJSONArray.Create;
    for LRange in ADiff.ChangedRanges do
    begin
      LPair := TJSONArray.Create;
      LPair.Add(LRange.Offset);
      LPair.Add(LRange.Size);
      LArray.AddElement(LPair);
    end;
    LRoot.AddPair('changedRanges', LArray);
    LArray := TJSONArray.Create;
    for LItem in ADiff.Items do
    begin
      LObject := TJSONObject.Create;
      LObject.AddPair('area', LItem.Area);
      LObject.AddPair('change', MHDiffChangeToName(LItem.Change));
      LObject.AddPair('name', LItem.Name);
      LObject.AddPair('old', LItem.OldValue);
      LObject.AddPair('new', LItem.NewValue);
      LArray.AddElement(LObject);
    end;
    LRoot.AddPair('items', LArray);
    Result := LRoot.Format(2);
  finally
    LRoot.Free;
  end;
end;

{ HTML }

function EntropyColorHex(AEntropy: Double): string;
var
  T: Double;
  R, G, B: Integer;
begin
  // Синий (0) → зелёный (4.5) → жёлтый (6.8) → красный (8): как на карте в интерфейсе.
  AEntropy := EnsureRange(AEntropy, 0, 8);
  if AEntropy < 4.5 then
  begin
    T := AEntropy / 4.5;
    R := Round(30 * (1 - T) + 60 * T);
    G := Round(60 * (1 - T) + 170 * T);
    B := Round(150 * (1 - T) + 80 * T);
  end
  else if AEntropy < 6.8 then
  begin
    T := (AEntropy - 4.5) / 2.3;
    R := Round(60 + (230 - 60) * T);
    G := Round(170 + (200 - 170) * T);
    B := Round(80 * (1 - T) + 40 * T);
  end
  else
  begin
    T := (AEntropy - 6.8) / 1.2;
    R := Round(230 + (200 - 230) * T);
    G := Round(200 * (1 - T) + 30 * T);
    B := Round(40 * (1 - T) + 30 * T);
  end;
  Result := Format('#%.2x%.2x%.2x', [EnsureRange(R, 0, 255), EnsureRange(G, 0, 255), EnsureRange(B, 0, 255)]);
end;

function EntropySvg(const AEntropy: TMHEntropyInfo): string;
const
  COLUMNS = 64;
  CELL = 10;
var
  LBuilder: TStringBuilder;
  I, LRows: Integer;
begin
  if Length(AEntropy.Blocks) = 0 then
    Exit('<p class="muted">' + H(MHL('Нет данных энтропии.', 'No entropy data.')) + '</p>');
  LRows := (Length(AEntropy.Blocks) + COLUMNS - 1) div COLUMNS;
  LBuilder := TStringBuilder.Create;
  try
    LBuilder.AppendFormat('<svg width="%d" height="%d" role="img" aria-label="%s">',
      [COLUMNS * CELL, LRows * CELL, H(MHL('Карта энтропии', 'Entropy map'))]);
    for I := 0 to High(AEntropy.Blocks) do
      LBuilder.AppendFormat('<rect x="%d" y="%d" width="%d" height="%d" fill="%s"><title>%s</title></rect>',
        [(I mod COLUMNS) * CELL, (I div COLUMNS) * CELL, CELL, CELL, EntropyColorHex(AEntropy.Blocks[I].Entropy),
         H(MHHexOffset(AEntropy.Blocks[I].Offset) + ': ' + Num(AEntropy.Blocks[I].Entropy))]);
    LBuilder.Append('</svg>');
    Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

function HistogramSvg(const AEntropy: TMHEntropyInfo): string;
const
  HEIGHT = 120;
var
  LBuilder: TStringBuilder;
  I, LBar: Integer;
  LMax: Double;
begin
  LMax := 0;
  for I := 0 to 255 do
    LMax := Max(LMax, Ln(1 + AEntropy.Histogram[I]));
  if LMax <= 0 then
    Exit('');
  LBuilder := TStringBuilder.Create;
  try
    LBuilder.AppendFormat('<svg width="%d" height="%d" role="img" aria-label="%s">',
      [256 * 2, HEIGHT, H(MHL('Распределение байтов', 'Byte distribution'))]);
    for I := 0 to 255 do
    begin
      LBar := Round(Ln(1 + AEntropy.Histogram[I]) / LMax * (HEIGHT - 2));
      LBuilder.AppendFormat('<rect x="%d" y="%d" width="2" height="%d" fill="#3a7bd5"><title>0x%.2x: %d</title></rect>',
        [I * 2, HEIGHT - LBar, LBar, I, AEntropy.Histogram[I]]);
    end;
    LBuilder.Append('</svg>');
    Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

function SeverityClass(ASeverity: TMHAnomalySeverity): string;
begin
  Result := 'sev-' + MHAnomalySeverityToName(ASeverity);
end;

function MHBinaryReportToHtml(const AReport: TMHBinaryReport): string;
var
  B: TStringBuilder;
  LAnomaly: TMHBinaryAnomaly;
  LSection: TMHPeSection;
  LImport: TMHPeImport;
  LExport: TMHPeExport;
  LResource: TMHPeResource;
  LEmbedded: TMHEmbeddedObject;
  LString: TMHBinaryString;
  LRegion: TMHEntropyRegion;
  LCategory: TMHStringCategory;
  LText: string;
  LCount, I: Integer;
  LPass: Integer;

  procedure Row(const AName, AValue: string);
  begin
    B.Append('<tr><th>').Append(H(AName)).Append('</th><td>').Append(H(AValue)).Append('</td></tr>');
  end;

begin
  B := TStringBuilder.Create;
  try
    B.Append('<!DOCTYPE html>'#13#10'<html lang="').Append(MHL('ru', 'en')).Append('">'#13#10'<head>'#13#10);
    B.Append('<meta charset="utf-8">'#13#10'<title>').Append(H('BinaryLab — ' + AReport.FileName)).Append('</title>'#13#10);
    B.Append('<style>').Append(HTML_STYLE).Append('</style>'#13#10'</head>'#13#10'<body>'#13#10);
    B.Append('<h1>').Append(H('MineHunter X BinaryLab — ' + AReport.FileName)).Append('</h1>'#13#10);
    B.Append('<div class="verdict ').Append(LevelClass(AReport.Level)).Append('"><strong>')
      .Append(H(Format(MHL('Оценка %d из 100 — %s', 'Score %d of 100 — %s'),
        [AReport.Score, MHRiskLevelToString(AReport.Level)])))
      .Append('</strong><br>').Append(H(AReport.Verdict)).Append('</div>'#13#10);

    B.Append('<h2>').Append(H(MHL('Файл', 'File'))).Append('</h2><table>');
    Row(MHL('Путь', 'Path'), AReport.Path);
    Row(MHL('Размер', 'Size'), FormatFloat('#,##0', AReport.Size) + MHL(' байт', ' bytes'));
    Row('SHA-256', AReport.Sha256);
    Row(MHL('Вид по содержимому', 'Type by content'), AReport.FileType.Description);
    if AReport.FileType.ExtensionMismatch then
      Row(MHL('Расширение', 'Extension'), AReport.FileType.Extension + MHL(' — не соответствует содержимому',
        ' — does not match the content'));
    Row(MHL('Подпись', 'Signature'), SignatureTitle(AReport.Signature) + IfThen(AReport.Signature.Signer <> '',
      ': ' + AReport.Signature.Signer, '') + IfThen(AReport.Signature.Error <> '', ' (' + AReport.Signature.Error + ')', ''));
    Row(MHL('Энтропия файла', 'File entropy'), Num(AReport.Entropy.Overall) + MHL(' из 8', ' of 8'));
    Row(MHL('Проанализирован', 'Analysed'), FormatDateTime('yyyy-mm-dd hh:nn:ss', AReport.AnalyzedAtUtc) + ' UTC, ' +
      IntToStr(AReport.DurationMs) + MHL(' мс', ' ms'));
    Row(MHL('Версия правил', 'Rules version'), AReport.RulesVersion);
    B.Append('</table>'#13#10);

    B.Append('<h2>').Append(H(MHL('Аномалии и признаки', 'Anomalies and signs'))).Append('</h2>');
    if Length(AReport.Anomalies) = 0 then
      B.Append('<p class="muted">').Append(H(MHL('Не обнаружено.', 'None found.'))).Append('</p>')
    else
    begin
      B.Append('<table><tr><th>').Append(H(MHL('Серьёзность', 'Severity'))).Append('</th><th>')
        .Append(H(MHL('Вес', 'Weight'))).Append('</th><th>').Append(H(MHL('Признак', 'Sign')))
        .Append('</th><th>').Append(H(MHL('Объяснение', 'Explanation'))).Append('</th></tr>');
      for LAnomaly in AReport.Anomalies do
      begin
        B.Append('<tr><td class="').Append(SeverityClass(LAnomaly.Severity)).Append('">')
          .Append(H(MHAnomalySeverityTitle(LAnomaly.Severity))).Append('</td><td>').Append(LAnomaly.Weight)
          .Append('</td><td>').Append(H(LAnomaly.Title)).Append('<br><span class="muted mono">').Append(H(LAnomaly.Code));
        if LAnomaly.Offset >= 0 then
          B.Append(' @ ').Append(H(MHHexOffset(LAnomaly.Offset)));
        B.Append('</span></td><td>').Append(H(LAnomaly.Details)).Append('</td></tr>');
      end;
      B.Append('</table>');
    end;

    if AReport.Pe.Valid then
    begin
      B.Append('<h2>').Append(H(MHL('Заголовок PE', 'PE header'))).Append('</h2><table>');
      Row(MHL('Формат', 'Format'), IfThen(AReport.Pe.Is64, 'PE32+', 'PE32') + ', ' + AReport.Pe.MachineName + ', ' +
        MHPeKindTitle(AReport.Pe.Kind) + IfThen(AReport.Pe.IsDotNet, ', .NET', ''));
      Row(MHL('Подсистема', 'Subsystem'), AReport.Pe.SubsystemName);
      Row(MHL('Точка входа', 'Entry point'), MHHexOffset(AReport.Pe.EntryPointRva) + ' (' +
        IfThen(AReport.Pe.EntryPointSection <> '', AReport.Pe.EntryPointSection, MHL('вне секций', 'outside sections')) + ')');
      Row(MHL('Базовый адрес', 'Image base'), '0x' + IntToHex(AReport.Pe.ImageBase, 8));
      Row(MHL('Время сборки (заголовок)', 'Build time (header)'),
        FormatDateTime('yyyy-mm-dd hh:nn', UnixToDateTime(AReport.Pe.TimeDateStamp, True)) + ' UTC');
      Row(MHL('Компоновщик / ОС', 'Linker / OS'), AReport.Pe.LinkerVersion + ' / ' + AReport.Pe.OsVersion);
      Row(MHL('Контрольная сумма', 'Checksum'), Format('0x%.8x / 0x%.8x', [AReport.Pe.CheckSum, AReport.Pe.ComputedCheckSum]));
      Row(MHL('Оверлей', 'Overlay'), FormatFloat('#,##0', AReport.Pe.OverlaySize) + MHL(' байт', ' bytes'));
      Row(MHL('Функций TLS', 'TLS callbacks'), IntToStr(AReport.Pe.TlsCallbackCount));
      B.Append('</table>');
      B.Append('<h2>').Append(H(MHL('Секции', 'Sections'))).Append('</h2><table><tr><th>')
        .Append(H(MHL('Имя', 'Name'))).Append('</th><th>RVA</th><th>')
        .Append(H(MHL('Размер в памяти', 'Virtual size'))).Append('</th><th>')
        .Append(H(MHL('Смещение', 'Offset'))).Append('</th><th>').Append(H(MHL('Размер в файле', 'Raw size')))
        .Append('</th><th>').Append(H(MHL('Доступ', 'Access'))).Append('</th><th>')
        .Append(H(MHL('Энтропия', 'Entropy'))).Append('</th></tr>');
      for LSection in AReport.Pe.Sections do
        B.Append('<tr><td class="mono">').Append(H(LSection.Name)).Append('</td><td class="mono">')
          .Append(H(MHHexOffset(LSection.VirtualAddress))).Append('</td><td>').Append(LSection.VirtualSize)
          .Append('</td><td class="mono">').Append(H(MHHexOffset(LSection.RawOffset))).Append('</td><td>')
          .Append(LSection.RawSize).Append('</td><td class="mono">').Append(H(LSection.AccessText))
          .Append('</td><td style="background:').Append(EntropyColorHex(Max(0.0, LSection.Entropy))).Append('33">')
          .Append(H(IfThen(LSection.Entropy >= 0, Num(LSection.Entropy), '—'))).Append('</td></tr>');
      B.Append('</table>');
      B.Append('<h2>').Append(H(Format(MHL('Импорт (%d функций)', 'Imports (%d functions)'),
        [AReport.Pe.ImportedFunctionCount]))).Append('</h2>');
      for LImport in AReport.Pe.Imports do
      begin
        B.Append('<details><summary class="mono">').Append(H(LImport.Dll));
        if LImport.Delayed then
          B.Append(H(MHL(' (отложенный)', ' (delayed)')));
        B.Append(' — ').Append(Length(LImport.Functions)).Append('</summary><div class="mono">')
          .Append(H(string.Join(', ', LImport.Functions))).Append('</div></details>');
      end;
      if Length(AReport.Pe.ExportedFunctions) > 0 then
      begin
        B.Append('<h2>').Append(H(Format(MHL('Экспорт (%d)', 'Exports (%d)'), [Length(AReport.Pe.ExportedFunctions)])))
          .Append('</h2><table><tr><th>#</th><th>').Append(H(MHL('Имя', 'Name'))).Append('</th><th>RVA</th><th>')
          .Append(H(MHL('Переадресация', 'Forwarder'))).Append('</th></tr>');
        for I := 0 to Min(High(AReport.Pe.ExportedFunctions), MH_HTML_MAX_EXPORTS - 1) do
        begin
          LExport := AReport.Pe.ExportedFunctions[I];
          B.Append('<tr><td>').Append(LExport.Ordinal).Append('</td><td class="mono">').Append(H(LExport.Name))
            .Append('</td><td class="mono">').Append(H(MHHexOffset(LExport.Rva))).Append('</td><td class="mono">')
            .Append(H(LExport.Forwarder)).Append('</td></tr>');
        end;
        B.Append('</table>');
      end;
      if Length(AReport.Pe.Resources) > 0 then
      begin
        B.Append('<h2>').Append(H(Format(MHL('Ресурсы (%d)', 'Resources (%d)'), [Length(AReport.Pe.Resources)])))
          .Append('</h2><table><tr><th>').Append(H(MHL('Тип', 'Type'))).Append('</th><th>')
          .Append(H(MHL('Имя', 'Name'))).Append('</th><th>').Append(H(MHL('Язык', 'Language'))).Append('</th><th>')
          .Append(H(MHL('Размер', 'Size'))).Append('</th><th>').Append(H(MHL('Энтропия', 'Entropy'))).Append('</th><th>')
          .Append(H(MHL('Содержимое', 'Content'))).Append('</th></tr>');
        for LResource in AReport.Pe.Resources do
          B.Append('<tr><td class="mono">').Append(H(LResource.TypeName)).Append('</td><td class="mono">')
            .Append(H(LResource.Name)).Append('</td><td>').Append(LResource.Language).Append('</td><td>')
            .Append(LResource.Size).Append('</td><td>').Append(H(IfThen(LResource.Entropy >= 0, Num(LResource.Entropy), '—')))
            .Append('</td><td>').Append(H(IfThen(LResource.ContentKind <> bkUnknown,
              MHBinaryKindTitle(LResource.ContentKind), ''))).Append('</td></tr>');
        B.Append('</table>');
      end;
      if Length(AReport.Pe.Warnings) > 0 then
      begin
        B.Append('<h2>').Append(H(MHL('Проблемы разбора', 'Parsing problems'))).Append('</h2><ul>');
        for LText in AReport.Pe.Warnings do
          B.Append('<li>').Append(H(LText)).Append('</li>');
        B.Append('</ul>');
      end;
    end;

    B.Append('<h2>').Append(H(MHL('Карта энтропии', 'Entropy map'))).Append('</h2><p class="muted">')
      .Append(H(Format(MHL('Блок %s байт; синий — заполнение и текст, зелёный — код, жёлтый — сжатые данные, ' +
        'красный — шифрованные или упакованные данные.', 'Block %s bytes; blue — padding and text, green — code, ' +
        'yellow — compressed data, red — encrypted or packed data.'), [FormatFloat('#,##0', AReport.Entropy.BlockSize)])))
      .Append('</p>').Append(EntropySvg(AReport.Entropy));
    if Length(AReport.Entropy.HighRegions) > 0 then
    begin
      B.Append('<table><tr><th>').Append(H(MHL('Область', 'Region'))).Append('</th><th>')
        .Append(H(MHL('Размер', 'Size'))).Append('</th><th>').Append(H(MHL('Энтропия', 'Entropy'))).Append('</th><th>')
        .Append(H(MHL('Где', 'Where'))).Append('</th></tr>');
      for LRegion in AReport.Entropy.HighRegions do
        B.Append('<tr><td class="mono">').Append(H(MHHexOffset(LRegion.Offset))).Append('</td><td>')
          .Append(LRegion.Size).Append('</td><td>').Append(H(Num(LRegion.AverageEntropy) + ' — ' +
            MHEntropyClassTitle(LRegion.EntropyClass))).Append('</td><td>').Append(H(LRegion.Location)).Append('</td></tr>');
      B.Append('</table>');
    end;
    B.Append('<h2>').Append(H(MHL('Распределение байтов', 'Byte distribution'))).Append('</h2>')
      .Append(HistogramSvg(AReport.Entropy));

    if Length(AReport.Embedded) > 0 then
    begin
      B.Append('<h2>').Append(H(MHL('Вложенные объекты', 'Embedded objects'))).Append('</h2><table><tr><th>')
        .Append(H(MHL('Смещение', 'Offset'))).Append('</th><th>').Append(H(MHL('Размер', 'Size'))).Append('</th><th>')
        .Append(H(MHL('Что', 'What'))).Append('</th><th>').Append(H(MHL('Где', 'Where'))).Append('</th></tr>');
      for LEmbedded in AReport.Embedded do
        B.Append('<tr><td class="mono">').Append(H(MHHexOffset(LEmbedded.Offset))).Append('</td><td>')
          .Append(H(IfThen(LEmbedded.Size >= 0, IntToStr(LEmbedded.Size), '?'))).Append('</td><td>')
          .Append(H(LEmbedded.Description)).Append('</td><td>').Append(H(LEmbedded.Location)).Append('</td></tr>');
      B.Append('</table>');
    end;

    B.Append('<h2>').Append(H(Format(MHL('Строки (найдено %d)', 'Strings (%d found)'), [AReport.Strings.TotalFound])))
      .Append('</h2><p class="muted">');
    for LCategory := Low(TMHStringCategory) to High(TMHStringCategory) do
      if AReport.Strings.CountByCategory[LCategory] > 0 then
        B.Append(H(MHStringCategoryTitle(LCategory) + ': ' + IntToStr(AReport.Strings.CountByCategory[LCategory]) + '. '));
    B.Append('</p><table><tr><th>').Append(H(MHL('Смещение', 'Offset'))).Append('</th><th>')
      .Append(H(MHL('Категория', 'Category'))).Append('</th><th>').Append(H(MHL('Строка', 'String'))).Append('</th></tr>');
    // Сначала индикаторы, затем обычные строки — в пределах лимита.
    LCount := 0;
    for LPass := 0 to 1 do
      for LString in AReport.Strings.Items do
      begin
        if (LPass = 0) = (LString.Category = scPlain) then
          Continue;
        if LCount >= MH_HTML_MAX_STRINGS then
          Break;
        Inc(LCount);
        B.Append('<tr><td class="mono">').Append(H(MHHexOffset(LString.Offset))).Append('</td><td>')
          .Append(H(MHStringCategoryTitle(LString.Category))).Append('</td><td class="mono">').Append(H(LString.Text))
          .Append('</td></tr>');
      end;
    B.Append('</table>');
    if (AReport.Strings.TotalFound > LCount) then
      B.Append('<p class="muted">').Append(H(Format(MHL('Показано %d строк; полный список — в отчёте JSON.',
        'Showing %d strings; the full list is in the JSON report.'), [LCount]))).Append('</p>');

    if (Length(AReport.Notes) > 0) or (Length(AReport.Errors) > 0) then
    begin
      B.Append('<h2>').Append(H(MHL('Замечания', 'Notes'))).Append('</h2><ul>');
      for LText in AReport.Notes do
        B.Append('<li>').Append(H(LText)).Append('</li>');
      for LText in AReport.Errors do
        B.Append('<li>').Append(H(LText)).Append('</li>');
      B.Append('</ul>');
    end;
    B.Append('<div class="disclaimer">').Append(H(MHL('BinaryLab анализирует файл без запуска (статически). Оценка — повод ' +
      'для проверки, а не диагноз: упаковку, отсутствие подписи и вложенные файлы используют и легальные программы. ' +
      'Файл не изменялся и никуда не передавался.', 'BinaryLab analyses the file without running it (statically). The ' +
      'score is a reason to check, not a diagnosis: legitimate programs also use packing, lack signatures and embed ' +
      'files. The file was not modified or sent anywhere.'))).Append('</div>'#13#10);
    B.Append('</body>'#13#10'</html>'#13#10);
    Result := B.ToString;
  finally
    B.Free;
  end;
end;

function MHBinaryDiffToHtml(const ADiff: TMHBinaryDiff): string;
var
  B: TStringBuilder;
  LItem: TMHDiffItem;
  LRange: TMHByteRange;
  LMax: Int64;
  LX, LW: Double;
  LClass: string;
begin
  B := TStringBuilder.Create;
  try
    B.Append('<!DOCTYPE html>'#13#10'<html lang="').Append(MHL('ru', 'en')).Append('">'#13#10'<head>'#13#10);
    B.Append('<meta charset="utf-8">'#13#10'<title>BinaryDiff</title>'#13#10);
    B.Append('<style>').Append(HTML_STYLE).Append('</style>'#13#10'</head>'#13#10'<body>'#13#10);
    B.Append('<h1>').Append(H('MineHunter X BinaryDiff')).Append('</h1><table>');
    B.Append('<tr><th></th><th>').Append(H(MHL('Путь', 'Path'))).Append('</th><th>').Append(H(MHL('Размер', 'Size')))
      .Append('</th><th>SHA-256</th></tr>');
    B.Append('<tr><th>A</th><td class="mono">').Append(H(ADiff.LeftPath)).Append('</td><td>').Append(ADiff.LeftSize)
      .Append('</td><td class="mono">').Append(H(ADiff.LeftSha256)).Append('</td></tr>');
    B.Append('<tr><th>B</th><td class="mono">').Append(H(ADiff.RightPath)).Append('</td><td>').Append(ADiff.RightSize)
      .Append('</td><td class="mono">').Append(H(ADiff.RightSha256)).Append('</td></tr></table>');
    if ADiff.Identical then
      B.Append('<div class="verdict lvl-low"><strong>').Append(H(MHL('Файлы идентичны.', 'The files are identical.')))
        .Append('</strong></div>')
    else
      B.Append('<div class="verdict lvl-needsReview"><strong>').Append(H(Format(MHL('Сходство %s%%, изменено %s байт, ' +
        'различий: %d.', 'Similarity %s%%, %s bytes changed, %d differences.'), [Num(ADiff.SimilarityPercent, 1),
        FormatFloat('#,##0', ADiff.ChangedBytes), Length(ADiff.Items)]))).Append('</strong></div>');
    // Полоса изменённых диапазонов.
    LMax := Max(Int64(1), Max(ADiff.LeftSize, ADiff.RightSize));
    B.Append('<svg width="800" height="24" role="img">');
    for LRange in ADiff.ChangedRanges do
    begin
      LX := LRange.Offset / LMax * 800;
      LW := Max(1.0, LRange.Size / LMax * 800);
      B.Append('<rect x="').Append(Num(LX, 1)).Append('" y="0" width="').Append(Num(LW, 1))
        .Append('" height="24" fill="#d9480f"><title>').Append(H(MHHexOffset(LRange.Offset))).Append('</title></rect>');
    end;
    B.Append('</svg>');
    B.Append('<h2>').Append(H(MHL('Различия', 'Differences'))).Append('</h2><table><tr><th>')
      .Append(H(MHL('Область', 'Area'))).Append('</th><th>').Append(H(MHL('Изменение', 'Change'))).Append('</th><th>')
      .Append(H(MHL('Элемент', 'Item'))).Append('</th><th>A</th><th>B</th></tr>');
    for LItem in ADiff.Items do
    begin
      case LItem.Change of
        dcAdded:   LClass := 'added';
        dcRemoved: LClass := 'removed';
      else
        LClass := 'changed';
      end;
      B.Append('<tr class="').Append(LClass).Append('"><td>').Append(H(MHDiffAreaTitle(LItem.Area))).Append('</td><td>')
        .Append(H(MHDiffChangeTitle(LItem.Change))).Append('</td><td class="mono">').Append(H(LItem.Name))
        .Append('</td><td class="mono">').Append(H(LItem.OldValue)).Append('</td><td class="mono">')
        .Append(H(LItem.NewValue)).Append('</td></tr>');
    end;
    B.Append('</table>');
    if ADiff.Truncated then
      B.Append('<p class="muted">').Append(H(MHL('Сравнение неполное: сработал лимит размера или числа элементов.',
        'The comparison is incomplete: a size or item limit was reached.'))).Append('</p>');
    B.Append('</body>'#13#10'</html>'#13#10);
    Result := B.ToString;
  finally
    B.Free;
  end;
end;

procedure MHSaveBinaryReport(const AReport: TMHBinaryReport; const AFileName: string);
begin
  if SameText(ExtractFileExt(AFileName), '.json') then
    MHSaveTextFile(AFileName, MHBinaryReportToJson(AReport))
  else
    MHSaveTextFile(AFileName, MHBinaryReportToHtml(AReport));
end;

procedure MHSaveBinaryDiff(const ADiff: TMHBinaryDiff; const AFileName: string);
begin
  if SameText(ExtractFileExt(AFileName), '.json') then
    MHSaveTextFile(AFileName, MHBinaryDiffToJson(ADiff))
  else
    MHSaveTextFile(AFileName, MHBinaryDiffToHtml(ADiff));
end;

initialization
  GInvariant := TFormatSettings.Invariant;

end.
