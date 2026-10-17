unit MineHunter.App.Lang;

{
  Язык интерфейса. Исходные тексты интерфейса — русские; при выбранном
  английском языке MHTr возвращает перевод из словаря (без перевода — исходный
  текст), а MHTranslateTree переводит подписи всех компонентов формы
  (Caption, Hint, TextHint, столбцы списков, элементы списков и меню,
  заголовки графиков). Язык меняется после перезапуска программы.
  Объяснения находок анализатора пока формируются только на русском.
}

interface

uses
  System.Classes, MineHunter.Core.Settings;

procedure MHSetLanguage(ALanguage: TMHUiLanguage);
function MHLanguage: TMHUiLanguage;
/// Перевод строки интерфейса на текущий язык.
function MHTr(const AText: string): string;
/// Переводит подписи всех компонентов, принадлежащих ARoot (и вложенных владельцев).
procedure MHTranslateTree(ARoot: TComponent);

implementation

uses
  System.SysUtils, System.TypInfo, System.Generics.Collections,
  Vcl.Controls, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls, Vcl.Menus, Vcl.ActnList,
  MineHunter.App.Chart;

var
  GLanguage: TMHUiLanguage = ulRussian;
  GDictionary: TDictionary<string, string>;

const
  // Пары «русский текст» → «английский текст». Ключи — без символа «&».
  TRANSLATIONS: array[0..223] of array[0..1] of string = (
    // Навигация и страницы
    ('Обзор', 'Overview'),
    ('Процессы', 'Processes'),
    ('Находки', 'Findings'),
    ('История', 'History'),
    ('Настройки', 'Settings'),
    ('Сейчас', 'Now'),
    // Верхняя панель
    ('Начать сканирование', 'Start monitoring'),
    ('Начать сканирование (F5)', 'Start monitoring (F5)'),
    ('Остановить', 'Stop'),
    ('Остановить сканирование (Shift+F5)', 'Stop monitoring (Shift+F5)'),
    ('Сканирование остановлено', 'Monitoring stopped'),
    ('■ Сканирование остановлено', '■ Monitoring stopped'),
    ('● Сканирование выполняется', '● Monitoring is running'),
    ('Проверить сейчас', 'Check now'),
    ('Проверка…', 'Checking…'),
    ('Внеочередная полная проверка (перечитываются автозапуск и признаки вмешательства) ' +
      'и понятный отчёт по её итогам.', 'Immediate full check (autostart and tampering are re-read) ' +
      'with a plain-language report.'),
    // Обзор
    ('Почему компьютер может тормозить или греться', 'Why the computer may be slow or hot'),
    ('Ожидание первого анализа…', 'Waiting for the first analysis…'),
    ('Нагрузка за последние 10 минут', 'Load over the last 10 minutes'),
    ('Нагрузка MineHunter', 'MineHunter load'),
    ('Источники данных', 'Data sources'),
    ('Журнал событий', 'Event log'),
    ('Открыть находки', 'Open findings'),
    ('Процессор', 'Processor'),
    ('Память', 'Memory'),
    ('Диск', 'Disk'),
    ('Сеть', 'Network'),
    ('Видеокарта', 'Graphics card'),
    ('Температура', 'Temperature'),
    ('Активность диска', 'Disk activity'),
    ('Чтение с диска', 'Disk reads'),
    ('Запись на диск', 'Disk writes'),
    ('Температура видеокарты', 'GPU temperature'),
    ('⚠ Требуют проверки: %d', '⚠ Need attention: %d'),
    ('✔ Признаков угроз не обнаружено', '✔ No signs of threats'),
    ('✔ Угроз не обнаружено · под наблюдением: %d', '✔ No threats · under observation: %d'),
    ('Программы работают в пределах нормы', 'Programs are within their normal range'),
    ('Источник', 'Source'),
    ('Состояние', 'State'),
    ('Время, мс', 'Time, ms'),
    ('Сообщение', 'Message'),
    ('Время', 'Time'),
    ('Уровень', 'Level'),
    ('Категория', 'Category'),
    ('Процессор:', 'Processor:'),
    ('Рабочий набор:', 'Working set:'),
    ('Обновлено:', 'Updated:'),
    ('нет данных', 'no data'),
    // Процессы
    ('Фильтр:', 'Filter:'),
    ('имя, путь или PID', 'name, path or PID'),
    ('Имя, часть пути или точный PID', 'Name, part of the path or exact PID'),
    ('Только без подписи', 'Unsigned only'),
    ('Только с находками', 'With findings only'),
    ('Показано 0 из 0', 'Shown 0 of 0'),
    ('Показано %d из %d', 'Shown %d of %d'),
    ('Подробности процесса', 'Process details'),
    ('Имя', 'Name'),
    ('Рабочий набор', 'Working set'),
    ('Частная память', 'Private memory'),
    ('Потоки', 'Threads'),
    ('Доступ', 'Access'),
    ('Подпись', 'Signature'),
    ('Путь', 'Path'),
    ('Риск', 'Risk'),
    ('система', 'system'),
    // Находки
    ('Показать:', 'Show:'),
    ('Уровень не ниже:', 'Level at least:'),
    ('Активные тревоги', 'Active alerts'),
    ('История за 7 дней', 'Last 7 days'),
    ('Активных: %d', 'Active: %d'),
    ('В истории: %d', 'In history: %d'),
    ('Оценка', 'Score'),
    ('Программа', 'Program'),
    ('Повторов', 'Repeats'),
    ('Последний раз', 'Last seen'),
    ('Подробности', 'Details'),
    ('Открыть расположение', 'Open file location'),
    ('Проверить в Defender', 'Scan with Defender'),
    ('Остановить процесс…', 'Stop process…'),
    ('Это моя программа…', 'This is my program…'),
    ('Экспорт карточки…', 'Export card…'),
    ('Экспорт отчёта…', 'Export report…'),
    ('Исправить (карантин с откатом)…', 'Fix (quarantine with rollback)…'),
    ('Нагрузка (последний час)', 'Load (last hour)'),
    ('CPU системы (час)', 'System CPU (hour)'),
    ('Microsoft Defender проверяет файл… Это может занять несколько минут.',
      'Microsoft Defender is scanning the file… This may take a few minutes.'),
    ('Для этой находки нет автоматических шагов исправления — следуйте рекомендациям.',
      'There are no automatic fix steps for this finding — follow the recommendations.'),
    ('Исправление выполнено: %d из %d шагов. Отменить можно в «Настройки → Карантин».',
      'Fix applied: %d of %d steps. You can undo it in Settings → Quarantine.'),
    ('Исправление выполнено частично: успешно %d, с ошибками %d — подробности в журнале.',
      'Fix partly applied: %d succeeded, %d failed — see the log.'),
    ('Эта программа уже есть в исключениях.', 'This program is already allowed.'),
    ('Карточка сохранена: ', 'Card saved: '),
    ('Не удалось сохранить карточку: ', 'Could not save the card: '),
    ('Отчёт сохранён: ', 'Report saved: '),
    ('Не удалось сохранить отчёт: ', 'Could not save the report: '),
    ('Не удалось прочитать сведения: ', 'Could not read the details: '),
    // История
    ('Период:', 'Period:'),
    ('Обновить', 'Refresh'),
    ('1 час', '1 hour'),
    ('6 часов', '6 hours'),
    ('24 часа', '24 hours'),
    ('7 дней', '7 days'),
    ('Загрузка…', 'Loading…'),
    ('За выбранный период данных нет', 'No data for the selected period'),
    ('Не удалось загрузить историю: ', 'Could not load history: '),
    ('История недоступна: ', 'History is unavailable: '),
    ('Перестроить норму', 'Rebuild baseline'),
    ('Показатель', 'Metric'),
    ('Сейчас (медиана / p95)', 'Now (median / p95)'),
    ('Норма (медиана / p95)', 'Normal (median / p95)'),
    ('Сейчас p95', 'Now p95'),
    ('Норма p95', 'Normal p95'),
    ('Отличие', 'Difference'),
    ('Пояснение', 'Explanation'),
    ('Профиль нормы недоступен без истории наблюдений.', 'The baseline is unavailable without history.'),
    ('Профиль нормы перестраивается в фоне. Нажмите «Обновить» через минуту.',
      'The baseline is being rebuilt in the background. Press Refresh in a minute.'),
    ('Впервые замечено', 'First seen'),
    ('Что изменилось', 'What changed'),
    ('Объект', 'Object'),
    ('Где', 'Where'),
    ('Электроэнергия: загрузка…', 'Electricity: loading…'),
    ('За 7 дней ничего нового не появилось. Наблюдение ведётся с ',
      'Nothing new in the last 7 days. Observed since '),
    // Настройки
    ('Интервал опроса:', 'Polling interval:'),
    ('История наблюдений', 'Observation history'),
    ('Хранить историю:', 'Keep history for:'),
    ('Сохранять в истории пути к файлам процессов', 'Store process file paths in history'),
    ('Очистить историю…', 'Clear history…'),
    ('Записей нет · размер файла %s', 'No records · file size %s'),
    ('Снимков: %d · размер файла %s · с %s', 'Snapshots: %d · file size %s · since %s'),
    ('История и настройки хранятся только на этом компьютере ',
      'History and settings are stored only on this computer '),
    ('История хранится только на этом компьютере. Изменения настроек действуют до перезапуска: ' +
      'сохранение настроек появится на этапе 6.', 'History is stored only on this computer.'),
    ('Анализ угроз', 'Threat analysis'),
    ('Порог высокой нагрузки процесса:', 'High process load threshold:'),
    ('Нагрузка должна длиться не меньше:', 'Load must last at least:'),
    ('Период обучения профиля нормы:', 'Baseline learning period:'),
    ('Начинать сканирование при запуске программы', 'Start monitoring when the program starts'),
    ('Обезличивать отчёты (скрывать имя пользователя и компьютера)',
      'Anonymize reports (hide user and computer names)'),
    ('Разрешённые программы (исключения)', 'Allowed programs (exclusions)'),
    ('Удалить из исключений…', 'Remove from exclusions…'),
    ('Добавлено', 'Added'),
    ('Файл:', 'File:'),
    ('любой файл по этому пути', 'any file at this path'),
    ('Журнал действий', 'Action log'),
    ('Действие', 'Action'),
    ('Результат', 'Result'),
    ('Вывод', 'Output'),
    ('Настройки применены, но не сохранены: ', 'Settings applied but not saved: '),
    ('Карантин и откат исправлений', 'Quarantine and rollback'),
    ('Карантин и откат исправлений — пусто', 'Quarantine and rollback — empty'),
    ('Карантин и откат исправлений — %d', 'Quarantine and rollback — %d'),
    ('Когда', 'When'),
    ('Тип', 'Type'),
    ('Причина', 'Reason'),
    ('Восстановить', 'Restore'),
    ('Удалить навсегда…', 'Delete permanently…'),
    ('Работа в фоне и уведомления', 'Background mode and notifications'),
    ('Сворачивать и закрывать в область уведомлений (значок у часов)',
      'Minimize and close to the notification area (icon near the clock)'),
    ('Уведомлять о новых тревогах (уровень «подозрительно» и выше)',
      'Notify about new alerts (level "suspicious" and above)'),
    ('Экономный режим: пока окно скрыто, опрос раз в %d с',
      'Economy mode: while the window is hidden, poll every %d s'),
    ('Запускать MineHunter X вместе с Windows (свёрнутым)', 'Start MineHunter X with Windows (minimized)'),
    ('Выключено.', 'Off.'),
    ('Включено: ', 'On: '),
    ('Цена электроэнергии, ₽ за кВт·ч:', 'Electricity price per kWh:'),
    ('Используется для оценки стоимости работы видеокарты (и скрытого майнера на ней).',
      'Used to estimate the cost of running the graphics card (and a hidden miner on it).'),
    ('Внешний вид и обновления', 'Appearance and updates'),
    ('Язык интерфейса:', 'Interface language:'),
    ('Тема:', 'Theme:'),
    ('Светлая', 'Light'),
    ('Тёмная', 'Dark'),
    ('Проверять новые версии на GitHub (раз в сутки)', 'Check GitHub for new versions (once a day)'),
    ('Проверить обновления', 'Check for updates'),
    ('Экспорт настроек…', 'Export settings…'),
    ('Импорт настроек…', 'Import settings…'),
    ('Язык изменится после перезапуска MineHunter X.', 'The language will change after MineHunter X restarts.'),
    ('Проверка обновлений выключена.', 'Update check is off.'),
    // Трей и окна
    ('Открыть MineHunter X', 'Open MineHunter X'),
    ('Выход', 'Exit'),
    ('MineHunter X работает в фоне', 'MineHunter X is running in the background'),
    ('Наблюдение продолжается. Откройте окно щелчком по значку; выход — в меню значка.',
      'Monitoring continues. Click the icon to open the window; exit is in the icon menu.'),
    ('MineHunter X — наблюдение остановлено', 'MineHunter X — monitoring stopped'),
    ('MineHunter X — угроз не обнаружено', 'MineHunter X — no threats'),
    ('MineHunter X — требуют проверки: %d', 'MineHunter X — need attention: %d'),
    ('MineHunter X — результат проверки', 'MineHunter X — check result'),
    ('MineHunter X: проверка завершена', 'MineHunter X: check completed'),
    ('Сохранить подробный отчёт…', 'Save detailed report…'),
    ('Закрыть', 'Close'),
    // Состояния источников и уровни риска
    ('не опрашивался', 'not polled'),
    ('успешно', 'ok'),
    ('частично', 'partial'),
    ('недоступен', 'unavailable'),
    ('ошибка', 'error'),
    ('нет признаков', 'no signs'),
    ('слабые признаки', 'weak signs'),
    ('требует проверки', 'needs review'),
    ('подозрительно', 'suspicious'),
    ('высокая степень подозрения', 'highly suspicious'),
    ('Угроз не обнаружено', 'No threats found'),
    // Ячейки и подсказки
    ('Сейчас:', 'Now:'),
    ('Нагрузка', 'Load'),
    ('Объём', 'Size'),
    ('Скорость', 'Rate'),
    ('свободно', 'free'),
    ('занято', 'used'),
    ('чтение', 'read'),
    ('запись', 'write'),
    ('вычисления', 'compute'),
    ('видеопамять', 'video memory'),
    ('Норма', 'Normal'),
    ('Выше нормы', 'Above normal'),
    ('Ниже нормы', 'Below normal'),
    ('Нет данных', 'No data'),
    ('Да', 'Yes'),
    ('Нет', 'No'),
    ('норма', 'normal'),
    ('внимание', 'attention'),
    ('высокая', 'high'),
    ('успех', 'ok'),
    ('недоступно', 'unavailable'),
    ('Снимок №%d в %s · процессов: %d', 'Snapshot #%d at %s · processes: %d'),
    ('Объяснение и безопасные действия — в «Находках». ', 'Explanations and safe actions are on the Findings page. '),
    ('Без прав администратора часть процессов видна не полностью.',
      'Without administrator rights some processes are only partly visible.'),
    ('Все доступные процессы анализируются.', 'All accessible processes are analyzed.'),
    (' Недоступно: ', ' Unavailable: '),
    (' (подробности ниже).', ' (details below).'),
    ('Что изменилось за 7 дней', 'What changed in the last 7 days')
  );

procedure EnsureDictionary;
var
  I: Integer;
begin
  if GDictionary <> nil then
    Exit;
  GDictionary := TDictionary<string, string>.Create(Length(TRANSLATIONS));
  for I := Low(TRANSLATIONS) to High(TRANSLATIONS) do
    GDictionary.AddOrSetValue(TRANSLATIONS[I][0], TRANSLATIONS[I][1]);
end;

procedure MHSetLanguage(ALanguage: TMHUiLanguage);
begin
  GLanguage := ALanguage;
end;

function MHLanguage: TMHUiLanguage;
begin
  Result := GLanguage;
end;

function MHTr(const AText: string): string;
var
  LKey: string;
begin
  if (GLanguage = ulRussian) or (AText = '') then
    Exit(AText);
  EnsureDictionary;
  if GDictionary.TryGetValue(AText, Result) then
    Exit;
  // Клавиши-ускорители («&Обновить») в переводе не сохраняются.
  LKey := AText.Replace('&', '');
  if not GDictionary.TryGetValue(LKey, Result) then
    Result := AText;
end;

procedure TranslateStrProp(AComponent: TComponent; const AName: string);
var
  LProp: PPropInfo;
  LValue: string;
begin
  LProp := GetPropInfo(AComponent, AName);
  if (LProp = nil) or (LProp.PropType^.Kind <> tkUString) or (LProp.SetProc = nil) then
    Exit;
  LValue := GetStrProp(AComponent, LProp);
  if LValue <> '' then
    SetStrProp(AComponent, LProp, MHTr(LValue));
end;

procedure TranslateStrings(AStrings: TStrings);
var
  I: Integer;
begin
  AStrings.BeginUpdate;
  try
    for I := 0 to AStrings.Count - 1 do
      AStrings[I] := MHTr(AStrings[I]);
  finally
    AStrings.EndUpdate;
  end;
end;

procedure TranslateComponent(AComponent: TComponent);
var
  I, LIndex: Integer;
begin
  TranslateStrProp(AComponent, 'Caption');
  TranslateStrProp(AComponent, 'Hint');
  TranslateStrProp(AComponent, 'TextHint');
  if AComponent is TListView then
    for I := 0 to TListView(AComponent).Columns.Count - 1 do
      TListView(AComponent).Columns[I].Caption := MHTr(TListView(AComponent).Columns[I].Caption)
  else if AComponent is TComboBox then
  begin
    LIndex := TComboBox(AComponent).ItemIndex;
    TranslateStrings(TComboBox(AComponent).Items);
    TComboBox(AComponent).ItemIndex := LIndex;
  end
  else if AComponent is TListBox then
  begin
    LIndex := TListBox(AComponent).ItemIndex;
    TranslateStrings(TListBox(AComponent).Items);
    TListBox(AComponent).ItemIndex := LIndex;
  end
  else if AComponent is TMHLineChart then
    TMHLineChart(AComponent).Title := MHTr(TMHLineChart(AComponent).Title)
  else if AComponent is TTrayIcon then
    TTrayIcon(AComponent).Hint := MHTr(TTrayIcon(AComponent).Hint);
end;

procedure MHTranslateTree(ARoot: TComponent);
var
  I: Integer;
begin
  if (ARoot = nil) or (GLanguage = ulRussian) then
    Exit;
  TranslateComponent(ARoot);
  for I := 0 to ARoot.ComponentCount - 1 do
  begin
    TranslateComponent(ARoot.Components[I]);
    if ARoot.Components[I].ComponentCount > 0 then
      MHTranslateTree(ARoot.Components[I]);
  end;
end;

initialization

finalization
  FreeAndNil(GDictionary);

end.
