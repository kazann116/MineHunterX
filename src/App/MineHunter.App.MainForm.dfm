object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 'MineHunter X'
  ClientHeight = 820
  ClientWidth = 1240
  Color = clBtnFace
  Constraints.MinHeight = 600
  Constraints.MinWidth = 760
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  ShowHint = True
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 15
  object pnlTop: TPanel
    Left = 0
    Top = 0
    Width = 1000
    Height = 44
    Align = alTop
    BevelOuter = bvNone
    TabOrder = 0
    object lblScanState: TLabel
      Left = 300
      Top = 14
      Width = 160
      Height = 15
      Caption = #1057#1082#1072#1085#1080#1088#1086#1074#1072#1085#1080#1077' '#1086#1089#1090#1072#1085#1086#1074#1083#1077#1085#1086
    end
    object btnStart: TButton
      Left = 8
      Top = 8
      Width = 140
      Height = 28
      Action = actStart
      TabOrder = 0
    end
    object btnStop: TButton
      Left = 154
      Top = 8
      Width = 130
      Height = 28
      Action = actStop
      TabOrder = 1
    end
  end
  object lbNav: TListBox
    Left = 0
    Top = 44
    Width = 170
    Height = 753
    Align = alLeft
    ItemHeight = 28
    Style = lbOwnerDrawFixed
    TabOrder = 1
    OnClick = lbNavClick
  end
  object pcMain: TPageControl
    Left = 170
    Top = 44
    Width = 830
    Height = 753
    ActivePage = tsDashboard
    Align = alClient
    TabOrder = 2
    object tsDashboard: TTabSheet
      Caption = #1054#1073#1079#1086#1088
      object sbDashboard: TScrollBox
        Left = 0
        Top = 0
        Width = 822
        Height = 814
        HorzScrollBar.Visible = False
        VertScrollBar.Tracking = True
        Align = alClient
        BorderStyle = bsNone
        TabOrder = 0
        object pnlStatus: TPanel
          AlignWithMargins = True
          Left = 8
          Top = 8
          Width = 806
          Height = 76
          Margins.Left = 8
          Margins.Top = 8
          Margins.Right = 8
          Margins.Bottom = 4
          Align = alTop
          BevelOuter = bvNone
          ParentBackground = False
          TabOrder = 0
          DesignSize = (
            806
            76)
          object lblAlerts: TLabel
            Left = 18
            Top = 12
            Width = 600
            Height = 25
            Anchors = [akLeft, akTop, akRight]
            AutoSize = False
            Caption = #1054#1078#1080#1076#1072#1085#1080#1077' '#1087#1077#1088#1074#1086#1075#1086' '#1072#1085#1072#1083#1080#1079#1072#8230
            Font.Charset = DEFAULT_CHARSET
            Font.Color = clWindowText
            Font.Height = -19
            Font.Name = 'Segoe UI'
            Font.Style = [fsBold]
            ParentFont = False
          end
          object lblRights: TLabel
            Left = 18
            Top = 44
            Width = 600
            Height = 20
            Anchors = [akLeft, akTop, akRight]
            AutoSize = False
            Caption = ''
            EllipsisPosition = epEndEllipsis
          end
          object btnGoFindings: TButton
            Left = 636
            Top = 22
            Width = 155
            Height = 32
            Anchors = [akTop, akRight]
            Caption = #1054#1090#1082#1088#1099#1090#1100' &'#1085#1072#1093#1086#1076#1082#1080
            TabOrder = 0
            OnClick = btnGoFindingsClick
          end
        end
        object lblNowCaption: TLabel
          AlignWithMargins = True
          Left = 10
          Top = 92
          Width = 802
          Height = 20
          Margins.Left = 10
          Margins.Top = 6
          Margins.Right = 10
          Margins.Bottom = 2
          Align = alTop
          Caption = #1057#1077#1081#1095#1072#1089
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -15
          Font.Name = 'Segoe UI'
          Font.Style = [fsBold]
          ParentFont = False
        end
        object pnlTiles: TPanel
          AlignWithMargins = True
          Left = 8
          Top = 118
          Width = 806
          Height = 118
          Margins.Left = 8
          Margins.Top = 2
          Margins.Right = 8
          Align = alTop
          BevelOuter = bvNone
          TabOrder = 1
          OnResize = pnlTilesResize
        end
        object lblChartsCaption: TLabel
          AlignWithMargins = True
          Left = 10
          Top = 230
          Width = 802
          Height = 20
          Margins.Left = 10
          Margins.Top = 6
          Margins.Right = 10
          Margins.Bottom = 2
          Align = alTop
          Caption = #1053#1072#1075#1088#1091#1079#1082#1072' '#1079#1072' '#1087#1086#1089#1083#1077#1076#1085#1080#1077' 10 '#1084#1080#1085#1091#1090
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -15
          Font.Name = 'Segoe UI'
          Font.Style = [fsBold]
          ParentFont = False
        end
        object pnlLiveCharts: TPanel
          AlignWithMargins = True
          Left = 8
          Top = 256
          Width = 806
          Height = 150
          Margins.Left = 2
          Margins.Top = 2
          Margins.Right = 2
          Align = alTop
          BevelOuter = bvNone
          TabOrder = 2
          OnResize = pnlLiveChartsResize
        end
        object lblWhySlow: TLabel
          AlignWithMargins = True
          Left = 10
          Top = 414
          Width = 802
          Height = 20
          Margins.Left = 10
          Margins.Top = 8
          Margins.Right = 10
          Margins.Bottom = 2
          Align = alTop
          Caption = #1055#1086#1095#1077#1084#1091' '#1082#1086#1084#1087#1100#1102#1090#1077#1088' '#1084#1086#1078#1077#1090' '#1090#1086#1088#1084#1086#1079#1080#1090#1100' '#1080#1083#1080' '#1075#1088#1077#1090#1100#1089#1103
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -15
          Font.Name = 'Segoe UI'
          Font.Style = [fsBold]
          ParentFont = False
        end
        object pnlReasons: TPanel
          AlignWithMargins = True
          Left = 8
          Top = 440
          Width = 806
          Height = 60
          Margins.Left = 8
          Margins.Top = 2
          Margins.Right = 8
          Align = alTop
          AutoSize = True
          BevelOuter = bvNone
          TabOrder = 3
        end
        object lblDetailsCaption: TLabel
          AlignWithMargins = True
          Left = 10
          Top = 508
          Width = 802
          Height = 20
          Margins.Left = 10
          Margins.Top = 8
          Margins.Right = 10
          Margins.Bottom = 2
          Align = alTop
          Caption = #1055#1086#1076#1088#1086#1073#1085#1086#1089#1090#1080
          Font.Charset = DEFAULT_CHARSET
          Font.Color = clWindowText
          Font.Height = -15
          Font.Name = 'Segoe UI'
          Font.Style = [fsBold]
          ParentFont = False
        end
        object pcDetails: TPageControl
          AlignWithMargins = True
          Left = 8
          Top = 534
          Width = 806
          Height = 230
          Margins.Left = 8
          Margins.Top = 2
          Margins.Right = 8
          Margins.Bottom = 8
          ActivePage = tsDetailSources
          Align = alTop
          TabOrder = 4
          object tsDetailSources: TTabSheet
            Caption = #1048#1089#1090#1086#1095#1085#1080#1082#1080' '#1076#1072#1085#1085#1099#1093
            object lvSources: TListView
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 792
              Height = 194
              Align = alClient
              Columns = <
                item
                  Caption = #1048#1089#1090#1086#1095#1085#1080#1082
                  Width = 140
                end
                item
                  Caption = #1057#1086#1089#1090#1086#1103#1085#1080#1077
                  Width = 130
                end
                item
                  Caption = #1042#1088#1077#1084#1103', '#1084#1089
                  Width = 80
                end
                item
                  Caption = #1055#1086#1103#1089#1085#1077#1085#1080#1077
                  Width = 420
                end>
              ReadOnly = True
              RowSelect = True
              TabOrder = 0
              ViewStyle = vsReport
            end
          end
          object tsDetailEvents: TTabSheet
            Caption = #1046#1091#1088#1085#1072#1083' '#1089#1086#1073#1099#1090#1080#1081
            ImageIndex = 1
            object lvEvents: TListView
              AlignWithMargins = True
              Left = 3
              Top = 3
              Width = 792
              Height = 194
              Align = alClient
              Columns = <
                item
                  Caption = #1042#1088#1077#1084#1103
                  Width = 80
                end
                item
                  Caption = #1059#1088#1086#1074#1077#1085#1100
                  Width = 80
                end
                item
                  Caption = #1048#1089#1090#1086#1095#1085#1080#1082
                  Width = 100
                end
                item
                  Caption = #1057#1086#1086#1073#1097#1077#1085#1080#1077
                  Width = 500
                end>
              ReadOnly = True
              RowSelect = True
              TabOrder = 0
              ViewStyle = vsReport
            end
          end
          object tsDetailSelf: TTabSheet
            Caption = #1053#1072#1075#1088#1091#1079#1082#1072' MineHunter'
            ImageIndex = 2
            object lblSelfCpuCaption: TLabel
              Left = 16
              Top = 16
              Width = 70
              Height = 15
              Caption = #1055#1088#1086#1094#1077#1089#1089#1086#1088':'
            end
            object lblSelfCpu: TLabel
              Left = 120
              Top = 16
              Width = 64
              Height = 15
              Caption = #1085#1077#1090' '#1076#1072#1085#1085#1099#1093
            end
            object lblSelfMemCaption: TLabel
              Left = 16
              Top = 40
              Width = 90
              Height = 15
              Caption = #1056#1072#1073#1086#1095#1080#1081' '#1085#1072#1073#1086#1088':'
            end
            object lblSelfMem: TLabel
              Left = 120
              Top = 40
              Width = 64
              Height = 15
              Caption = #1085#1077#1090' '#1076#1072#1085#1085#1099#1093
            end
            object lblSelfUpdatedCaption: TLabel
              Left = 16
              Top = 64
              Width = 70
              Height = 15
              Caption = #1054#1073#1085#1086#1074#1083#1077#1085#1086':'
            end
            object lblSelfUpdated: TLabel
              Left = 120
              Top = 64
              Width = 64
              Height = 15
              Caption = #1085#1077#1090' '#1076#1072#1085#1085#1099#1093
            end
          end
        end
      end
    end
    object tsProcesses: TTabSheet
      Caption = #1055#1088#1086#1094#1077#1089#1089#1099
      ImageIndex = 1
      object pnlProcFilter: TPanel
        Left = 0
        Top = 0
        Width = 822
        Height = 36
        Align = alTop
        BevelOuter = bvNone
        TabOrder = 0
        object lblProcFilter: TLabel
          Left = 8
          Top = 10
          Width = 44
          Height = 15
          Caption = '&'#1060#1080#1083#1100#1090#1088':'
          FocusControl = edProcFilter
        end
        object lblProcCount: TLabel
          Left = 330
          Top = 10
          Width = 100
          Height = 15
          Caption = #1055#1086#1082#1072#1079#1072#1085#1086' 0 '#1080#1079' 0'
        end
        object chkOnlyFindings: TCheckBox
          Left = 470
          Top = 9
          Width = 150
          Height = 19
          Caption = #1058#1086#1083#1100#1082#1086' '#1089' &'#1085#1072#1093#1086#1076#1082#1072#1084#1080
          TabOrder = 1
          OnClick = chkOnlyFindingsClick
        end
        object chkOnlyUnsigned: TCheckBox
          Left = 630
          Top = 9
          Width = 160
          Height = 19
          Caption = #1058#1086#1083#1100#1082#1086' &'#1073#1077#1079' '#1087#1086#1076#1087#1080#1089#1080
          TabOrder = 2
          OnClick = chkOnlyUnsignedClick
        end
        object edProcFilter: TEdit
          Left = 70
          Top = 6
          Width = 240
          Height = 23
          Hint = #1048#1084#1103', '#1095#1072#1089#1090#1100' '#1087#1091#1090#1080' '#1080#1083#1080' '#1090#1086#1095#1085#1099#1081' PID'
          TabOrder = 0
          TextHint = #1080#1084#1103', '#1087#1091#1090#1100' '#1080#1083#1080' PID'
          OnChange = edProcFilterChange
        end
      end
      object lvProcesses: TListView
        Left = 0
        Top = 36
        Width = 822
        Height = 357
        Align = alClient
        Columns = <
          item
            Caption = #1048#1084#1103
            Width = 170
          end
          item
            Alignment = taRightJustify
            Caption = 'PID'
            Width = 60
          end
          item
            Alignment = taRightJustify
            Caption = 'CPU'
            Width = 70
          end
          item
            Alignment = taRightJustify
            Caption = #1055#1072#1084#1103#1090#1100
            Width = 90
          end
          item
            Alignment = taRightJustify
            Caption = 'GPU'
            Width = 60
          end
          item
            Alignment = taRightJustify
            Caption = #1056#1072#1073#1086#1095#1080#1081' '#1085#1072#1073#1086#1088
            Width = 100
          end
          item
            Alignment = taRightJustify
            Caption = #1063#1072#1089#1090#1085#1072#1103' '#1087#1072#1084#1103#1090#1100
            Width = 105
          end
          item
            Alignment = taRightJustify
            Caption = #1055#1086#1090#1086#1082#1080
            Width = 60
          end
          item
            Caption = #1044#1086#1089#1090#1091#1087
            Width = 85
          end
          item
            Caption = #1055#1091#1090#1100
            Width = 200
          end
          item
            Caption = #1056#1080#1089#1082
            Width = 130
          end
          item
            Caption = #1055#1086#1076#1087#1080#1089#1100
            Width = 170
          end>
        HideSelection = False
        OwnerData = True
        ReadOnly = True
        RowSelect = True
        TabOrder = 1
        ViewStyle = vsReport
        OnColumnClick = lvProcessesColumnClick
        OnData = lvProcessesData
        OnSelectItem = lvProcessesSelectItem
      end
      object splProcDetails: TSplitter
        Left = 0
        Top = 393
        Width = 822
        Height = 4
        Cursor = crVSplit
        Align = alBottom
      end
      object gbProcDetails: TGroupBox
        AlignWithMargins = True
        Left = 3
        Top = 400
        Width = 816
        Height = 140
        Align = alBottom
        Caption = #1055#1086#1076#1088#1086#1073#1085#1086#1089#1090#1080' '#1087#1088#1086#1094#1077#1089#1089#1072
        TabOrder = 2
        object mmProcDetails: TMemo
          AlignWithMargins = True
          Left = 5
          Top = 20
          Width = 806
          Height = 115
          Align = alClient
          BorderStyle = bsNone
          ParentColor = True
          ReadOnly = True
          ScrollBars = ssVertical
          TabOrder = 0
        end
      end
    end
    object tsFindings: TTabSheet
      Caption = #1053#1072#1093#1086#1076#1082#1080
      ImageIndex = 2
      object pnlFindingsTop: TPanel
        Left = 0
        Top = 0
        Width = 822
        Height = 40
        Align = alTop
        BevelOuter = bvNone
        TabOrder = 0
        object lblFindingsMode: TLabel
          Left = 8
          Top = 12
          Width = 56
          Height = 15
          Caption = '&'#1055#1086#1082#1072#1079#1072#1090#1100':'
          FocusControl = cbFindingsMode
        end
        object lblFindingsMinLevel: TLabel
          Left = 250
          Top = 12
          Width = 95
          Height = 15
          Caption = '&'#1059#1088#1086#1074#1077#1085#1100' '#1085#1077' '#1085#1080#1078#1077':'
          FocusControl = cbFindingsMinLevel
        end
        object lblFindingsCount: TLabel
          Left = 540
          Top = 12
          Width = 120
          Height = 15
          Caption = ''
        end
        object cbFindingsMode: TComboBox
          Left = 70
          Top = 8
          Width = 170
          Height = 23
          Style = csDropDownList
          TabOrder = 0
          OnChange = cbFindingsModeChange
        end
        object cbFindingsMinLevel: TComboBox
          Left = 352
          Top = 8
          Width = 180
          Height = 23
          Style = csDropDownList
          TabOrder = 1
          OnChange = cbFindingsMinLevelChange
        end
        object btnExportReport: TButton
          Left = 680
          Top = 7
          Width = 135
          Height = 27
          Anchors = [akTop, akRight]
          Caption = '&'#1069#1082#1089#1087#1086#1088#1090' '#1086#1090#1095#1105#1090#1072#8230
          TabOrder = 2
          OnClick = btnExportReportClick
        end
      end
      object lvFindings: TListView
        Left = 0
        Top = 40
        Width = 822
        Height = 200
        Align = alTop
        Columns = <
          item
            Caption = #1059#1088#1086#1074#1077#1085#1100
            Width = 170
          end
          item
            Alignment = taRightJustify
            Caption = #1054#1094#1077#1085#1082#1072
            Width = 60
          end
          item
            Caption = #1050#1072#1090#1077#1075#1086#1088#1080#1103
            Width = 170
          end
          item
            Caption = #1054#1073#1098#1077#1082#1090
            Width = 230
          end
          item
            Caption = #1055#1086#1089#1083#1077#1076#1085#1080#1081' '#1088#1072#1079
            Width = 95
          end
          item
            Alignment = taRightJustify
            Caption = #1055#1086#1074#1090#1086#1088#1086#1074
            Width = 70
          end>
        HideSelection = False
        OwnerData = True
        ReadOnly = True
        RowSelect = True
        TabOrder = 1
        ViewStyle = vsReport
        OnData = lvFindingsData
        OnSelectItem = lvFindingsSelectItem
      end
      object splFindings: TSplitter
        Left = 0
        Top = 240
        Width = 822
        Height = 4
        Cursor = crVSplit
        Align = alTop
      end
      object pnlCard: TPanel
        Left = 0
        Top = 244
        Width = 822
        Height = 449
        Align = alClient
        BevelOuter = bvNone
        TabOrder = 2
        object pnlCardButtons: TPanel
          Left = 0
          Top = 380
          Width = 822
          Height = 69
          Align = alBottom
          BevelOuter = bvNone
          TabOrder = 0
          object lblCardStatus: TLabel
            Left = 8
            Top = 4
            Width = 806
            Height = 15
            Anchors = [akLeft, akTop, akRight]
            AutoSize = False
            Caption = ''
            ShowAccelChar = False
          end
          object btnOpenLocation: TButton
            Left = 8
            Top = 28
            Width = 160
            Height = 30
            Caption = #1054#1090#1082#1088#1099#1090#1100' &'#1088#1072#1089#1087#1086#1083#1086#1078#1077#1085#1080#1077
            TabOrder = 0
            OnClick = btnOpenLocationClick
          end
          object btnDefender: TButton
            Left = 174
            Top = 28
            Width = 160
            Height = 30
            Caption = #1055#1088#1086#1074#1077#1088#1080#1090#1100' '#1074' &Defender'
            TabOrder = 1
            OnClick = btnDefenderClick
          end
          object btnStopProcess: TButton
            Left = 340
            Top = 28
            Width = 150
            Height = 30
            Caption = '&'#1054#1089#1090#1072#1085#1086#1074#1080#1090#1100' '#1087#1088#1086#1094#1077#1089#1089#8230
            TabOrder = 2
            OnClick = btnStopProcessClick
          end
          object btnAllow: TButton
            Left = 496
            Top = 28
            Width = 165
            Height = 30
            Caption = #1069#1090#1086' '#1084#1086#1103' &'#1087#1088#1086#1075#1088#1072#1084#1084#1072#8230
            TabOrder = 3
            OnClick = btnAllowClick
          end
          object btnExportCard: TButton
            Left = 667
            Top = 28
            Width = 147
            Height = 30
            Caption = #1069#1082#1089#1087#1086#1088#1090' &'#1082#1072#1088#1090#1086#1095#1082#1080#8230
            TabOrder = 4
            OnClick = btnExportCardClick
          end
        end
        object pnlCardChart: TPanel
          Left = 502
          Top = 0
          Width = 320
          Height = 380
          Align = alRight
          BevelOuter = bvNone
          TabOrder = 1
          OnResize = pnlCardChartResize
        end
        object mmCard: TMemo
          AlignWithMargins = True
          Left = 3
          Top = 3
          Width = 496
          Height = 374
          Align = alClient
          ReadOnly = True
          ScrollBars = ssVertical
          TabOrder = 2
        end
      end
    end
    object tsHistory: TTabSheet
      Caption = #1048#1089#1090#1086#1088#1080#1103
      ImageIndex = 3
      object pnlHistoryTop: TPanel
        Left = 0
        Top = 0
        Width = 822
        Height = 40
        Align = alTop
        BevelOuter = bvNone
        TabOrder = 0
        object lblHistoryPeriod: TLabel
          Left = 8
          Top = 12
          Width = 46
          Height = 15
          Caption = '&'#1055#1077#1088#1080#1086#1076':'
          FocusControl = cbHistoryPeriod
        end
        object lblHistoryStatus: TLabel
          Left = 330
          Top = 12
          Width = 400
          Height = 15
          AutoSize = False
          Caption = ''
        end
        object cbHistoryPeriod: TComboBox
          Left = 70
          Top = 8
          Width = 130
          Height = 23
          Style = csDropDownList
          TabOrder = 0
          OnChange = cbHistoryPeriodChange
        end
        object btnHistoryRefresh: TButton
          Left = 210
          Top = 7
          Width = 105
          Height = 25
          Caption = '&'#1054#1073#1085#1086#1074#1080#1090#1100
          TabOrder = 1
          OnClick = btnHistoryRefreshClick
        end
      end
      object pnlBaseline: TPanel
        Left = 0
        Top = 473
        Width = 822
        Height = 220
        Align = alBottom
        BevelOuter = bvNone
        TabOrder = 2
        object lblBaselineInfo: TLabel
          Left = 8
          Top = 6
          Width = 650
          Height = 30
          Anchors = [akLeft, akTop, akRight]
          AutoSize = False
          Caption = ''
          WordWrap = True
        end
        object btnRebuildBaseline: TButton
          Left = 664
          Top = 6
          Width = 150
          Height = 27
          Anchors = [akTop, akRight]
          Caption = #1055#1077#1088#1077#1089#1090#1088#1086#1080#1090#1100' &'#1085#1086#1088#1084#1091
          TabOrder = 0
          OnClick = btnRebuildBaselineClick
        end
        object lvComparison: TListView
          Left = 8
          Top = 40
          Width = 806
          Height = 84
          Anchors = [akLeft, akTop, akRight]
          Columns = <
            item
              Caption = #1055#1086#1082#1072#1079#1072#1090#1077#1083#1100
              Width = 130
            end
            item
              Caption = #1057#1077#1081#1095#1072#1089' ('#1084#1077#1076#1080#1072#1085#1072' / p95)'
              Width = 170
            end
            item
              Caption = #1053#1086#1088#1084#1072' ('#1084#1077#1076#1080#1072#1085#1072' / p95)'
              Width = 170
            end
            item
              Caption = #1042#1099#1074#1086#1076
              Width = 300
            end>
          ReadOnly = True
          RowSelect = True
          TabOrder = 1
          ViewStyle = vsReport
        end
        object lvDeviations: TListView
          Left = 8
          Top = 128
          Width = 806
          Height = 88
          Anchors = [akLeft, akTop, akRight, akBottom]
          Columns = <
            item
              Caption = #1055#1088#1086#1075#1088#1072#1084#1084#1072
              Width = 200
            end
            item
              Caption = #1057#1077#1081#1095#1072#1089' p95'
              Width = 90
            end
            item
              Caption = #1053#1086#1088#1084#1072' p95'
              Width = 90
            end
            item
              Caption = #1054#1090#1083#1080#1095#1080#1077
              Width = 400
            end>
          ReadOnly = True
          RowSelect = True
          TabOrder = 2
          ViewStyle = vsReport
        end
      end
      object pnlHistoryCharts: TPanel
        Left = 0
        Top = 40
        Width = 822
        Height = 500
        Align = alClient
        BevelOuter = bvNone
        TabOrder = 1
        OnResize = pnlHistoryChartsResize
      end
    end
    object tsSettings: TTabSheet
      Caption = #1053#1072#1089#1090#1088#1086#1081#1082#1080
      ImageIndex = 4
      object sbSettings: TScrollBox
        Left = 0
        Top = 0
        Width = 822
        Height = 693
        VertScrollBar.Tracking = True
        Align = alClient
        BorderStyle = bsNone
        TabOrder = 0
        object lblInterval: TLabel
          Left = 16
          Top = 20
          Width = 140
          Height = 15
          Caption = '&'#1048#1085#1090#1077#1088#1074#1072#1083' '#1086#1087#1088#1086#1089#1072':'
          FocusControl = cbInterval
        end
        object lblPrivacy: TLabel
          Left = 16
          Top = 64
          Width = 600
          Height = 30
          AutoSize = False
          Caption =
            #1040#1085#1072#1083#1080#1079' '#1074#1099#1087#1086#1083#1085#1103#1077#1090#1089#1103' '#1083#1086#1082#1072#1083#1100#1085#1086'. MineHunter X '#1085#1077' '#1087#1077#1088#1077#1076#1072#1105#1090' '#1076#1072#1085#1085#1099#1077' '#1074' '#1089 +
            #1077#1090#1100'.'
          WordWrap = True
        end
        object cbInterval: TComboBox
          Left = 170
          Top = 16
          Width = 120
          Height = 23
          Style = csDropDownList
          TabOrder = 0
          OnChange = cbIntervalChange
        end
        object gbStorage: TGroupBox
          Left = 16
          Top = 104
          Width = 680
          Height = 230
          Caption = #1048#1089#1090#1086#1088#1080#1103' '#1085#1072#1073#1083#1102#1076#1077#1085#1080#1081
          TabOrder = 1
          object lblStoragePathCaption: TLabel
            Left = 16
            Top = 26
            Width = 40
            Height = 15
            Caption = #1060#1072#1081#1083':'
          end
          object lblStoragePath: TLabel
            Left = 160
            Top = 26
            Width = 500
            Height = 15
            AutoSize = False
            Caption = ''
            ShowAccelChar = False
          end
          object lblStorageStats: TLabel
            Left = 16
            Top = 50
            Width = 640
            Height = 15
            AutoSize = False
            Caption = ''
          end
          object lblRetention: TLabel
            Left = 16
            Top = 82
            Width = 120
            Height = 15
            Caption = '&'#1061#1088#1072#1085#1080#1090#1100' '#1080#1089#1090#1086#1088#1080#1102':'
            FocusControl = cbRetention
          end
          object lblStorageNote: TLabel
            Left = 16
            Top = 176
            Width = 640
            Height = 45
            AutoSize = False
            Caption = #1048#1089#1090#1086#1088#1080#1103' '#1093#1088#1072#1085#1080#1090#1089#1103' '#1090#1086#1083#1100#1082#1086' '#1085#1072' '#1101#1090#1086#1084' '#1082#1086#1084#1087#1100#1102#1090#1077#1088#1077'. '#1048#1079#1084#1077#1085#1077#1085#1080#1103' '#1085#1072#1089#1090#1088#1086#1077#1082' '#1076#1077#1081#1089#1090#1074#1091#1102#1090' '#1076#1086' '#1087#1077#1088#1077#1079#1072#1087#1091#1089#1082#1072': '#1089#1086#1093#1088#1072#1085#1077#1085#1080#1077' '#1085#1072#1089#1090#1088#1086#1077#1082' '#1087#1086#1103#1074#1080#1090#1089#1103' '#1085#1072' '#1101#1090#1072#1087#1077' 6.'
            WordWrap = True
          end
          object cbRetention: TComboBox
            Left = 160
            Top = 78
            Width = 120
            Height = 23
            Style = csDropDownList
            TabOrder = 0
            OnChange = cbRetentionChange
          end
          object chkStorePaths: TCheckBox
            Left = 16
            Top = 112
            Width = 600
            Height = 19
            Caption = #1057#1086#1093#1088#1072#1085#1103#1090#1100' '#1074' '#1080#1089#1090#1086#1088#1080#1080' &'#1087#1091#1090#1080' '#1082' '#1092#1072#1081#1083#1072#1084' '#1087#1088#1086#1094#1077#1089#1089#1086#1074
            TabOrder = 1
            OnClick = chkStorePathsClick
          end
          object btnClearHistory: TButton
            Left = 16
            Top = 140
            Width = 180
            Height = 27
            Caption = #1054'&'#1095#1080#1089#1090#1080#1090#1100' '#1080#1089#1090#1086#1088#1080#1102#8230
            TabOrder = 2
            OnClick = btnClearHistoryClick
          end
        end
        object gbAnalysis: TGroupBox
          Left = 16
          Top = 346
          Width = 680
          Height = 170
          Caption = #1040#1085#1072#1083#1080#1079' '#1091#1075#1088#1086#1079
          TabOrder = 2
          object lblHighCpu: TLabel
            Left = 16
            Top = 28
            Width = 200
            Height = 15
            Caption = #1055#1086#1088#1086#1075' &'#1074#1099#1089#1086#1082#1086#1081' '#1085#1072#1075#1088#1091#1079#1082#1080' '#1087#1088#1086#1094#1077#1089#1089#1072':'
            FocusControl = cbHighCpu
          end
          object lblSustained: TLabel
            Left = 16
            Top = 60
            Width = 200
            Height = 15
            Caption = '&'#1053#1072#1075#1088#1091#1079#1082#1072' '#1076#1086#1083#1078#1085#1072' '#1076#1083#1080#1090#1100#1089#1103' '#1085#1077' '#1084#1077#1085#1100#1096#1077':'
            FocusControl = cbSustained
          end
          object lblLearning: TLabel
            Left = 16
            Top = 92
            Width = 200
            Height = 15
            Caption = #1055#1077#1088#1080#1086#1076' &'#1086#1073#1091#1095#1077#1085#1080#1103' '#1087#1088#1086#1092#1080#1083#1103' '#1085#1086#1088#1084#1099':'
            FocusControl = cbLearning
          end
          object cbHighCpu: TComboBox
            Left = 260
            Top = 24
            Width = 200
            Height = 23
            Style = csDropDownList
            TabOrder = 0
            OnChange = cbHighCpuChange
          end
          object cbSustained: TComboBox
            Left = 260
            Top = 56
            Width = 200
            Height = 23
            Style = csDropDownList
            TabOrder = 1
            OnChange = cbSustainedChange
          end
          object cbLearning: TComboBox
            Left = 260
            Top = 88
            Width = 200
            Height = 23
            Style = csDropDownList
            TabOrder = 2
            OnChange = cbLearningChange
          end
          object chkStartScan: TCheckBox
            Left = 16
            Top = 120
            Width = 600
            Height = 19
            Caption = #1053#1072#1095#1080#1085#1072#1090#1100' &'#1089#1082#1072#1085#1080#1088#1086#1074#1072#1085#1080#1077' '#1087#1088#1080' '#1079#1072#1087#1091#1089#1082#1077' '#1087#1088#1086#1075#1088#1072#1084#1084#1099
            TabOrder = 3
            OnClick = chkStartScanClick
          end
          object chkRedactReports: TCheckBox
            Left = 16
            Top = 142
            Width = 640
            Height = 19
            Caption = #1054'&'#1073#1077#1079#1083#1080#1095#1080#1074#1072#1090#1100' '#1086#1090#1095#1105#1090#1099' ('#1089#1082#1088#1099#1074#1072#1090#1100' '#1080#1084#1103' '#1087#1086#1083#1100#1079#1086#1074#1072#1090#1077#1083#1103' '#1080' '#1082#1086#1084#1087#1100#1102#1090#1077#1088#1072')'
            TabOrder = 4
            OnClick = chkRedactReportsClick
          end
        end
        object gbExclusions: TGroupBox
          Left = 16
          Top = 526
          Width = 680
          Height = 190
          Caption = #1056#1072#1079#1088#1077#1096#1105#1085#1085#1099#1077' '#1087#1088#1086#1075#1088#1072#1084#1084#1099' ('#1080#1089#1082#1083#1102#1095#1077#1085#1080#1103')'
          TabOrder = 3
          object lvExclusions: TListView
            Left = 12
            Top = 22
            Width = 656
            Height = 126
            Columns = <
              item
                Caption = #1055#1088#1086#1075#1088#1072#1084#1084#1072
                Width = 130
              end
              item
                Caption = #1055#1091#1090#1100
                Width = 260
              end
              item
                Caption = 'SHA-256'
                Width = 120
              end
              item
                Caption = #1044#1086#1073#1072#1074#1083#1077#1085#1086
                Width = 120
              end>
            ReadOnly = True
            RowSelect = True
            TabOrder = 0
            ViewStyle = vsReport
          end
          object btnRemoveExclusion: TButton
            Left = 12
            Top = 154
            Width = 200
            Height = 27
            Caption = '&'#1059#1076#1072#1083#1080#1090#1100' '#1080#1079' '#1080#1089#1082#1083#1102#1095#1077#1085#1080#1081#8230
            TabOrder = 1
            OnClick = btnRemoveExclusionClick
          end
        end
        object gbActionLog: TGroupBox
          Left = 16
          Top = 726
          Width = 680
          Height = 200
          Caption = #1046#1091#1088#1085#1072#1083' '#1076#1077#1081#1089#1090#1074#1080#1081
          TabOrder = 4
          object lvActionLog: TListView
            Left = 12
            Top = 22
            Width = 656
            Height = 166
            Columns = <
              item
                Caption = #1042#1088#1077#1084#1103
                Width = 120
              end
              item
                Caption = #1044#1077#1081#1089#1090#1074#1080#1077
                Width = 110
              end
              item
                Caption = #1054#1073#1098#1077#1082#1090
                Width = 200
              end
              item
                Caption = #1056#1077#1079#1091#1083#1100#1090#1072#1090
                Width = 210
              end>
            ReadOnly = True
            RowSelect = True
            TabOrder = 0
            ViewStyle = vsReport
          end
        end
      end
    end
  end
  object sbMain: TStatusBar
    Left = 0
    Top = 797
    Width = 1000
    Height = 23
    Panels = <
      item
        Width = 260
      end
      item
        Width = 50
      end>
  end
  object sdExport: TSaveDialog
    DefaultExt = 'html'
    Filter = #1054#1090#1095#1105#1090' HTML (*.html)|*.html|'#1044#1072#1085#1085#1099#1077' JSON (*.json)|*.json'
    Options = [ofOverwritePrompt, ofHideReadOnly, ofPathMustExist, ofEnableSizing]
    Left = 820
    Top = 8
  end
  object alMain: TActionList
    Left = 880
    Top = 8
    object actStart: TAction
      Caption = #1053#1072#1095#1072#1090#1100' '#1089#1082#1072#1085#1080#1088#1086#1074#1072#1085#1080#1077
      Hint = #1053#1072#1095#1072#1090#1100' '#1089#1082#1072#1085#1080#1088#1086#1074#1072#1085#1080#1077' (F5)'
      ShortCut = 116
      OnExecute = actStartExecute
    end
    object actStop: TAction
      Caption = #1054#1089#1090#1072#1085#1086#1074#1080#1090#1100
      Hint = #1054#1089#1090#1072#1085#1086#1074#1080#1090#1100' '#1089#1082#1072#1085#1080#1088#1086#1074#1072#1085#1080#1077' (Shift+F5)'
      ShortCut = 8308
      OnExecute = actStopExecute
    end
    object actNavDashboard: TAction
      Caption = #1054#1073#1079#1086#1088
      ShortCut = 16433
      OnExecute = actNavExecute
    end
    object actNavProcesses: TAction
      Tag = 1
      Caption = #1055#1088#1086#1094#1077#1089#1089#1099
      ShortCut = 16434
      OnExecute = actNavExecute
    end
    object actNavFindings: TAction
      Tag = 2
      Caption = #1053#1072#1093#1086#1076#1082#1080
      ShortCut = 16435
      OnExecute = actNavExecute
    end
    object actNavHistory: TAction
      Tag = 3
      Caption = #1048#1089#1090#1086#1088#1080#1103
      ShortCut = 16436
      OnExecute = actNavExecute
    end
    object actNavSettings: TAction
      Tag = 4
      Caption = #1053#1072#1089#1090#1088#1086#1081#1082#1080
      ShortCut = 16437
      OnExecute = actNavExecute
    end
  end
end
