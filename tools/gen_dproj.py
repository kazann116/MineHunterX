"""Generate minimal Win64-only .dproj files for MineHunter X projects.

The .dpr files are the source of truth for unit lists; this script keeps the
.dproj files (needed by MSBuild and the IDE) in sync with them.

Usage: python tools/gen_dproj.py
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TEMPLATE = r'''<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
    <PropertyGroup>
        <ProjectGuid>@GUID@</ProjectGuid>
        <ProjectVersion>20.1</ProjectVersion>
        <FrameworkType>VCL</FrameworkType>
        <AppType>@APPTYPE@</AppType>
        <MainSource>@NAME@.dpr</MainSource>
        <Base>True</Base>
        <Config Condition="'$(Config)'==''">Debug</Config>
        <Platform Condition="'$(Platform)'==''">Win64</Platform>
        <TargetedPlatforms>2</TargetedPlatforms>
    </PropertyGroup>
    <PropertyGroup Condition="'$(Config)'=='Base' or '$(Base)'!=''">
        <Base>true</Base>
    </PropertyGroup>
    <PropertyGroup Condition="('$(Platform)'=='Win64' and '$(Base)'=='true') or '$(Base_Win64)'!=''">
        <Base_Win64>true</Base_Win64>
        <CfgParent>Base</CfgParent>
        <Base>true</Base>
    </PropertyGroup>
    <PropertyGroup Condition="'$(Config)'=='Debug' or '$(Cfg_1)'!=''">
        <Cfg_1>true</Cfg_1>
        <CfgParent>Base</CfgParent>
        <Base>true</Base>
    </PropertyGroup>
    <PropertyGroup Condition="('$(Platform)'=='Win64' and '$(Cfg_1)'=='true') or '$(Cfg_1_Win64)'!=''">
        <Cfg_1_Win64>true</Cfg_1_Win64>
        <CfgParent>Cfg_1</CfgParent>
        <Cfg_1>true</Cfg_1>
        <Base>true</Base>
    </PropertyGroup>
    <PropertyGroup Condition="'$(Config)'=='Release' or '$(Cfg_2)'!=''">
        <Cfg_2>true</Cfg_2>
        <CfgParent>Base</CfgParent>
        <Base>true</Base>
    </PropertyGroup>
    <PropertyGroup Condition="('$(Platform)'=='Win64' and '$(Cfg_2)'=='true') or '$(Cfg_2_Win64)'!=''">
        <Cfg_2_Win64>true</Cfg_2_Win64>
        <CfgParent>Cfg_2</CfgParent>
        <Cfg_2>true</Cfg_2>
        <Base>true</Base>
    </PropertyGroup>
    <PropertyGroup Condition="'$(Base)'!=''">
        <SanitizedProjectName>@SANITIZED@</SanitizedProjectName>
        <DCC_ExeOutput>@ROOT@build\$(Platform)\$(Config)</DCC_ExeOutput>
        <DCC_DcuOutput>@ROOT@build\dcu\@NAME@\$(Platform)\$(Config)</DCC_DcuOutput>
        <DCC_UnitSearchPath>@SEARCH@$(DCC_UnitSearchPath)</DCC_UnitSearchPath>
        <DCC_Namespace>System;Xml;Data;Datasnap;Web;Soap;Vcl;Vcl.Imaging;Vcl.Touch;Vcl.Samples;Vcl.Shell;$(DCC_Namespace)</DCC_Namespace>
        <DCC_Define>@DEFINES@$(DCC_Define)</DCC_Define>
        <DCC_Hints>true</DCC_Hints>
        <DCC_Warnings>true</DCC_Warnings>
        <VerInfo_IncludeVerInfo>false</VerInfo_IncludeVerInfo>
        <Manifest_File>None</Manifest_File>
        <AppEnableRuntimeThemes>false</AppEnableRuntimeThemes>
    </PropertyGroup>
    <PropertyGroup Condition="'$(Base_Win64)'!=''">
        <DCC_Namespace>Winapi;System.Win;Data.Win;Datasnap.Win;Web.Win;Soap.Win;Xml.Win;$(DCC_Namespace)</DCC_Namespace>
    </PropertyGroup>
    <PropertyGroup Condition="'$(Cfg_1)'!=''">
        <DCC_Define>DEBUG;$(DCC_Define)</DCC_Define>
        <DCC_DebugDCUs>false</DCC_DebugDCUs>
        <DCC_DebugInfoInExe>true</DCC_DebugInfoInExe>
        <DCC_GenerateStackFrames>true</DCC_GenerateStackFrames>
        <DCC_Optimize>false</DCC_Optimize>
        <DCC_RangeChecking>true</DCC_RangeChecking>
        <DCC_IntegerOverflowCheck>true</DCC_IntegerOverflowCheck>
    </PropertyGroup>
    <PropertyGroup Condition="'$(Cfg_2)'!=''">
        <DCC_Define>RELEASE;$(DCC_Define)</DCC_Define>
        <DCC_DebugInformation>0</DCC_DebugInformation>
        <DCC_LocalDebugSymbols>false</DCC_LocalDebugSymbols>
        <DCC_SymbolReferenceInfo>0</DCC_SymbolReferenceInfo>
    </PropertyGroup>
    <ItemGroup>
        <DelphiCompile Include="$(MainSource)">
            <MainSource>MainSource</MainSource>
        </DelphiCompile>
@ITEMS@        <BuildConfiguration Include="Base">
            <Key>Base</Key>
        </BuildConfiguration>
        <BuildConfiguration Include="Debug">
            <Key>Cfg_1</Key>
            <CfgParent>Base</CfgParent>
        </BuildConfiguration>
        <BuildConfiguration Include="Release">
            <Key>Cfg_2</Key>
            <CfgParent>Base</CfgParent>
        </BuildConfiguration>
    </ItemGroup>
    <ProjectExtensions>
        <Borland.Personality>Delphi.Personality.12</Borland.Personality>
        <Borland.ProjectType>@APPTYPE@</Borland.ProjectType>
        <BorlandProject>
            <Delphi.Personality>
                <Source>
                    <Source Name="MainSource">@NAME@.dpr</Source>
                </Source>
            </Delphi.Personality>
            <Platforms>
                <Platform value="Win64">True</Platform>
            </Platforms>
        </BorlandProject>
        <ProjectFileVersion>12</ProjectFileVersion>
    </ProjectExtensions>
    <Import Project="$(BDS)\Bin\CodeGear.Delphi.Targets" Condition="Exists('$(BDS)\Bin\CodeGear.Delphi.Targets')"/>
    <Import Project="$(APPDATA)\Embarcadero\$(BDSAPPDATABASEDIR)\$(PRODUCTVERSION)\UserTools.proj" Condition="Exists('$(APPDATA)\Embarcadero\$(BDSAPPDATABASEDIR)\$(PRODUCTVERSION)\UserTools.proj')"/>
</Project>
'''

USES_RE = re.compile(r"^\s*([\w.]+)\s+in\s+'([^']+)'(?:\s*\{(\w+)\})?", re.M)
RC_RE = re.compile(r"\{\$R\s+'([^']+)'\s+'([^']+)'\}")


def items_from_dpr(dpr_path):
    with open(dpr_path, encoding='utf-8-sig') as f:
        text = f.read()
    out = []
    for _unit, path, form in USES_RE.findall(text):
        if form:
            out.append('        <DCCReference Include="%s">\n'
                       '            <Form>%s</Form>\n'
                       '            <FormType>dfm</FormType>\n'
                       '        </DCCReference>\n' % (path, form))
        else:
            out.append('        <DCCReference Include="%s"/>\n' % path)
    for res, rc in RC_RE.findall(text):
        out.append('        <RcCompile Include="%s">\n'
                   '            <Form>%s</Form>\n'
                   '        </RcCompile>\n' % (rc, res))
    return ''.join(out)


def generate(rel_dir, name, guid, apptype, search, defines=''):
    folder = os.path.join(ROOT, rel_dir)
    depth = rel_dir.replace('\\', '/').strip('/').count('/') + 1
    values = {
        'GUID': guid,
        'APPTYPE': apptype,
        'NAME': name,
        'SANITIZED': name.replace('.', '_'),
        'ROOT': '..\\' * depth,
        'SEARCH': ''.join(s + ';' for s in search),
        'DEFINES': defines,
        'ITEMS': items_from_dpr(os.path.join(folder, name + '.dpr')),
    }
    text = TEMPLATE
    for key, value in values.items():
        text = text.replace('@%s@' % key, value)
    with open(os.path.join(folder, name + '.dproj'), 'w', encoding='utf-8', newline='\r\n') as f:
        f.write(text)
    print('generated', os.path.join(rel_dir, name + '.dproj'))


if __name__ == '__main__':
    generate('src/App', 'MineHunter.App', '{3A0D4C2B-7E61-4B8E-A7C5-1F2E9D6B0A11}', 'Application',
             ['..\\Core', '..\\Core\\Collectors', '..\\Storage'])
    generate('tests', 'MineHunter.Tests', '{3A0D4C2B-7E61-4B8E-A7C5-1F2E9D6B0A12}', 'Console',
             ['..\\src\\Core', '..\\src\\Core\\Collectors', '..\\src\\Storage', '..\\src\\App',
              'Unit', 'Integration', 'UI', 'Fixtures'])
    generate('tests/Soak', 'MineHunter.Soak', '{3A0D4C2B-7E61-4B8E-A7C5-1F2E9D6B0A13}', 'Console',
             ['..\\..\\src\\Core', '..\\..\\src\\Core\\Collectors', '..\\..\\src\\Storage', '..\\..\\src\\App'])
