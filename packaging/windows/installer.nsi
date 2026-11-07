; ===================================================================
; AI卫士 (AI Guard) - Windows 标准 EXE 安装向导脚本 (NSIS)
; ===================================================================

!include "MUI2.nsh"
!include "x64.nsh"

; --- 基础信息定义 ---
Name "AI卫士"
OutFile "AI卫士-v0.1.0-Setup.exe"
Unicode True
RequestExecutionLevel user

; 默认安装路径：%LOCALAPPDATA%\Programs\AI-Guard
InstallDir "$LOCALAPPDATA\Programs\AI-Guard"
InstallDirRegKey HKCU "Software\AI-Guard" "InstallDir"

; 极致固态压缩 (LZMA)
SetCompressor /SOLID lzma

; --- 界面定义 (MUI2) ---
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install-blue.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall-blue.ico"

!define MUI_WELCOMEPAGE_TITLE "欢迎使用 AI卫士 v0.1 安装向导"
!define MUI_WELCOMEPAGE_TEXT "AI卫士是专为个人开发者打造的本地 AI 编程安全助手。\r\n\r\n本向导将指引您在当前用户环境下快速安装 AI卫士。\r\n\r\n• 严格运行在 127.0.0.1 本地回路，无需管理员提权\r\n• 协同纳管 Windows 与 WSL2 双环境 Codex\r\n• 毫秒级阻断高危删除与恶意外联\r\n\r\n点击「下一步」继续。"

!define MUI_FINISHPAGE_RUN "$INSTDIR\ai-guard.exe"
!define MUI_FINISHPAGE_RUN_TEXT "立即运行 AI卫士"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\使用说明.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "查看使用说明文档"

; 安装页面序列
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; 卸载页面序列
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; 语言设置（简体中文）
!insertmacro MUI_LANGUAGE "SimpChinese"

; --- 安装执行段 ---
Section "AI-Guard Core" SecCore
  SetOutPath "$INSTDIR"
  
  ; 写入主执行程序及配套文档
  File "..\..\target\x86_64-pc-windows-gnu\release\ai-guard.exe"
  File "使用说明.txt"
  
  ; 生成标准卸载可执行文件
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  
  ; 创建 Windows 开始菜单快捷方式
  CreateDirectory "$SMPROGRAMS\AI卫士"
  CreateShortcut "$SMPROGRAMS\AI卫士\AI卫士.lnk" "$INSTDIR\ai-guard.exe" "" "$INSTDIR\ai-guard.exe" 0
  CreateShortcut "$SMPROGRAMS\AI卫士\使用说明.lnk" "notepad.exe" '"$INSTDIR\使用说明.txt"' "" 0
  CreateShortcut "$SMPROGRAMS\AI卫士\卸载AI卫士.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0
  
  ; 创建桌面快捷方式
  CreateShortcut "$DESKTOP\AI卫士.lnk" "$INSTDIR\ai-guard.exe" "" "$INSTDIR\ai-guard.exe" 0
  
  ; 注册到 Windows 控制面板与设置的「应用和功能」列表中
  WriteRegStr HKCU "Software\AI-Guard" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Guard" "DisplayName" "AI卫士 (AI Guard) - AI编程执行前安全防火墙"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Guard" "DisplayVersion" "0.1.0"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Guard" "Publisher" "AI Guard Team"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Guard" "DisplayIcon" "$INSTDIR\ai-guard.exe,0"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Guard" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Guard" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Guard" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Guard" "NoRepair" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Guard" "EstimatedSize" 7800
SectionEnd

; --- 卸载执行段 ---
Section "Uninstall"
  ; 删除桌面与开始菜单快捷方式
  Delete "$DESKTOP\AI卫士.lnk"
  Delete "$SMPROGRAMS\AI卫士\AI卫士.lnk"
  Delete "$SMPROGRAMS\AI卫士\使用说明.lnk"
  Delete "$SMPROGRAMS\AI卫士\卸载AI卫士.lnk"
  RMDir "$SMPROGRAMS\AI卫士"
  
  ; 删除安装目录文件
  Delete "$INSTDIR\ai-guard.exe"
  Delete "$INSTDIR\使用说明.txt"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  
  ; 清理 Windows 注册表项
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AI-Guard"
  DeleteRegKey HKCU "Software\AI-Guard"
SectionEnd
