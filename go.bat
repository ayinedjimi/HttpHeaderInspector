@echo off
REM HttpHeaderInspector - Script de compilation
REM Ayi NEDJIMI Consultants - https://www.ayinedjimi-consultants.fr

echo Compilation de HttpHeaderInspector...
cl /EHsc /nologo /W4 /MD /O2 /DUNICODE /D_UNICODE HttpHeaderInspector.cpp /link winhttp.lib comctl32.lib user32.lib gdi32.lib shell32.lib comdlg32.lib

if errorlevel 1 (
    echo Erreur de compilation!
    pause
    exit /b 1
)

echo Compilation reussie: HttpHeaderInspector.exe
pause
