@echo off
if exist binary_check.spec (
    echo Found spec file, using it to build...
    pyinstaller binary_check.spec
) else (
    echo No spec file, using .py to build...
    pyinstaller -F binary_check.py
)
echo 
if %errorlevel% == 0 (
    echo Build Pass : please check \dist\binary_check.exe

    if exist binary_check.exe (
        echo Found existing binary_check.exe in current folder, renaming it...
        ren binary_check.exe compare_BCU_RN_o.exe
    )

    copy /Y dist\binary_check.exe .\
) else (
    echo Fail %errorlevel%
)
pause