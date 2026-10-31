@echo off
chcp 65001 >nul
setlocal EnableExtensions
set "PYTHONUTF8=1"
cd /d "%~dp0"

if not exist "translate.json" (
    echo ERROR: translate.json was not found in this folder.
    goto failed
)
if not exist "translate.py" (
    echo ERROR: translate.py was not found in this folder.
    goto failed
)
where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python was not found in PATH.
    goto failed
)

if not exist "translation_config.json" (
    copy /Y "translation_config.example.json" "translation_config.json" >nul
    echo Created translation_config.json.
    echo Edit api_base, model and api_key, then run this file again.
    goto finish
)

echo Using API settings from translation_config.json
echo Completed batches are saved in translation_cache.json.
echo Press Ctrl+C to stop; completed batches can be resumed.
echo.

python -X utf8 translate.py --config "translation_config.json" --json "translate.json" --output "translate.translated.json" --review "translation_review.json" --cache "translation_cache.json" --glossary "translation_glossary.json"
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" (
    echo Translation stopped or failed. Fix the issue and run again to resume.
    goto finish
)
echo Translation process finished.
echo Review translation_review.json and translate.translated.json before writing back.
goto finish

:failed
echo Check that Python and the required files are ready.
:finish
echo.
pause
endlocal
