@echo off
chcp 65001 >nul
setlocal EnableExtensions
set "PYTHONUTF8=1"
cd /d "%~dp0"

set "INPUT=translate.json"
set "OUTPUT=translate.translated.json"
set "REVIEW=translation_review.json"
set "CACHE=deepseek_json_translation_cache.json"
set "GLOSSARY=translation_glossary.json"
set "MODEL=deepseek-flash"
set "BATCH_SIZE=8"
set "MAX_CHARS=5000"
set "MAX_TOKENS=4096"
set "TIMEOUT=180"

if not exist "%INPUT%" goto missing_input
if not exist "translate.py" goto missing_script
where python >nul 2>nul
if errorlevel 1 goto missing_python
if not defined DEEPSEEK_API_KEY goto missing_key

echo DeepSeek API model: %MODEL%
echo Thinking: disabled
echo Batch size: %BATCH_SIZE%  Max chars: %MAX_CHARS%  Max output tokens: %MAX_TOKENS%
echo Press Ctrl+C to stop. Completed batches are saved in the DeepSeek cache.
echo.

python -X utf8 translate.py --json "%INPUT%" --output "%OUTPUT%" --review "%REVIEW%" --cache "%CACHE%" --glossary "%GLOSSARY%" --api-base "https://api.deepseek.com" --model "%MODEL%" --batch-size %BATCH_SIZE% --max-chars %MAX_CHARS% --max-tokens %MAX_TOKENS% --context-lines 2 --timeout %TIMEOUT%
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" goto translation_failed
echo Translation process finished.
echo Check %REVIEW% and %OUTPUT% before writing anything back to Pawn source files.
goto finish

:missing_input
echo ERROR: translate.json was not found in this folder.
goto failed
:missing_script
echo ERROR: translate.py was not found in this folder.
goto failed
:missing_python
echo ERROR: Python was not found in PATH.
goto failed
:missing_key
echo ERROR: DEEPSEEK_API_KEY environment variable is missing.
echo In PowerShell run: setx DEEPSEEK_API_KEY "YOUR_API_KEY"
echo Then close and reopen PowerShell or VS Code, and run this BAT again.
goto failed
:translation_failed
echo Translation stopped or failed. Fix the issue and run this file again to resume from cache.
goto finish
:failed
echo Check that the required files and API key are ready.
:finish
echo.
pause
endlocal
