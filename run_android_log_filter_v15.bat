@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 android_log_filter_timestamp_v15.py
) else (
    python android_log_filter_timestamp_v15.py
)
if errorlevel 1 pause
endlocal
