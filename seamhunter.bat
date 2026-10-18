@echo off
setlocal
set HERE=%~dp0
where py >nul 2>nul && (py -3 "%HERE%autopsy_main.py" %*) || (python "%HERE%autopsy_main.py" %*)
