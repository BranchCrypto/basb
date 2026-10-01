@echo off
REM Minimal agent stand-in: spawn a child, linger so the watcher can see it, write into cwd (workdir).
echo parent=%~nx0
ping -n 2 127.0.0.1 >nul
echo mvp-ok> out.txt
exit /b 0
