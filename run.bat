@echo off
title Windows Hardener
echo ========================================
echo Windows Security Hardening Tool
echo ========================================
echo.
echo Running with Administrator privileges...
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0windows_hardening.ps1"
pause
