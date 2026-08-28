@echo off
chcp 65001 >nul
title 微信小程序域名一键提取
cd /d "%~dp0.."
"%~dp0..\tools\miniapp_extract\一键小程序域名提取.cmd"
