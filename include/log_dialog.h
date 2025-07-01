#pragma once
#include <string>
#include <windows.h>

// 日志级别
enum class LogLevel {
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_SUCCESS
};

// 日志输出到对话框多行编辑框
void logToDialog(LogLevel level, const std::string& message);

// 获取当前时间字符串
std::string getCurrentTimeString();

// 全局对话框句柄
extern HWND g_hLogDlg; 