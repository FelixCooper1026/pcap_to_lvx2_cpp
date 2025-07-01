#pragma once
#include <string>
#include <windows.h>

// ��־����
enum class LogLevel {
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_SUCCESS
};

// ��־������Ի�����б༭��
void logToDialog(LogLevel level, const std::string& message);

// ��ȡ��ǰʱ���ַ���
std::string getCurrentTimeString();

// ȫ�ֶԻ�����
extern HWND g_hLogDlg; 