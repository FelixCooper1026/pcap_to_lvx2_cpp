#include "pcap_to_lvx2.h"
#include <Windows.h>
#include <commdlg.h>
#include <filesystem>
#include <string>
#include <shellapi.h>
#include <windowsx.h>
#include "resource.h"
#include <sstream>
#include <ctime>
#include "log_dialog.h"
#include <commctrl.h>
#pragma comment(lib, "user32.lib")

static std::string logText;
HWND g_hLogDlg = NULL;

std::string getCurrentTimeString() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[20];
    localtime_s(&tstruct, &now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tstruct);
    return buf;
}

void appendLog(const std::string& msg) {
    if (!g_hLogDlg) return;
    logText += msg + "\r\n";
    SetDlgItemTextA(g_hLogDlg, IDC_LOG_EDIT, logText.c_str());
    // Scroll to bottom
    HWND hEdit = GetDlgItem(g_hLogDlg, IDC_LOG_EDIT);
    int len = GetWindowTextLengthA(hEdit);
    SendMessageA(hEdit, EM_SETSEL, len, len);
    SendMessageA(hEdit, EM_SCROLLCARET, 0, 0);
}

void logToDialog(LogLevel level, const std::string& message) {
    std::string levelStr;
    switch (level) {
        case LogLevel::LOG_INFO:    levelStr = "[INFO]"; break;
        case LogLevel::LOG_WARNING: levelStr = "[WARNING]"; break;
        case LogLevel::LOG_ERROR:   levelStr = "[ERROR]"; break;
        case LogLevel::LOG_SUCCESS: levelStr = "[SUCCESS]"; break;
    }
    std::ostringstream oss;
    oss << getCurrentTimeString() << " " << levelStr << " " << message;
    appendLog(oss.str());
}

std::string selectPcapFile(HWND hDlg) {
    OPENFILENAMEW ofn;
    wchar_t szFile[260] = { 0 };
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hDlg;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"PCAP Files\0*.pcap;*.pcapng;*.cap\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    ofn.lpstrTitle = L"选择 PCAP 文件";

    if (GetOpenFileNameW(&ofn)) {
        int size_needed = WideCharToMultiByte(CP_ACP, 0, szFile, -1, NULL, 0, NULL, NULL);
        std::string strTo(size_needed - 1, 0);
        WideCharToMultiByte(CP_ACP, 0, szFile, -1, &strTo[0], size_needed - 1, NULL, NULL);
        return strTo;
    }
    return "";
}

// 对话框回调
INT_PTR CALLBACK SelectOpDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    static std::string input_file;
    switch (message) {
    case WM_INITDIALOG:
        g_hLogDlg = hDlg;
        logText.clear();
        SetDlgItemTextA(hDlg, IDC_LOG_EDIT, "");
        logToDialog(LogLevel::LOG_INFO, "请点击“选择文件”按钮选择PCAP文件。");
        return TRUE;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_LVX2: {
            if (input_file.empty()) {
                logToDialog(LogLevel::LOG_WARNING, "请先点击“选择文件”按钮选择PCAP文件。");
                break;
            }
            if (!std::filesystem::exists(input_file)) {
                logToDialog(LogLevel::LOG_ERROR, "输入文件不存在: " + input_file);
                break;
            }
            logToDialog(LogLevel::LOG_INFO, "开始点云转LVX2...");
            std::string output_file = std::filesystem::path(input_file).replace_extension(".lvx2").string();
            PCAPToLVX2 converter(input_file, output_file);
            if (converter.convert()) {
                logToDialog(LogLevel::LOG_SUCCESS, "LVX2转换成功！");
                std::string abs_path = std::filesystem::absolute(output_file).string();
                logToDialog(LogLevel::LOG_INFO, "文件保存位置: " + abs_path);
                std::string message = "LVX2转换成功！\n\n文件保存位置: " + abs_path;
                MessageBoxA(hDlg, message.c_str(), "操作成功", MB_OK | MB_ICONINFORMATION);
                std::string output_dir = std::filesystem::path(output_file).parent_path().string();
                ShellExecuteA(NULL, "open", output_dir.c_str(), NULL, NULL, SW_SHOW);
            } else {
                logToDialog(LogLevel::LOG_ERROR, "LVX2转换失败。");
            }
            break;
        }
        case IDC_BTN_IMU: {
            if (input_file.empty()) {
                logToDialog(LogLevel::LOG_WARNING, "请先点击“选择文件”按钮选择PCAP文件。");
                break;
            }
            if (!std::filesystem::exists(input_file)) {
                logToDialog(LogLevel::LOG_ERROR, "输入文件不存在: " + input_file);
                break;
            }
            std::string csv_file = std::filesystem::path(input_file).replace_extension("_imu.csv").string();
            extern bool extractImuDataToCsv(const std::string&, const std::string&, HWND);
            if (extractImuDataToCsv(input_file, csv_file, hDlg)) {
                std::string abs_path = std::filesystem::absolute(csv_file).string();
                logToDialog(LogLevel::LOG_SUCCESS, "IMU数据已成功导出为CSV文件！");
                logToDialog(LogLevel::LOG_INFO, "文件保存位置: " + abs_path);
                std::string message = "IMU数据已成功导出为CSV文件！\n\n文件保存位置: " + abs_path;
                MessageBoxA(hDlg, message.c_str(), "操作成功", MB_OK | MB_ICONINFORMATION);
                std::string output_dir = std::filesystem::path(csv_file).parent_path().string();
                ShellExecuteA(NULL, "open", output_dir.c_str(), NULL, NULL, SW_SHOW);
            } else {
                logToDialog(LogLevel::LOG_ERROR, "IMU CSV导出失败。");
            }
            break;
        }
        case IDC_BTN_SELECT:
            input_file = selectPcapFile(hDlg);
            if (input_file.empty()) {
                logToDialog(LogLevel::LOG_WARNING, "未选择文件。");
            } else {
                logToDialog(LogLevel::LOG_INFO, "已选择文件: " + input_file);
            }
            break;
        case IDCANCEL:
            EndDialog(hDlg, 0);
            return TRUE;
        }
        break;
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    case WM_SIZE: {
        RECT rc;
        GetClientRect(hDlg, &rc);
        int width = rc.right - rc.left;
        int height = rc.bottom - rc.top;

        // Default sizes
        const int default_win_width = 600;
        const int default_win_height = 400;
        const int default_button_width = 120;
        const int default_button_height = 30;
        const int num_buttons = 4;
        const int margin = 10;
        const int button_spacing = 20;

        // Calculate scale (do not shrink below 1.0)
        double scale_w = (double)width / default_win_width;
        double scale_h = (double)height / default_win_height;
        double scale = min(scale_w, scale_h);
        scale = (scale < 1.0) ? 1.0 : scale;

        int button_width = (int)(default_button_width * scale + 0.5);
        int button_height = (int)(default_button_height * scale + 0.5);
        int spacing = (int)(button_spacing * scale + 0.5);

        // Ensure minimum size
        if (button_width < default_button_width) button_width = default_button_width;
        if (button_height < default_button_height) button_height = default_button_height;
        if (spacing < button_spacing) spacing = button_spacing;

        int total_button_width = num_buttons * button_width + (num_buttons - 1) * spacing;
        int button_top = height - margin - button_height;
        int button_left = (width - total_button_width) / 2;

        // Log area: fill above the buttons
        MoveWindow(GetDlgItem(hDlg, IDC_LOG_EDIT), margin, margin, width - 2 * margin, button_top - margin * 2, TRUE);

        // Buttons: 选择文件, 点云转LVX2, IMU导出CSV, 退出
        MoveWindow(GetDlgItem(hDlg, IDC_BTN_SELECT), button_left, button_top, button_width, button_height, TRUE);
        MoveWindow(GetDlgItem(hDlg, IDC_BTN_LVX2), button_left + (button_width + spacing) * 1, button_top, button_width, button_height, TRUE);
        MoveWindow(GetDlgItem(hDlg, IDC_BTN_IMU), button_left + (button_width + spacing) * 2, button_top, button_width, button_height, TRUE);
        MoveWindow(GetDlgItem(hDlg, IDCANCEL), button_left + (button_width + spacing) * 3, button_top, button_width, button_height, TRUE);
        break;
    }
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    DialogBoxParam(
        GetModuleHandle(NULL),
        MAKEINTRESOURCE(IDD_SELECT_OP),
        NULL,
        SelectOpDlgProc,
        0
    );
    return 0;
}