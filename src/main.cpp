#include "pcap_to_lvx2.h"
#include <Windows.h>
#include <commdlg.h>
#include <filesystem>
#include <string>
#include <shellapi.h>
#include <windowsx.h>
#include "../include/resource.h"
#include <sstream>
#include <ctime>
#include "log_dialog.h"
#include <commctrl.h>
#include <vector>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "packet.lib")

static std::string logText;
HWND g_hLogDlg = NULL;
static std::string last_output_dir;

struct ControlInitPos {
    int id;
    RECT rect;
};
static std::vector<ControlInitPos> g_initPos;
static int g_initWinWidth = 0, g_initWinHeight = 0;

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
    case WM_INITDIALOG: {
        g_hLogDlg = hDlg;
        logText.clear();
        SetDlgItemTextA(hDlg, IDC_LOG_EDIT, "");
        logToDialog(LogLevel::LOG_INFO, "请点击“选择文件”按钮选择PCAP文件。");
        EnableWindow(GetDlgItem(hDlg, IDC_BTN_OPEN_OUTPUT), FALSE);
        // 记录初始窗口大小和控件位置
        RECT winRect;
        GetClientRect(hDlg, &winRect);
        g_initWinWidth = winRect.right - winRect.left;
        g_initWinHeight = winRect.bottom - winRect.top;
        int ids[] = {IDC_BTN_SELECT, IDC_BTN_LVX2, IDC_BTN_IMU, IDC_BTN_OPEN_OUTPUT, IDCANCEL, IDC_LOG_EDIT};
        g_initPos.clear();
        for (int i = 0; i < sizeof(ids)/sizeof(ids[0]); ++i) {
            HWND hCtrl = GetDlgItem(hDlg, ids[i]);
            RECT rc;
            GetWindowRect(hCtrl, &rc);
            MapWindowPoints(HWND_DESKTOP, hDlg, (LPPOINT)&rc, 2);
            g_initPos.push_back({ids[i], rc});
        }
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_LVX2: { // 1003
            if (input_file.empty()) {
                logToDialog(LogLevel::LOG_WARNING, "请先点击“选择文件”按钮选择PCAP文件。");
                break;
            }
            if (!std::filesystem::exists(input_file)) {
                logToDialog(LogLevel::LOG_ERROR, "输入文件不存在: " + input_file);
                break;
            }
            logToDialog(LogLevel::LOG_INFO, "\n开始导出点云数据...");
            std::string output_file = std::filesystem::path(input_file).replace_extension(".lvx2").string();
            PCAPToLVX2 converter(input_file, output_file);
            if (converter.convert()) {
                logToDialog(LogLevel::LOG_SUCCESS, "点云数据已成功导出为 LVX2 文件！");
                std::string abs_path = std::filesystem::absolute(output_file).string();
                logToDialog(LogLevel::LOG_INFO, "文件保存位置: " + abs_path);
                std::string message = "点云数据已成功导出为 LVX2 文件！\n\n文件保存位置: " + abs_path;
                MessageBoxA(hDlg, message.c_str(), "操作成功", MB_OK | MB_ICONINFORMATION);
                last_output_dir = std::filesystem::path(output_file).parent_path().string();
                EnableWindow(GetDlgItem(hDlg, IDC_BTN_OPEN_OUTPUT), TRUE);
            } else {
                logToDialog(LogLevel::LOG_ERROR, "点云数据导出失败。");
            }
            break;
        }
        case IDC_BTN_IMU: { // 1026
            if (input_file.empty()) {
                logToDialog(LogLevel::LOG_WARNING, "请先点击“选择文件”按钮选择PCAP文件。");
                break;
            }
            if (!std::filesystem::exists(input_file)) {
                logToDialog(LogLevel::LOG_ERROR, "输入文件不存在: " + input_file);
                break;
            }
            logToDialog(LogLevel::LOG_INFO, "开始导出 IMU 数据...");
            std::string csv_file = std::filesystem::path(input_file).replace_extension("_imu.csv").string();
            extern bool extractImuDataToCsv(const std::string&, const std::string&, HWND);
            if (extractImuDataToCsv(input_file, csv_file, hDlg)) {
                std::string abs_path = std::filesystem::absolute(csv_file).string();
                logToDialog(LogLevel::LOG_SUCCESS, "IMU 数据已成功导出为 CSV 文件！");
                logToDialog(LogLevel::LOG_INFO, "文件保存位置: " + abs_path);
                std::string message = "IMU 数据已成功导出为 CSV 文件！\n\n文件保存位置: " + abs_path;
                MessageBoxA(hDlg, message.c_str(), "操作成功", MB_OK | MB_ICONINFORMATION);
                last_output_dir = std::filesystem::path(csv_file).parent_path().string();
                EnableWindow(GetDlgItem(hDlg, IDC_BTN_OPEN_OUTPUT), TRUE);
            } else {
                logToDialog(LogLevel::LOG_ERROR, "IMU 数据导出失败。");
            }
            break;
        }
        case IDC_BTN_SELECT: // 1045
            input_file = selectPcapFile(hDlg);
            if (input_file.empty()) {
                logToDialog(LogLevel::LOG_WARNING, "未选择文件。");
            } else {
                logToDialog(LogLevel::LOG_INFO, "已选择文件: " + input_file);
            }
            EnableWindow(GetDlgItem(hDlg, IDC_BTN_OPEN_OUTPUT), FALSE);
            break;
        case IDC_BTN_OPEN_OUTPUT: // 1046
            if (!last_output_dir.empty()) {
                ShellExecuteA(NULL, "open", last_output_dir.c_str(), NULL, NULL, SW_SHOW);
            } else {
                logToDialog(LogLevel::LOG_WARNING, "请先完成一次转换或导出操作。");
            }
            break;
        case IDCANCEL: // 2 (系统默认)
            EndDialog(hDlg, 0);
            return TRUE;
        }
        break;
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    case WM_GETMINMAXINFO: {
        MINMAXINFO* pMMI = (MINMAXINFO*)lParam;
        pMMI->ptMinTrackSize.x = g_initWinWidth; // 最小宽度
        pMMI->ptMinTrackSize.y = g_initWinHeight; // 最小高度
        return 0;
    }
    case WM_SIZE: {
        if (g_initWinWidth == 0 || g_initWinHeight == 0 || g_initPos.empty()) break;
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);
        double scaleW = (double)width / g_initWinWidth;
        double scaleH = (double)height / g_initWinHeight;
        double scale = min(scaleW, scaleH); // 等比缩放
        for (const auto& ctrl : g_initPos) {
            int x = int(ctrl.rect.left * scale + 0.5);
            int y = int(ctrl.rect.top * scale + 0.5);
            int w = int((ctrl.rect.right - ctrl.rect.left) * scale + 0.5);
            int h = int((ctrl.rect.bottom - ctrl.rect.top) * scale + 0.5);
            MoveWindow(GetDlgItem(hDlg, ctrl.id), x, y, w, h, TRUE);
        }
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