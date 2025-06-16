#include "pcap_to_lvx2.h"
#include <iostream>
#include <Windows.h>
#include <commdlg.h>
#include <filesystem>
#include <string>
#include <conio.h>

std::string selectPcapFile() {
    OPENFILENAMEW ofn;
    wchar_t szFile[260] = { 0 };
    
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"PCAP Files\0*.pcap;*.pcapng\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        // 将宽字符转换为多字节字符（使用 CP_ACP 而不是 CP_UTF8）
        int size_needed = WideCharToMultiByte(CP_ACP, 0, szFile, -1, NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_ACP, 0, szFile, -1, &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }
    return "";
}

void waitForExit() {
    std::cout << "\nPress Enter to exit..." << std::endl;
    // 设置控制台模式，允许关闭窗口
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD prev_mode;
    GetConsoleMode(hInput, &prev_mode);
    SetConsoleMode(hInput, prev_mode | ENABLE_QUICK_EDIT_MODE);

    // 等待用户输入或窗口关闭
    while (true) {
        if (_kbhit()) {
            int key = _getch();
            if (key == 13) { // Enter key
                break;
            }
        }
        Sleep(100); // 减少 CPU 使用率
    }
}

int main(int argc, char* argv[]) {
    // 设置控制台输出代码页为 UTF-8
    SetConsoleOutputCP(CP_UTF8);
    // 确保输出不被缓冲
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);

    std::string input_file;
    if (argc < 2) {
        std::cout << "No input file specified. Opening file dialog..." << std::endl;
        input_file = selectPcapFile();
        if (input_file.empty()) {
            std::cout << "No file selected." << std::endl;
            return 1;
        }
    } else {
        input_file = argv[1];
    }

    // 检查文件是否存在
    if (!std::filesystem::exists(input_file)) {
        std::cerr << "[Error] Input file does not exist: " << input_file << std::endl;
        waitForExit();
        return 1;
    }

    std::cout << "Starting conversion..." << std::endl;
    std::string output_file = std::filesystem::path(input_file).replace_extension(".lvx2").string();
    
    //std::cout << "Input file: " << input_file << std::endl;
    //std::cout << "Output file: " << output_file << std::endl;

    PCAPToLVX2 converter(input_file, output_file);
    if (converter.convert()) {
        std::cout << "\n>>> Conversion completed successfully !" << std::endl;
        std::cout << ">>> Output file location: " << std::filesystem::absolute(output_file).string() << std::endl;
    } else {
        std::cerr << "[ERROR] Conversion failed." << std::endl;
        waitForExit();
        return 1;
    }
    waitForExit();
    return 0;
}