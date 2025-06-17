# PCAP to LVX2 Converter

一个用于将 PCAP/PCAPNG/CAP 文件转换为 LVX2 格式的工具，支持中文路径，提供图形界面。

## 功能特点

- 支持 PCAP、PCAPNG 和 CAP 格式文件转换
- 支持中文路径
- 提供图形界面文件选择
- 支持命令行操作
- 自动管理 editcap 路径配置
- 中文错误提示弹窗
- 自动清理中间文件
- 转换成功后自动打开输出文件夹

## 系统要求

- Windows 10 或更高版本
- Visual C++ 2022 Runtime
- Npcap（用于网络数据包捕获）
- Wireshark-editcap

## 安装步骤

1. 下载最新版本的安装包
2. 运行安装程序，按照提示完成安装
3. 如果提示缺少依赖，请安装：
   - Visual C++ 2022 Runtime
   - Npcap
   - Wireshark

## 使用方法

### 图形界面

1. 双击运行程序
2. 在弹出的文件选择对话框中选择要转换的 PCAP/PCAPNG/CAP 文件
3. 首次运行时，需要选择 editcap.exe 的路径（通常位于 Wireshark 安装目录）
4. 等待转换完成
5. 转换成功后会自动打开输出文件夹
6. 转换后的文件将保存在原文件相同目录下，扩展名为 .lvx2

### 命令行

```bash
PcaptoLVX2.exe <input_file>
```

例如：
```bash
PcaptoLVX2.exe data.pcap
```

## 配置管理

程序会自动保存 editcap.exe 的路径配置：
- 配置文件位置：`%APPDATA%/pcap_to_lvx2/editcap_path.ini`
- 首次运行时会提示选择路径
- 如需更改路径：
  1. 删除配置文件
  2. 重新运行程序
  3. 选择新的 editcap.exe 路径

## 注意事项

- 转换过程中请勿关闭程序
- 如果遇到错误，会显示中文错误提示弹窗
- 选择 PCAPNG 文件时，程序会先转换为 PCAP 中间文件，确保有足够的磁盘空间
- 转换 LVX2 成功或失败时会自动清理 PCAP 中间文件
- 转换 LVX2 成功后会自动打开输出文件夹

## 常见问题

1. 程序无法启动
   - 检查是否安装了所需的运行库
   - 检查是否以管理员权限运行

2. 转换失败
   - 检查输入文件是否完整
   - 检查文件格式是否正确
   - 查看错误提示弹窗获取详细原因

3. editcap 路径问题
   - 确保 Wireshark 已正确安装
   - 可以手动删除配置文件重新选择路径

## 版本信息

- 版本：1.1.0
- 发布日期：2025-06-17
- 许可证：BSD-3-Clause License

## 许可证

本项目采用 BSD-3-Clause 许可证。详情请查看 [LICENSE](LICENSE) 文件。 
