# PCAP to LVX2 Converter

一个用于将 PCAP/PCAPNG 文件转换为 LVX2 格式的工具，支持中文路径，提供图形界面。

## 功能特点

- 支持 PCAP 和 PCAPNG 格式文件转换
- 支持中文路径
- 提供图形界面文件选择
- 支持命令行操作

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
2. 在弹出的文件选择对话框中选择要转换的 PCAP/PCAPNG 文件
3. 等待转换完成
4. 转换后的文件将保存在原文件相同目录下，扩展名为 .lvx2

### 命令行

```bash
PcaptoLVX2.exe <input_file>
```

例如：
```bash
PcaptoLVX2.exe data.pcap
```

## 注意事项

- 确保有足够的磁盘空间
- 转换过程中请勿关闭程序
- 如果遇到错误，请查看错误信息并确保文件格式正确
- 读取含有中文字符的路径或文件名时，可能会显示乱码，不影响文件转换
- 选择 pcapng 文件时，程序会先转换为 pcap（生成一个 “原文件名_converted.pcap” 文件）

## 常见问题

1. 程序无法启动
   - 检查是否安装了所需的运行库
   - 检查是否以管理员权限运行

2. 转换失败
   - 检查输入文件是否完整
   - 检查文件格式是否正确
   - 查看错误信息获取详细原因

## 版本信息

- 版本：1.0.0
- 发布日期：2025-06-16
- 许可证：BSD-3-Clause License

## 许可证

本项目采用 BSD-3-Clause 许可证。详情请查看 [LICENSE](LICENSE) 文件。 
