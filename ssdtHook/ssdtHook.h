#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <ntddk.h>
#include <stdlib.h>

#define MAX_PROCESS_ARRAY_LENGTH     10 //最多保护10个进程
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;        // 文件的产生时刻
    USHORT    MajorVersion;
    USHORT    MinorVersion;
    ULONG   Name;                  // 指向文件名的RVA
    ULONG   Base;                  // 导出函数的起始序号
    ULONG   NumberOfFunctions;     // 导出函数总数
    ULONG   NumberOfNames;         // 以名称导出函数的总数
    ULONG   AddressOfFunctions;    // 导出函数地址表的RVA
    ULONG   AddressOfNames;        // 函数名称地址表的RVA
    ULONG   AddressOfNameOrdinals; // 函数名序号表的RVA
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    USHORT   e_magic;                     // MZ标记 0x5a4d 
    USHORT   e_cblp;                      // 最后(部分)页中的字节数
    USHORT   e_cp;                        // 文件中的全部和部分页数
    USHORT   e_crlc;                      // 重定位表中的指针数
    USHORT   e_cparhdr;                   // 头部尺寸以段落为单位
    USHORT   e_minalloc;                  // 所需的最小附加段
    USHORT   e_maxalloc;                  // 所需的最大附加段
    USHORT   e_ss;                        // 初始的SS值(相对偏移量)
    USHORT   e_sp;                        // 初始的SP值
    USHORT   e_csum;                      // 补码校验值
    USHORT   e_ip;                        // 初始的IP值
    USHORT   e_cs;                        // 初始的SS值
    USHORT   e_lfarlc;                    // 重定位表的字节偏移量
    USHORT   e_ovno;                      // 覆盖号
    USHORT   e_res[4];                    // 保留字
    USHORT   e_oemid;                     // OEM标识符(相对m_oeminfo)
    USHORT   e_oeminfo;                   // OEM信息
    USHORT   e_res2[10];                  // 保留字
    LONG   e_lfanew;                    // NT头(PE标记)相对于文件的偏移地址
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    USHORT  Machine;
    USHORT  NumberOfSections;
    ULONG   TimeDateStamp;
    ULONG   PointerToSymbolTable;
    ULONG   NumberOfSymbols;
    USHORT  SizeOfOptionalHeader;
    USHORT  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    USHORT  Magic;
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    ULONG   SizeOfCode;
    ULONG   SizeOfInitializedData;
    ULONG   SizeOfUninitializedData;
    ULONG   AddressOfEntryPoint;
    ULONG   BaseOfCode;
    ULONG   BaseOfData;
    ULONG   ImageBase;
    ULONG   SectionAlignment;
    ULONG   FileAlignment;
    USHORT  MajorOperatingSystemVersion;
    USHORT  MinorOperatingSystemVersion;
    USHORT  MajorImageVersion;
    USHORT  MinorImageVersion;
    USHORT  MajorSubsystemVersion;
    USHORT  MinorSubsystemVersion;
    ULONG   Win32VersionValue;
    ULONG   SizeOfImage;
    ULONG   SizeOfHeaders;
    ULONG   CheckSum;
    USHORT  Subsystem;
    USHORT  DllCharacteristics;
    ULONG   SizeOfStackReserve;
    ULONG   SizeOfStackCommit;
    ULONG   SizeOfHeapReserve;
    ULONG   SizeOfHeapCommit;
    ULONG   LoaderFlags;
    ULONG   NumberOfRvaAndSizes;
    // 以下是数据目录数组，具体内容可根据需要访问
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
    ULONG Signature;//PE标记 0x00004550 
    IMAGE_FILE_HEADER FileHeader;//标准PE头 大小固定为0x14(20)字节
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;//扩展PE头 32BIT默认大小为0xE0
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

// KSYSTEM_SERVICE_TABLE 和 KSERVICE_TABLE_DESCRIPTOR
// 用来定义 SSDT 结构
typedef struct _KSYSTEM_SERVICE_TABLE
{
    PULONG  ServiceTableBase;                               // SSDT (System Service Dispatch Table)的基地址
    PULONG  ServiceCounterTableBase;                        // 用于 checked builds, 包含 SSDT 中每个服务被调用的次数
    ULONG   NumberOfService;                                // 服务函数的个数, NumberOfService * 4 就是整个地址表的大小
    ULONG   ParamTableBase;                                 // SSPT(System Service Parameter Table)的基地址
} KSYSTEM_SERVICE_TABLE, * PKSYSTEM_SERVICE_TABLE;

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
    KSYSTEM_SERVICE_TABLE   ntoskrnl; // ntoskrnl.exe 的服务函数
    KSYSTEM_SERVICE_TABLE   win32k;   // win32k.sys 的服务函数(GDI32.dll/User32.dll 的内核支持)
    KSYSTEM_SERVICE_TABLE   notUsed1;
    KSYSTEM_SERVICE_TABLE   notUsed2;
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;

extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;

ULONG g_ulArrayProtectPid[MAX_PROCESS_ARRAY_LENGTH];
ULONG g_ulArrayProtectPidLen = 0;

// windows未开放的接口，需要先声明才能使用
UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
NTSTATUS PsLookupProcessByProcessId(__in HANDLE ProcessId, __deref_out PEPROCESS * Process);

/**
 * @brief: 检测进程是否已经是被保护的进程了
 * @param: [in] uPid 需要检测的进程id
 * @return: -1 不是被保护的进程 其他值 被保护的进程
 */
ULONG ValidateProcessNeedProtect(ULONG uPid);

void disableWrite();
void enableWrite();

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT objDriver,
    IN PUNICODE_STRING ustrRegeditPath
);

NTSTATUS driverUnload(
    IN PDRIVER_OBJECT objDriver
);

NTSTATUS driverPass(
    IN PDEVICE_OBJECT objDriver,
    IN PIRP objIrp
);

/**
 * @brief 获取函数在某个dll文件内的索引值
 * @param [IN] ustrDllFileName 需要获取的函数所在的dll文件
 *        [IN] pszFuncName 需要获取的函数名称 (这里为什么不用UNICODE_STRING，需要测试一下)
 * @return 如果查找到了，返回对应的索引值 否则返回0
 */
ULONG GetFuncIndex(
    IN UNICODE_STRING ustrDllFileName,
    IN PCHAR pszFuncName
);

/**
 * @brief dll映射到内存
 * @param [IN] ustrDllFileName 映射的dll文件
 *        [OUT] phFile dll文件句柄
 *        [OUT] phSection 节对象句柄
 *        [OUT] ppBaseAddress dll文件基地址
 */
NTSTATUS DllFileMap(
    IN UNICODE_STRING ustrDllFileName,
    OUT HANDLE* phFile,
    OUT HANDLE* phSection,
    OUT PVOID* ppBaseAddress
);

/**
 * @brief 从导出表中获取索引函数
 * @param [IN] pBaseAddress dll文件的基地址
 *        [IN] pszFunctionName 需要获取索引的函数名
 * @return 如果找到该函数 返回该函数的索引号，否则返回0
 * @note 这个函数中结构体里的地址都是相对地址，加上基地址就是真实地址
 */
ULONG GetIndexFromExportTable(
    IN PVOID pBaseAddress,
    IN PUCHAR pszFunctionName
);

/**
 * @brief 安装HOOK
 * @param [IN] ustrDllFileName 需要获取的函数所在的dll文件
 *        [IN] pszFuncName 需要获取的函数名称 (这里为什么不用UNICODE_STRING，需要测试一下)
 *        [IN] ulMyFuncAddr hook后的新函数地址
 */
VOID InstallHook(
    IN UNICODE_STRING ustrDllFileName,
    IN PCHAR pszFuncName,
    IN ULONG ulMyFuncAddr
);

/**
 * @brief 卸载HOOK
 */
VOID UnLoadHook(
);

/**
 * @brief hook后的函数
 */
NTSTATUS MyHookZwTerminateProcess(
    HANDLE processHandle,
    NTSTATUS exitStatus
);
