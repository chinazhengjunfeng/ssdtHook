//
// @file ssdtHook.c
// @date 2024.01.31
//
#pragma warning (disable: 4100; disable: 4057)

#include "ssdtHook.h"
#include <ntdef.h>

//根据 ZwServiceFunction 获取 ZwServiceFunction 在 SSDT 中所对应的服务的索引号
#define SYSCALL_INDEX(ServiceFunction) (*(PULONG)((PUCHAR)ServiceFunction + 1)) 

//根据ZwServiceFunction 来获得服务在 SSDT 中的索引号，然后再通过该索引号来获取ServiceFunction的地址 
#define SYSCALL_FUNCTION(ServiceFunction) KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[SYSCALL_INDEX(ServiceFunction)]

typedef NTSTATUS(__stdcall* NewNtOpenProcess)
(
    __out PHANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId
    );

typedef NTSTATUS(*pZwTerminateProcess)(
    IN HANDLE ProcessHandle, 
    IN NTSTATUS ExitStatus
    );

static ULONG gs_ulIndex = 0;
static ULONG gs_ulOldServiceAddress = 0;    // 原始的索引对应的地址
static ULONG gs_ulNewServiceAddress = 0;    // HOOK之后的服务新地址
NewNtOpenProcess gs_newNtOpenProcess;
ULONG ValidateProcessNeedProtect(ULONG uPid)
{
    ULONG i = 0;

    if (uPid == 0)
    {
        return MAX_PROCESS_ARRAY_LENGTH;
    }

    for (i = 0; i < g_ulArrayProtectPidLen && i < MAX_PROCESS_ARRAY_LENGTH; ++i)
    {
        if (uPid == g_ulArrayProtectPid[i])
        {
            return i;
        }
    }
    return MAX_PROCESS_ARRAY_LENGTH;
}

//设置为不可写
void disableWrite()
{
    __try
    {
        _asm
        {
            mov eax, cr0
            or eax, 10000h
            mov cr0, eax
            sti
        }
    }
    __except (1)
    {
        DbgPrint("DisableWrite执行失败！\n");
    }
}
// 设置为可写
void enableWrite()
{
    __try
    {
        _asm
        {
            cli
            mov eax, cr0
            and eax, not 10000h //and eax,0FFFEFFFFh
            mov cr0, eax
        }
    }
    __except (1)
    {
        DbgPrint("EnableWrite执行失败！\n");
    }
}

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT objDriver,
    IN PUNICODE_STRING ustrRegeditPath
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG i;
    DbgPrint("HELLO\n");
//#ifdef DBG
//    __asm int 3
//#endif
    objDriver->DriverUnload = driverUnload;
    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        objDriver->MajorFunction[i] = driverPass;
    }
    UNICODE_STRING ustrDllFileName;
    // ??表示"Win32根"(Win32 root) 或驱动器全局命名空间 这个路径表示绝对路径C:\\Windows\\System32\\ntdll.dll 这种方式可以确保在文件系统中的引用文件时没有歧义
    RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll"); 
    InstallHook(ustrDllFileName, "ZwTerminateProcess", (ULONG)MyHookZwTerminateProcess);
    //ULONG ulIndex = GetFuncIndex(ustrDllFileName, "ZwTerminateProcess");
    //DbgPrint("ZwTerminateProcess index = %d\n", ulIndex);
    return ntStatus;
}

NTSTATUS driverUnload(
    IN PDRIVER_OBJECT objDriver
)
{
    UnLoadHook();
    return STATUS_SUCCESS;
}

NTSTATUS driverPass(
    IN PDEVICE_OBJECT objDriver,
    IN PIRP objIrp
)
{
    NTSTATUS statusRes = STATUS_SUCCESS;
    objIrp->IoStatus.Status = statusRes;
    objIrp->IoStatus.Information = 0;
    IoCompleteRequest(objIrp, IO_NO_INCREMENT);
    return statusRes;
}

ULONG GetFuncIndex(
    IN UNICODE_STRING ustrDllFileName,
    IN PCHAR pszFuncName
)
{
    ULONG ulFuncIndex = 0; // 函数在ssdt表中的索引位置
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    PVOID pBaseAddress = NULL; // 基地址

    // 获取dll映射到内存中的地址
    status = DllFileMap(ustrDllFileName, &hFile, &hSection, &pBaseAddress);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("DllFileMap Error! error: 0x%X\n", status);
        return ulFuncIndex;
    }
    
    ulFuncIndex = GetIndexFromExportTable(pBaseAddress, pszFuncName);
    
    ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
    ZwClose(hSection);
    ZwClose(hFile);

    return ulFuncIndex;
}

NTSTATUS DllFileMap(
    IN UNICODE_STRING ustrDllFileName,
    OUT HANDLE* phFile,
    OUT HANDLE* phSection,
    OUT PVOID* ppBaseAddress
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    OBJECT_ATTRIBUTES objAttributes = { 0 };
    IO_STATUS_BLOCK iosb = { 0 };
    PVOID pBaseAddress = NULL;
    SIZE_T sizeView = 0;

    // 打开dll文件，并获取文件句柄
    InitializeObjectAttributes(&objAttributes, &ustrDllFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ntStatus = ZwOpenFile(&hFile, GENERIC_READ, &objAttributes, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(ntStatus))
    {
        DbgPrint("ZwOpenFile failed! error: 0x%X\n", ntStatus);
        return ntStatus;
    }

    // 创建一个节对象，以PE结构中的SectionAligment大小对其映射文件
    ntStatus = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0X1000000, hFile);
    if (!NT_SUCCESS(ntStatus))
    {
        ZwClose(hFile);
        DbgPrint("ZwCreateSection failed! error: 0x%X\n", ntStatus);
        return ntStatus;
    }

    // 映射内存
    ntStatus = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress,
        0, 1024, 0, &sizeView, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
    if (!NT_SUCCESS(ntStatus))
    {
        ZwClose(hSection);
        ZwClose(hFile);
        DbgPrint("ZwMapViewOfSection failed! error: 0x%X\n", ntStatus);
        return ntStatus;
    }

    // 返回数据
    *phFile = hFile;
    *phSection = hSection;
    *ppBaseAddress = pBaseAddress;
    return ntStatus;
}

ULONG GetIndexFromExportTable(
    IN PVOID pBaseAddress,
    IN PUCHAR pszFunctionName
)
{
    ULONG ulFuncIndex = 0;
    // Dos Header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;

    // NT Header
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);

    // Export Table
    PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

    // 有名称的导出函数个数
    ULONG ulNumberOfNames = pExportTable->NumberOfNames;

    // 导出名称地址表
    PULONG pulNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
    PCHAR pszName = NULL;

    // 遍历导出表
    for (ULONG i = 0; i < ulNumberOfNames; ++i)
    {
        pszName = (PCHAR)((PUCHAR)pDosHeader + pulNameArray[i]);
        // 判断是否是查找的函数
        if (0 == _strnicmp(pszFunctionName, pszName, strlen(pszFunctionName)))
        {
            USHORT uHint = *(USHORT*)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
            ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
            PVOID pvFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
#ifdef _WIN64
            ulFuncIndex = *(ULONG*)((PUCHAR)pvFuncAddr + 4);
#else
            ulFuncIndex = *(ULONG*)((PUCHAR)pvFuncAddr + 1);
#endif
            DbgPrint("uHint = %d, ulFuncAddr = 0x%x, pvFuncAddr = 0x%x\n", uHint, ulFuncAddr, pvFuncAddr);
            //gs_ulOldServiceAddress = ulFuncAddr;
            gs_ulOldServiceAddress = KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[gs_ulIndex];
            break;
        }
    }
    return ulFuncIndex;
}

VOID InstallHook(
    IN UNICODE_STRING ustrDllFileName,
    IN PCHAR pszFuncName,
    IN ULONG ulMyFuncAddr
)
{
    // 获取函数索引及地址
    gs_ulIndex = GetFuncIndex(ustrDllFileName, pszFuncName);
    //ULONG ulOldFuncAddr = gs_ulOldServiceAddress;
    gs_ulNewServiceAddress = ulMyFuncAddr;
    DbgPrint("HOOK func addr = 0x%x, index = %d, new func addr = 0x%x\n", gs_ulOldServiceAddress, gs_ulIndex, gs_ulNewServiceAddress);
    
    // 设置页面可写
    enableWrite();

    // 替换函数地址为新地址
    KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[gs_ulIndex] = gs_ulNewServiceAddress;
    //ulOldFuncAddr = gs_ulNewServiceAddress;

    // 恢复页面不可写
    disableWrite();
}

VOID UnLoadHook(
)
{
    //ULONG ulOldFuncAddr = gs_ulNewServiceAddress;
    DbgPrint("HOOK func addr = 0x%x, new func addr = 0x%x\n", gs_ulOldServiceAddress, gs_ulNewServiceAddress);

    // 设置页面可写
    enableWrite();

    // 替换函数地址为旧地址
    KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[gs_ulIndex] = gs_ulOldServiceAddress;
    //ulOldFuncAddr = gs_ulOldServiceAddress;

    // 恢复页面不可写
    disableWrite();
}

NTSTATUS MyHookZwTerminateProcess(
    HANDLE processHandle,
    NTSTATUS exitStatus
)
{
    ULONG ulPid;
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PEPROCESS pEprocess;

    ntStatus = ObReferenceObjectByHandle(processHandle, FILE_READ_DATA, NULL, KernelMode, (PVOID*)&pEprocess, NULL);
    if (!NT_SUCCESS(ntStatus))
    {
        DbgPrint("ObReferenceObject failed! error = 0x%x\n", ntStatus);
        return ntStatus;
    }

    ulPid = (ULONG)PsGetProcessId(pEprocess);
    DbgPrint("NtTerminateProcess Process Id: %d\n", ulPid);
    if (1020 == ulPid)
    {
        return STATUS_ACCESS_DENIED;
    }
    return ((pZwTerminateProcess)gs_ulOldServiceAddress)(processHandle, exitStatus);
}

