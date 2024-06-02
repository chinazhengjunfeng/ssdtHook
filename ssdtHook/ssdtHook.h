#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <ntddk.h>
#include <stdlib.h>

#define MAX_PROCESS_ARRAY_LENGTH     10 //��ౣ��10������
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;        // �ļ��Ĳ���ʱ��
    USHORT    MajorVersion;
    USHORT    MinorVersion;
    ULONG   Name;                  // ָ���ļ�����RVA
    ULONG   Base;                  // ������������ʼ���
    ULONG   NumberOfFunctions;     // ������������
    ULONG   NumberOfNames;         // �����Ƶ�������������
    ULONG   AddressOfFunctions;    // ����������ַ���RVA
    ULONG   AddressOfNames;        // �������Ƶ�ַ���RVA
    ULONG   AddressOfNameOrdinals; // ��������ű��RVA
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    USHORT   e_magic;                     // MZ��� 0x5a4d 
    USHORT   e_cblp;                      // ���(����)ҳ�е��ֽ���
    USHORT   e_cp;                        // �ļ��е�ȫ���Ͳ���ҳ��
    USHORT   e_crlc;                      // �ض�λ���е�ָ����
    USHORT   e_cparhdr;                   // ͷ���ߴ��Զ���Ϊ��λ
    USHORT   e_minalloc;                  // �������С���Ӷ�
    USHORT   e_maxalloc;                  // �������󸽼Ӷ�
    USHORT   e_ss;                        // ��ʼ��SSֵ(���ƫ����)
    USHORT   e_sp;                        // ��ʼ��SPֵ
    USHORT   e_csum;                      // ����У��ֵ
    USHORT   e_ip;                        // ��ʼ��IPֵ
    USHORT   e_cs;                        // ��ʼ��SSֵ
    USHORT   e_lfarlc;                    // �ض�λ����ֽ�ƫ����
    USHORT   e_ovno;                      // ���Ǻ�
    USHORT   e_res[4];                    // ������
    USHORT   e_oemid;                     // OEM��ʶ��(���m_oeminfo)
    USHORT   e_oeminfo;                   // OEM��Ϣ
    USHORT   e_res2[10];                  // ������
    LONG   e_lfanew;                    // NTͷ(PE���)������ļ���ƫ�Ƶ�ַ
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
    // ����������Ŀ¼���飬�������ݿɸ�����Ҫ����
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
    ULONG Signature;//PE��� 0x00004550 
    IMAGE_FILE_HEADER FileHeader;//��׼PEͷ ��С�̶�Ϊ0x14(20)�ֽ�
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;//��չPEͷ 32BITĬ�ϴ�СΪ0xE0
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

// KSYSTEM_SERVICE_TABLE �� KSERVICE_TABLE_DESCRIPTOR
// �������� SSDT �ṹ
typedef struct _KSYSTEM_SERVICE_TABLE
{
    PULONG  ServiceTableBase;                               // SSDT (System Service Dispatch Table)�Ļ���ַ
    PULONG  ServiceCounterTableBase;                        // ���� checked builds, ���� SSDT ��ÿ�����񱻵��õĴ���
    ULONG   NumberOfService;                                // �������ĸ���, NumberOfService * 4 ����������ַ��Ĵ�С
    ULONG   ParamTableBase;                                 // SSPT(System Service Parameter Table)�Ļ���ַ
} KSYSTEM_SERVICE_TABLE, * PKSYSTEM_SERVICE_TABLE;

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
    KSYSTEM_SERVICE_TABLE   ntoskrnl; // ntoskrnl.exe �ķ�����
    KSYSTEM_SERVICE_TABLE   win32k;   // win32k.sys �ķ�����(GDI32.dll/User32.dll ���ں�֧��)
    KSYSTEM_SERVICE_TABLE   notUsed1;
    KSYSTEM_SERVICE_TABLE   notUsed2;
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;

extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;

ULONG g_ulArrayProtectPid[MAX_PROCESS_ARRAY_LENGTH];
ULONG g_ulArrayProtectPidLen = 0;

// windowsδ���ŵĽӿڣ���Ҫ����������ʹ��
UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
NTSTATUS PsLookupProcessByProcessId(__in HANDLE ProcessId, __deref_out PEPROCESS * Process);

/**
 * @brief: �������Ƿ��Ѿ��Ǳ������Ľ�����
 * @param: [in] uPid ��Ҫ���Ľ���id
 * @return: -1 ���Ǳ������Ľ��� ����ֵ �������Ľ���
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
 * @brief ��ȡ������ĳ��dll�ļ��ڵ�����ֵ
 * @param [IN] ustrDllFileName ��Ҫ��ȡ�ĺ������ڵ�dll�ļ�
 *        [IN] pszFuncName ��Ҫ��ȡ�ĺ������� (����Ϊʲô����UNICODE_STRING����Ҫ����һ��)
 * @return ������ҵ��ˣ����ض�Ӧ������ֵ ���򷵻�0
 */
ULONG GetFuncIndex(
    IN UNICODE_STRING ustrDllFileName,
    IN PCHAR pszFuncName
);

/**
 * @brief dllӳ�䵽�ڴ�
 * @param [IN] ustrDllFileName ӳ���dll�ļ�
 *        [OUT] phFile dll�ļ����
 *        [OUT] phSection �ڶ�����
 *        [OUT] ppBaseAddress dll�ļ�����ַ
 */
NTSTATUS DllFileMap(
    IN UNICODE_STRING ustrDllFileName,
    OUT HANDLE* phFile,
    OUT HANDLE* phSection,
    OUT PVOID* ppBaseAddress
);

/**
 * @brief �ӵ������л�ȡ��������
 * @param [IN] pBaseAddress dll�ļ��Ļ���ַ
 *        [IN] pszFunctionName ��Ҫ��ȡ�����ĺ�����
 * @return ����ҵ��ú��� ���ظú����������ţ����򷵻�0
 * @note ��������нṹ����ĵ�ַ������Ե�ַ�����ϻ���ַ������ʵ��ַ
 */
ULONG GetIndexFromExportTable(
    IN PVOID pBaseAddress,
    IN PUCHAR pszFunctionName
);

/**
 * @brief ��װHOOK
 * @param [IN] ustrDllFileName ��Ҫ��ȡ�ĺ������ڵ�dll�ļ�
 *        [IN] pszFuncName ��Ҫ��ȡ�ĺ������� (����Ϊʲô����UNICODE_STRING����Ҫ����һ��)
 *        [IN] ulMyFuncAddr hook����º�����ַ
 */
VOID InstallHook(
    IN UNICODE_STRING ustrDllFileName,
    IN PCHAR pszFuncName,
    IN ULONG ulMyFuncAddr
);

/**
 * @brief ж��HOOK
 */
VOID UnLoadHook(
);

/**
 * @brief hook��ĺ���
 */
NTSTATUS MyHookZwTerminateProcess(
    HANDLE processHandle,
    NTSTATUS exitStatus
);
