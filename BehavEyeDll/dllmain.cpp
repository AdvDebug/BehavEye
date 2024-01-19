#include "pch.h"
#include "IPCDll.h"
#include <Windows.h>
#include <string>
#include <detours.h>
#include <atlstr.h>
#pragma comment(lib, "ws2_32.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG              Length;
    HANDLE             RootDirectory;
    PUNICODE_STRING    ObjectName;
    ULONG              Attributes;
    PVOID              SecurityDescriptor;
    PVOID              SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        LONG Status;
        PVOID Pointer;
    };
    ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _CLIENT_ID {
    PVOID              UniqueProcess;
    PVOID              UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef SOCKET(WINAPI* RealSocket)(int, int, int);
typedef int (WINAPI* RealSend)(SOCKET, const char*, int, int);
typedef int (WINAPI* RealRecv)(SOCKET, char*, int, int);
typedef NTSTATUS(NTAPI* RealNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* RealNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* RealNtWriteVirtualMemory)(HANDLE, PVOID, LPCVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* RealNtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef HHOOK(WINAPI* RealSetWindowsHookExAW)(int, HOOKPROC, HINSTANCE, DWORD);
typedef BOOL(WINAPI* RealGetUserNameW)(LPWSTR, LPDWORD);
typedef BOOL(WINAPI* RealGetUserNameA)(LPSTR, LPDWORD);
typedef LSTATUS(WINAPI* RealRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* RealRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef NTSTATUS(NTAPI* RealRtlQueryEnvironmentVariable)(PVOID, PWSTR, size_t, PWSTR, size_t, PSIZE_T);
typedef HANDLE(NTAPI* RealNtUserGetClipboardData)(UINT, void**);
typedef NTSTATUS(NTAPI* RealNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* RealNtLoadDriver)(PUNICODE_STRING);
typedef BOOL(WINAPI* RealCreateProcessInternalW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);
typedef NTSTATUS(NTAPI* RealNtShutdownSystem)(void*);
typedef NTSTATUS(NTAPI* RealNtSetSystemPowerState)(void*, void*, void*);
typedef NTSTATUS(NTAPI* RealNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR*, ULONG, PULONG);
typedef UINT(NTAPI* RealNtUserSendInput)(UINT, LPINPUT, INT);
typedef BOOL(NTAPI* RealNtUserBlockInput)(BOOL);
typedef NTSTATUS(NTAPI* RealNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* RealNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
typedef HWND(NTAPI* RealNtUserFindWindowEx)(HWND, HWND, PUNICODE_STRING, PUNICODE_STRING, DWORD);
typedef BOOL(WINAPI* RealGetLastInputInfo)(PLASTINPUTINFO);
typedef SC_HANDLE(WINAPI* RealCreateServiceA)(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
typedef SC_HANDLE(WINAPI* RealCreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
typedef NTSTATUS(NTAPI* RealNtDeviceIoControlFile)(HANDLE, HANDLE, void*, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* RealNtQuerySystemInformation)(int, PVOID, ULONG, PULONG);
void* hPipe = NULL;

RealNtCreateFile OriginalNtCreateFile = nullptr;
HANDLE NtCreateFileMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    WaitForSingleObject(NtCreateFileMutex, INFINITE);
    std::wstring szFileName(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(wchar_t));
    NTSTATUS Status = OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    if (NT_SUCCESS(Status))
    {
        std::wstring FileName;
        DWORD LastError = GetLastError();
        if (CreateDisposition == CREATE_ALWAYS)
        {
            if (LastError == ERROR_ALREADY_EXISTS)
            {
                FileName.append(L"File Handle Opened: ");
            }
            else
            {
                FileName.append(L"File Created: ");
            }
        }
        else
        {
            FileName.append(L"File Handle Opened: ");
        }
        FileName.append(szFileName.c_str());
        WritePipeServer(hPipe, FileName.c_str());
    }
    ReleaseMutex(NtCreateFileMutex);
    return Status;
}

RealSocket OriginalSocket = nullptr;
RealSend OriginalSend = nullptr;
RealRecv OriginalRecv = nullptr;

HANDLE SocketMutex = CreateMutex(NULL, FALSE, NULL);
SOCKET WINAPI HookedSocket(int af, int type, int protocol)
{
    WaitForSingleObject(SocketMutex, INFINITE);
    WritePipeServer(hPipe, "The Process have created a socket...");
    SOCKET sock = OriginalSocket(af, type, protocol);
    ReleaseMutex(SocketMutex);
    return sock;
}

HANDLE SendMutex = CreateMutex(NULL, FALSE, NULL);
int WINAPI HookedSend(SOCKET sock, const char* buf, int len, int flags)
{
    WaitForSingleObject(SendMutex, INFINITE);
    int Status = OriginalSend(sock, buf, len, flags);
    if (Status != SOCKET_ERROR)
    {
        sockaddr_in destAddress;
        int destAddrSize = sizeof(destAddress);
        getpeername(sock, (sockaddr*)&destAddress, &destAddrSize);
        char* Address = inet_ntoa(destAddress.sin_addr);
        std::string Info("The Process successfully sent \"");
        Info.append(std::to_string(Status));
        Info.append("\" bytes of data to: ");
        Info.append(Address);
        WritePipeServer(hPipe, Info.c_str());
    }
    else
    {
        std::string Info("The process tried to send data to an ip address but failed with the error code: ");
        Info.append(std::to_string(GetLastError()).c_str());
        WritePipeServer(hPipe, Info.c_str());
    }
    ReleaseMutex(SendMutex);
    return Status;
}

HANDLE RecvMutex = CreateMutex(NULL, FALSE, NULL);
int WINAPI HookedRecv(SOCKET sock, char* buf, int len, int flags)
{
    WaitForSingleObject(RecvMutex, INFINITE);
    int Status = OriginalRecv(sock, buf, len, flags);
    if (Status != SOCKET_ERROR)
    {
        sockaddr_in destAddress;
        int destAddrSize = sizeof(destAddress);
        getpeername(sock, (sockaddr*)&destAddress, &destAddrSize);
        char* Address = inet_ntoa(destAddress.sin_addr);
        std::string Info("The Process successfully recieved \"");
        Info.append(std::to_string(Status).c_str());
        Info.append("\" bytes of data from: ");
        Info.append(Address);
        WritePipeServer(hPipe, Info.c_str());
    }
    else
    {
        std::string Info("The process tried to receive data from an ip address but failed with the error code: ");
        Info.append(std::to_string(GetLastError()).c_str());
        WritePipeServer(hPipe, Info.c_str());
    }
    ReleaseMutex(RecvMutex);
    return Status;
}

RealNtOpenProcess OriginalNtOpenProcess = nullptr;
HANDLE NtOpenProcessMutex = CreateMutex(NULL, FALSE, NULL);

NTSTATUS NTAPI HookedNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    WaitForSingleObject(NtOpenProcessMutex, INFINITE);
    NTSTATUS Status = OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    if (NT_SUCCESS(Status))
    {
        DWORD PID = (DWORD)ClientId->UniqueProcess;
        std::string Process("Process handle opened to pid: ");
        Process.append(std::to_string(PID).c_str());
        WritePipeServer(hPipe, Process.c_str());
    }
    ReleaseMutex(NtOpenProcessMutex);
    return Status;
}

RealNtWriteVirtualMemory OriginalNtWriteVirtualMemory = nullptr;
HANDLE NtWriteVirtualMemoryMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, LPCVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten)
{
    WaitForSingleObject(NtWriteVirtualMemoryMutex, INFINITE);
    NTSTATUS Status = 0;
    DWORD PID = GetProcessId(ProcessHandle);
    if (PID != GetCurrentProcessId())
    {
        Status = OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        if (NT_SUCCESS(Status))
        {
            std::string Process("The Process wrote to the process memory of: ");
            Process.append(std::to_string(PID).c_str());
            WritePipeServer(hPipe, Process.c_str());
        }
        ReleaseMutex(NtWriteVirtualMemoryMutex);
        return Status;
    }
    else
    {
        Status = OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        ReleaseMutex(NtWriteVirtualMemoryMutex);
        return Status;
    }
}

RealNtReadVirtualMemory OriginalNtReadVirtualMemory = nullptr;
HANDLE NtReadVirtualMemoryMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead)
{
    WaitForSingleObject(NtReadVirtualMemoryMutex, INFINITE);
    NTSTATUS Status = 0;
    DWORD PID = GetProcessId(ProcessHandle);
    if (PID != GetCurrentProcessId())
    {
        Status = OriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
        if (NT_SUCCESS(Status))
        {
            std::string Process("The Process readed the process memory of: ");
            Process.append(std::to_string(PID).c_str());
            WritePipeServer(hPipe, Process.c_str());
        }
        ReleaseMutex(NtReadVirtualMemoryMutex);
        return Status;
    }
    else
    {
        Status = OriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
        ReleaseMutex(NtReadVirtualMemoryMutex);
        return Status;
    }
}

RealSetWindowsHookExAW OriginalSetWindowsHookExAW = nullptr;
HANDLE SetWindowsHookExAWMutex = CreateMutex(NULL, FALSE, NULL);
HHOOK WINAPI HookedSetWindowsHookExAW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId)
{
    WaitForSingleObject(SetWindowsHookExAWMutex, INFINITE);
    HHOOK Status = OriginalSetWindowsHookExAW(idHook, lpfn, hMod, dwThreadId);
    if (dwThreadId == 0 && Status != NULL)
    {
        if (idHook & WH_KEYBOARD || idHook & WH_KEYBOARD_LL)
        {
            WritePipeServer(hPipe, "The Process installed a global keyboard hook which can be used to monitor keystrokes.");
        }

        if (idHook & WH_MOUSE || idHook & WH_MOUSE_LL)
        {
            WritePipeServer(hPipe, "The Process installed a global mouse hook.");
        }
    }
    ReleaseMutex(SetWindowsHookExAWMutex);
    return Status;
}

RealGetUserNameW OriginalGetUserNameW = nullptr;
HANDLE GetUserNameWMutex = CreateMutex(NULL, FALSE, NULL);
BOOL WINAPI HookedGetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer)
{
    WaitForSingleObject(GetUserNameWMutex, INFINITE);
    BOOL Status = OriginalGetUserNameW(lpBuffer, pcbBuffer);
    if (Status)
        WritePipeServer(hPipe, "The Process readed the username of this pc.");
    ReleaseMutex(GetUserNameWMutex);
    return Status;
}

RealGetUserNameA OriginalGetUserNameA = nullptr;
HANDLE GetUserNameAMutex = CreateMutex(NULL, FALSE, NULL);
BOOL WINAPI HookedGetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer)
{
    WaitForSingleObject(GetUserNameAMutex, INFINITE);
    BOOL Status = OriginalGetUserNameA(lpBuffer, pcbBuffer);
    if (Status)
        WritePipeServer(hPipe, "The Process readed the username of this pc.");
    ReleaseMutex(GetUserNameAMutex);
    return Status;
}

RealRegOpenKeyExW OriginalRegOpenKeyExW = nullptr;
HANDLE RegOpenKeyExWMutex = CreateMutex(NULL, FALSE, NULL);
LSTATUS WINAPI HookedRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    WaitForSingleObject(RegOpenKeyExWMutex, INFINITE);
    LSTATUS Status = OriginalRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    if (Status == ERROR_SUCCESS)
    {
        if (lpSubKey != NULL)
        {
            std::wstring Info(L"The Process opened the registry key with the subkey: ");
            Info.append(lpSubKey);
            WritePipeServer(hPipe, Info.c_str());
        }
        else
        {
            WritePipeServer(hPipe, "The Process opened a registry key, but couldn't determine what is it.");
        }
    }
    ReleaseMutex(RegOpenKeyExWMutex);
    return Status;
}

std::wstring GetKeyPathFromKKEY(HKEY key)
{
    std::wstring keyPath;
    if (key != NULL)
    {
        HMODULE dll = GetModuleHandle(L"ntdll.dll");
        typedef DWORD(__stdcall* NtQueryKey)(HANDLE, int, PVOID, ULONG, PULONG);
        NtQueryKey Query = reinterpret_cast<NtQueryKey>(::GetProcAddress(dll, "NtQueryKey"));
        if (Query != NULL)
        {
            DWORD size = 0;
            DWORD result = 0;
            result = Query(key, 3, 0, 0, &size);
            if (result == 0xC0000023)
            {
                size = size + 2;
                wchar_t* buffer = new (std::nothrow) wchar_t[size / sizeof(wchar_t)];
                if (buffer != NULL)
                {
                    result = Query(key, 3, buffer, size, &size);
                    if (result == 0)
                    {
                        buffer[size / sizeof(wchar_t)] = L'\0';
                        keyPath = std::wstring(buffer + 2);
                    }

                    delete[] buffer;
                }
            }
        }
    }
    return keyPath;
}

RealRegSetValueExW OriginalRegSetValueExW = nullptr;
HANDLE RegSetValueExWMutex = CreateMutex(NULL, FALSE, NULL);
LSTATUS WINAPI HookedRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    WaitForSingleObject(RegSetValueExWMutex, INFINITE);
    LSTATUS Status = OriginalRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    if (Status == ERROR_SUCCESS)
    {
        if (lpValueName != NULL)
        {
            std::wstring Info(L"The Process modified/created a registry value with the value name \"");
            Info.append(lpValueName);
            Info.append(L"\"");
            std::wstring Path(GetKeyPathFromKKEY(hKey));
            if (Path.c_str() != NULL)
            {
                Info.append(L" from the registry path: ");
                Info.append(Path);
            }
            WritePipeServer(hPipe, Info.c_str());
        }
    }
    ReleaseMutex(RegSetValueExWMutex);
    return Status;
}

RealRtlQueryEnvironmentVariable OriginalRtlQueryEnvironmentVariable = nullptr;
HANDLE RtlQueryEnvironmentVariableMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedRtlQueryEnvironmentVariable(PVOID Environment, PWSTR Name, size_t NameLength, PWSTR Value, size_t ValueLength, PSIZE_T ReturnLength)
{
    WaitForSingleObject(RtlQueryEnvironmentVariableMutex, INFINITE);
    NTSTATUS Status = OriginalRtlQueryEnvironmentVariable(Environment, Name, NameLength, Value, ValueLength, ReturnLength);
    if (NT_SUCCESS(Status))
    {
        if (Name != NULL)
        {
            std::wstring Info(L"The Process readed the environment variable with the name: ");
            Info.append(Name);
            WritePipeServer(hPipe, Info.c_str());
        }
    }
    ReleaseMutex(RtlQueryEnvironmentVariableMutex);
    return Status;
}

RealNtUserGetClipboardData OriginalNtUserGetClipboardData = nullptr;
HANDLE NtUserGetClipboardDataMutex = CreateMutex(NULL, FALSE, NULL);
HANDLE NTAPI HookedNtUserGetClipboardData(UINT fmt, void** pgcd)
{
    WaitForSingleObject(NtUserGetClipboardDataMutex, INFINITE);
    HANDLE hClipboard = OriginalNtUserGetClipboardData(fmt, pgcd);
    if (hClipboard != NULL)
        WritePipeServer(hPipe, "The Process readed the clipboard.");
    ReleaseMutex(NtUserGetClipboardDataMutex);
    return hClipboard;
}

RealNtAllocateVirtualMemory OriginalNtAllocateVirtualMemory = nullptr;
HANDLE NtAllocateVirtualMemoryMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    WaitForSingleObject(NtAllocateVirtualMemoryMutex, INFINITE);
    NTSTATUS Status = OriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    if (NT_SUCCESS(Status))
    {
        DWORD PID = GetProcessId(ProcessHandle);
        if (PID != 0 && PID != GetCurrentProcessId())
        {
            std::string Info("The Process allocated virtual memory in the process with the id: ");
            Info.append(std::to_string(PID));
            WritePipeServer(hPipe, Info.c_str());
        }
    }
    ReleaseMutex(NtAllocateVirtualMemoryMutex);
    return Status;
}

RealNtLoadDriver OriginalNtLoadDriver = nullptr;
HANDLE NtLoadDriverMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtLoadDriver(PUNICODE_STRING DriverServiceName)
{
    WaitForSingleObject(NtLoadDriverMutex, INFINITE);
    NTSTATUS Status = OriginalNtLoadDriver(DriverServiceName);
    if (NT_SUCCESS(Status))
    {
        LPWSTR Driver = DriverServiceName->Buffer;
        if (Driver != NULL)
        {
            std::wstring Info(L"The Process loaded a driver: ");
            Info.append(Driver);
            WritePipeServer(hPipe, Info.c_str());
        }
    }
    ReleaseMutex(NtLoadDriverMutex);
    return Status;
}

BOOL IsParentSpoofed(DWORD dwCreationFlags, LPSTARTUPINFOW lpStartupInfo)
{
    if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT)
    {
        LPSTARTUPINFOEXW ExtendedSi = (LPSTARTUPINFOEXW)lpStartupInfo;
        LPPROC_THREAD_ATTRIBUTE_LIST AttributeList = ExtendedSi->lpAttributeList;
        if (AttributeList != NULL)
        {
            SIZE_T attributeListSize = 0;
            attributeListSize = *(SIZE_T*)AttributeList;
            for (SIZE_T i = 0; i < attributeListSize; i += sizeof(SIZE_T))
            {
                if (*(DWORD*)((SIZE_T)AttributeList + i) == PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
                {
                    return true;
                }
            }
        }
    }
    return false;
}

RealCreateProcessInternalW OriginalCreateProcessInternalW = nullptr;
HANDLE CreateProcessInternalWMutex = CreateMutex(NULL, FALSE, NULL);
BOOL WINAPI HookedCreateProcessInternalW(HANDLE hUserToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hRestrictedUserToken)
{
    WaitForSingleObject(CreateProcessInternalWMutex, INFINITE);
    BOOL IsSpoofedP = IsParentSpoofed(dwCreationFlags, lpStartupInfo);
    BOOL Status = OriginalCreateProcessInternalW(hUserToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hRestrictedUserToken);
    if (Status)
    {
        if (lpApplicationName != NULL)
        {
            std::wstring Info;
            if (lpCommandLine != NULL)
            {
                std::wstring Info;
                if (IsSpoofedP)
                {
                    Info.append(L"The Process created a new process with a spoofed parent from the filename \"");
                }
                else
                {
                    Info.append(L"The Process created a new process from the filename \"");
                }
                Info.append(lpApplicationName);
                Info.append(L"\" with the commandline: ");
                Info.append(lpCommandLine);
            }
            else
            {
                Info.append(L"The Process created a new process from the filename: ");
                Info.append(lpApplicationName);
            }
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (lpCommandLine != NULL)
        {
            std::wstring Info;
            if (IsSpoofedP)
            {
                Info.append(L"The Process created a new process with a spoofed parent from the commandline: ");
            }
            else
            {
                Info.append(L"The Process created a new process with the commandline: ");
            }
            Info.append(lpCommandLine);
            WritePipeServer(hPipe, Info.c_str());
        }
    }
    ReleaseMutex(CreateProcessInternalWMutex);
    return Status;
}

RealNtShutdownSystem OriginalNtShutdownSystem = nullptr;
HANDLE NtShutdownSystemMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtShutdownSystem(void* Action)
{
    WaitForSingleObject(NtShutdownSystemMutex, INFINITE);
    WritePipeServer(hPipe, "The Process tried to shutdown/reboot the system but this action has been blocked to continue the analysis.");
    ReleaseMutex(NtShutdownSystemMutex);
    return 0;
}

RealNtSetSystemPowerState OriginalNtSetSystemPowerState = nullptr;
HANDLE NtSetSystemPowerStateMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtSetSystemPowerState(void* SystemAction, void* MinSystemState, void* Flags)
{
    WaitForSingleObject(NtSetSystemPowerStateMutex, INFINITE);
    WritePipeServer(hPipe, "The Process tried to change the system power state, which could be used to shutdown/crash the system, this action has been blocked to continue the analysis.");
    ReleaseMutex(NtSetSystemPowerStateMutex);
    return 0;
}

RealNtRaiseHardError OriginalNtRaiseHardError = nullptr;
HANDLE NtRaiseHardErrorMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeString, PULONG_PTR* Parameters, ULONG ResponseOption, PULONG Response)
{
    WaitForSingleObject(NtRaiseHardErrorMutex, INFINITE);
    if (ResponseOption == 6)
    {
        WritePipeServer(hPipe, "The Process tried to trigger a BSOD but this action has been blocked to continue the analysis.");
        ReleaseMutex(NtRaiseHardErrorMutex);
        return 0;
    }
    NTSTATUS Status = OriginalNtRaiseHardError(ErrorStatus, NumberOfParameters, UnicodeString, Parameters, ResponseOption, Response);
    ReleaseMutex(NtRaiseHardErrorMutex);
    return Status;
}

RealNtUserSendInput OriginalNtUserSendInput = nullptr;
HANDLE NtUserSendInputMutex = CreateMutex(NULL, FALSE, NULL);
UINT NTAPI HookedNtUserSendInput(UINT nInputs, LPINPUT pInput, INT cbSize)
{
    WaitForSingleObject(NtUserSendInputMutex, INFINITE);
    UINT Status = OriginalNtUserSendInput(nInputs, pInput, cbSize);
    if (Status != 0)
    {
        DWORD Type = pInput->type;
        if (Type == INPUT_MOUSE)
        {
            std::string Info("The Process successfully inserted \"");
            Info.append(std::to_string(Status));
            Info.append("\" mouse input events.");
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (Type == INPUT_KEYBOARD)
        {
            std::string Info("The Process successfully inserted \"");
            Info.append(std::to_string(Status));
            Info.append("\" keyboard input events.");
            WritePipeServer(hPipe, Info.c_str());
        }
    }
    ReleaseMutex(NtUserSendInputMutex);
    return Status;
}

RealNtUserBlockInput OriginalNtUserBlockInput = nullptr;
HANDLE NtUserBlockInputMutex = CreateMutex(NULL, FALSE, NULL);
BOOL HookedNtUserBlockInput(BOOL fBlockInput)
{
    WaitForSingleObject(NtUserBlockInputMutex, INFINITE);
    BOOL Status = OriginalNtUserBlockInput(fBlockInput);
    if (Status)
    {
        if (fBlockInput)
        {
            WritePipeServer(hPipe, "The Process blocked input.");
        }
        else
        {
            WritePipeServer(hPipe, "The Process unblocked input.");
        }
    }
    ReleaseMutex(NtUserBlockInputMutex);
    return Status;
}

RealNtSetInformationProcess OriginalNtSetInformationProcess = nullptr;
HANDLE NtSetInformationProcessMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtSetInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
    WaitForSingleObject(NtSetInformationProcessMutex, INFINITE);
    NTSTATUS Status = OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
    if (NT_SUCCESS(Status))
    {
        DWORD PID = GetProcessId(ProcessHandle);
        if (ProcessInformationClass == 9)
        {
            if (PID != 0)
            {
                std::string Info("The Process possibly tries to change the token of the process: ");
                Info.append(std::to_string(PID));
                WritePipeServer(hPipe, Info.c_str());
            }
            else
            {
                std::string Info("The Process possibly tries to change the token of a process.");
            }
        }
        else if (ProcessInformationClass == 18)
        {
            if (PID != 0)
            {
                std::string Info("The Process possibly tries to change the priority of the process: ");
                Info.append(std::to_string(PID));
                WritePipeServer(hPipe, Info.c_str());
            }
            else
            {
                std::string Info("The Process possibly tries to change a process priority.");
            }
        }
        else if (ProcessInformationClass == 29)
        {
            if (PID != 0)
            {
                std::string Info("The Process possibly tries to make the process critical: ");
                Info.append(std::to_string(PID));
                WritePipeServer(hPipe, Info.c_str());
            }
            else
            {
                WritePipeServer(hPipe, "The Process possibly tries to make a process critical.");
            }
        }
        else if (ProcessInformationClass == 33)
        {
            if (PID != 0)
            {
                std::string Info("The Process possibly tries to change the i/o priority of the process: ");
                Info.append(std::to_string(PID));
                WritePipeServer(hPipe, Info.c_str());
            }
            else
            {
                std::string Info("The Process possibly tries to change a process i/o priority.");
            }
        }
        else if (ProcessInformationClass == 52)
        {
            if (PID != 0)
            {
                std::string Info("The Process possibly tries to remove/add an exploit mitigation to the process: ");
                Info.append(std::to_string(PID));
                WritePipeServer(hPipe, Info.c_str());
            }
            else
            {
                WritePipeServer(hPipe, "The Process possibly tries to remove/add an exploit mitigation to a process.");
            }
        }
    }
    ReleaseMutex(NtSetInformationProcessMutex);
    return Status;
}

RealNtSetInformationThread OriginalNtSetInformationThread = nullptr;
HANDLE NtSetInformationThreadMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtSetInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
    WaitForSingleObject(NtSetInformationThreadMutex, INFINITE);
    NTSTATUS Status = OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
    if (NT_SUCCESS(Status))
    {
        DWORD TID = GetThreadId(ThreadHandle);
        if (ThreadInformationClass == 5)
        {
            if (TID != 0)
            {
                std::string Info("The Process possibly tries to impersonate a token and apply it to the thread: ");
                Info.append(std::to_string(TID));
                WritePipeServer(hPipe, Info.c_str());
            }
            else
            {
                std::string Info("The Process possibly tries to impersonate a token and apply it to a thread.");
                WritePipeServer(hPipe, Info.c_str());
            }
        }
        else if (ThreadInformationClass == 17)
        {
            if (TID != 0)
            {
                std::string Info("The Process possibly tries to hide a thread from a debugger, the thread: ");
                Info.append(std::to_string(TID));
                WritePipeServer(hPipe, Info.c_str());
            }
            else
            {
                std::string Info("The Process possibly tries to hide a thread from a debugger.");
                WritePipeServer(hPipe, Info.c_str());
            }
        }
        else if (ThreadInformationClass == 18)
        {
            if (TID != 0)
            {
                std::string Info("The Process possibly tries to make a thread critical so that it triggers a BSOD if it got killed, the thread: ");
                Info.append(std::to_string(TID));
                WritePipeServer(hPipe, Info.c_str());
            }
            else
            {
                std::string Info("The Process possibly tries to make a thread critical to trigger a BSOD if it got killed.");
                WritePipeServer(hPipe, Info.c_str());
            }
        }
        else if (ThreadInformationClass == 22)
        {
            if (TID != 0)
            {
                std::string Info("The Process possibly tries to change the priority of a thread, the thread: ");
                Info.append(std::to_string(TID));
                WritePipeServer(hPipe, Info.c_str());
            }
            else
            {
                std::string Info("The Process possibly tries to change the thread priority of a thread.");
                WritePipeServer(hPipe, Info.c_str());
            }
        }
        else if (ThreadInformationClass == 24)
        {
            if (TID != 0)
            {
                std::string Info("The Process possibly tries to change the thread page priority, the thread: ");
                Info.append(std::to_string(TID));
                WritePipeServer(hPipe, Info.c_str());
            }
            else
            {
                std::string Info("The Process possibly tries to make a thread critical to trigger a BSOD if it got killed.");
                WritePipeServer(hPipe, Info.c_str());
            }
        }
    }
    ReleaseMutex(NtSetInformationThreadMutex);
    return Status;
}

RealNtUserFindWindowEx OriginalNtUserFindWindowEx = nullptr;
HANDLE NtUserFindWindowExMutex = CreateMutex(NULL, FALSE, NULL);
HWND HookedNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwUnknown)
{
    WaitForSingleObject(NtUserFindWindowExMutex, INFINITE);
    LPWSTR Class = lpszClass->Buffer;
    LPWSTR Window = lpszWindow->Buffer;
    if (Class != NULL)
    {
        std::wstring Info(L"The Process tried to find a window with the class name \"");
        Info.append(Class);
        Info.append(L"\"");
        if (Window != NULL)
        {
            Info.append(L" and the window name : ");
            Info.append(Window);
        }
        WritePipeServer(hPipe, Info.c_str());
    }
    else if (Window != NULL)
    {
        std::wstring Info(L"The Process tried to find a window with the window name \"");
        Info.append(Window);
        Info.append(L"\"");
        WritePipeServer(hPipe, Info.c_str());
    }
    HWND hWindow = OriginalNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwUnknown);
    ReleaseMutex(NtUserFindWindowExMutex);
    return hWindow;
}

RealGetLastInputInfo OriginalGetLastInputInfo = nullptr;
HANDLE GetLastInputInfoMutex = CreateMutex(NULL, FALSE, NULL);
BOOL WINAPI HookedGetLastInputInfo(PLASTINPUTINFO plii)
{
    WaitForSingleObject(GetLastInputInfoMutex, INFINITE);
    BOOL Status = OriginalGetLastInputInfo(plii);
    if (Status)
    {
        WritePipeServer(hPipe, "The Process got when was the last time the user has been active with the keyboard or mouse.");
    }
    ReleaseMutex(GetLastInputInfoMutex);
    return Status;
}

char* GetServiceType(DWORD dwServiceType)
{
    char Buffer[30];
    if (dwServiceType == SERVICE_WIN32_OWN_PROCESS)
    {
        strcpy_s(Buffer, sizeof(Buffer) - 1, "service ");
    }
    else if (dwServiceType == SERVICE_WIN32_SHARE_PROCESS)
    {
        strcpy_s(Buffer, sizeof(Buffer) - 1, "shared service ");
    }
    else if(dwServiceType == SERVICE_KERNEL_DRIVER)
    {
        strcpy_s(Buffer, sizeof(Buffer) - 1, "kernel driver ");
    }
    else if (dwServiceType == SERVICE_FILE_SYSTEM_DRIVER)
    {
        strcpy_s(Buffer, sizeof(Buffer) - 1, "file system driver ");
    }
    return Buffer;
}

wchar_t* GetServiceTypeW(DWORD dwServiceType)
{
    wchar_t Buffer[30];
    if (dwServiceType == SERVICE_WIN32_OWN_PROCESS)
    {
        wcsncpy_s(Buffer, L"service ", sizeof(Buffer) - 1);
    }
    else if (dwServiceType == SERVICE_WIN32_SHARE_PROCESS)
    {
        wcsncpy_s(Buffer, L"shared service ", sizeof(Buffer) - 1);
    }
    else if (dwServiceType == SERVICE_KERNEL_DRIVER)
    {
        wcsncpy_s(Buffer, L"kernel driver ", sizeof(Buffer) - 1);
    }
    else if (dwServiceType == SERVICE_FILE_SYSTEM_DRIVER)
    {
        wcsncpy_s(Buffer, L"file system driver ", sizeof(Buffer) - 1);
    }
    return Buffer;
}

RealCreateServiceA OriginalCreateServiceA = nullptr;
HANDLE CreateServiceAMutex = CreateMutex(NULL, FALSE, NULL);
SC_HANDLE WINAPI HookedCreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword)
{
    WaitForSingleObject(CreateServiceAMutex, INFINITE);
    std::string Type(GetServiceType(dwServiceType));
    SC_HANDLE hService = OriginalCreateServiceA(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
    if (hService != NULL)
    {
        if (Type.c_str() != NULL)
        {
            if (lpServiceName != NULL)
            {
                std::string Info("The Process created a ");
                Info.append(Type);
                Info.append("with the service name \"");
                Info.append(lpServiceName);
                Info.append("\"");
                Info.append(" and the ");
                Info.append(Type);
                Info.append("path is: ");
                Info.append(lpBinaryPathName);
                WritePipeServer(hPipe, Info.c_str());
            }
        }
    }
    ReleaseMutex(CreateServiceAMutex);
    return hService;
}

RealCreateServiceW OriginalCreateServiceW = nullptr;
HANDLE CreateServiceWMutex = CreateMutex(NULL, FALSE, NULL);
SC_HANDLE WINAPI HookedCreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword)
{
    WaitForSingleObject(CreateServiceAMutex, INFINITE);
    std::wstring Type(GetServiceTypeW(dwServiceType));
    SC_HANDLE hService = OriginalCreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
    if (hService != NULL)
    {
        if (Type.c_str() != NULL)
        {
            if (lpServiceName != NULL)
            {
                std::wstring Info(L"The Process created a ");
                Info.append(Type);
                Info.append(L"with the service name \"");
                Info.append(lpServiceName);
                Info.append(L"\"");
                Info.append(L" and the ");
                Info.append(Type);
                Info.append(L"path is: ");
                Info.append(lpBinaryPathName);
                WritePipeServer(hPipe, Info.c_str());
            }
        }
    }
    ReleaseMutex(CreateServiceAMutex);
    return hService;
}

typedef NTSTATUS(NTAPI* PNtQueryObject)(HANDLE, int, PVOID, ULONG, PULONG);
typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

//credits to KernelCactus project
DWORD GetNtPathFromHandle(HANDLE hDriver, wchar_t* Buffer)
{
    if (hDriver == 0 || hDriver == INVALID_HANDLE_VALUE)
        return ERROR_INVALID_HANDLE;
    PNtQueryObject NtQueryObject = (PNtQueryObject)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
    if (!NtQueryObject) {
        return ERROR_NOT_FOUND;
    }
    BYTE  u8_Buffer[2000];
    DWORD u32_ReqLength = 0;
    UNICODE_STRING* pk_Info = &((OBJECT_NAME_INFORMATION*)u8_Buffer)->Name;
    pk_Info->Buffer = 0;
    pk_Info->Length = 0;
    NtQueryObject(hDriver, 1, u8_Buffer, sizeof(u8_Buffer), &u32_ReqLength);
    if (!pk_Info->Buffer || !pk_Info->Length)
        return ERROR_FILE_NOT_FOUND;
    pk_Info->Buffer[pk_Info->Length / 2] = 0;
    CString TempBuffer[MAX_PATH + 1];
    *TempBuffer = pk_Info->Buffer;
    if (TempBuffer->Compare(L"\\Device\\ConDrv") == 0)
        return 1;
    ZeroMemory(Buffer, sizeof(Buffer));
    wcscpy_s(Buffer, wcslen(Buffer) - 1, TempBuffer->GetBuffer());
    TempBuffer->Empty();
    return 0;
}

RealNtDeviceIoControlFile OriginalNtDeviceIoControlFile = nullptr;
HANDLE NtDeviceIoControlFileMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS HookedNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, void* APCRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
    WaitForSingleObject(NtDeviceIoControlFileMutex, INFINITE);
    wchar_t Buffer[MAX_PATH + 1];
    DWORD bReturn = GetNtPathFromHandle(FileHandle, Buffer);
    NTSTATUS Status = OriginalNtDeviceIoControlFile(FileHandle, Event, APCRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    if (NT_SUCCESS(Status))
    {
        if (bReturn != 1)
        {
            std::wstring Info;
            if (bReturn == 0)
            {
                Info.append(L"The Process communicated with the driver \"");
                Info.append(Buffer);
                Info.append(L"\"");
            }
            else
            {
                Info.append(L"The Process communicated with a driver");
            }
            if (IoControlCode != NULL)
            {
                Info.append(L" with the control code \"");
                Info.append(std::to_wstring(IoControlCode));
                Info.append(L"\"");
            }

            if (InputBuffer != NULL)
            {
                Info.append(L" and sent a message to the driver with the size of \"");
                Info.append(std::to_wstring(InputBufferLength));
                Info.append(L"\"");
                if (OutputBuffer != NULL)
                {
                    Info.append(L", it also recieved an output from the driver with the size \"");
                    Info.append(std::to_wstring(OutputBufferLength));
                    Info.append(L"\"");
                }
            }
            else if (OutputBuffer != NULL)
            {
                Info.append(L" and recieved a message from the driver with the size of \"");
                Info.append(std::to_wstring(OutputBufferLength));
                Info.append(L"\"");
            }
            WritePipeServer(hPipe, Info.c_str());
        }
    }
    ReleaseMutex(NtDeviceIoControlFileMutex);
    return Status;
}

RealNtQuerySystemInformation OriginalNtQuerySystemInformation = nullptr;
HANDLE NtQuerySystemInformationMutex = CreateMutex(NULL, FALSE, NULL);
NTSTATUS NTAPI HookedNtQuerySystemInformation(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    WaitForSingleObject(NtQuerySystemInformationMutex, INFINITE);
    NTSTATUS Status = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (NT_SUCCESS(Status))
    {
        if (SystemInformationClass == 0x01)
        {
            std::string Info("The Process got the cpu information.");
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (SystemInformationClass == 0x02)
        {
            std::string Info("The Process retrieved all running processes on the system.");
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (SystemInformationClass == 0x39)
        {
            std::string Info("The Process retrieved all running processes on the system with extended information.");
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (SystemInformationClass == 0x10)
        {
            std::string Info("The Process enumerated all handles on the system.");
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (SystemInformationClass == 0x40)
        {
            std::string Info("The Process enumerated all handles on the system with extended information.");
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (SystemInformationClass == 0x91)
        {
            std::string Info("The Process tried to know if the system have secureboot enabled.");
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (SystemInformationClass == 0x8F)
        {
            std::string Info("The Process got secureboot policy info.");
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (SystemInformationClass == 0xAB)
        {
            std::string Info("The Process got the full secureboot policy info.");
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (SystemInformationClass == 0x67)
        {
            std::string Info("The Process tried to know if the system have code integrity checking enabled.");
            WritePipeServer(hPipe, Info.c_str());
        }
        else if (SystemInformationClass == 0x23)
        {
            std::string Info("The Process tried to know if kernel debugging are enabled on the system.");
            WritePipeServer(hPipe, Info.c_str());
        }
    }
    ReleaseMutex(NtQuerySystemInformationMutex);
    return Status;
}

void HookConnectionsAPIs()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalSocket = reinterpret_cast<RealSocket>(DetourFindFunction("ws2_32.dll", "socket"));
    DetourAttach(&(LPVOID&)OriginalSocket, HookedSocket);
    OriginalSend = reinterpret_cast<RealSend>(DetourFindFunction("ws2_32.dll", "send"));
    DetourAttach(&(LPVOID&)OriginalSend, HookedSend);
    OriginalRecv = reinterpret_cast<RealRecv>(DetourFindFunction("ws2_32.dll", "recv"));
    DetourAttach(&(LPVOID&)OriginalRecv, HookedRecv);
    DetourTransactionCommit();
}

void HookFileSystemAPIs()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalNtCreateFile = reinterpret_cast<RealNtCreateFile>(DetourFindFunction("ntdll.dll", "NtCreateFile"));
    DetourAttach(&(LPVOID&)OriginalNtCreateFile, HookedNtCreateFile);
    DetourTransactionCommit();
}

void HookProcessRelatedAPIs()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalNtOpenProcess = reinterpret_cast<RealNtOpenProcess>(DetourFindFunction("ntdll.dll", "NtOpenProcess"));
    DetourAttach(&(LPVOID&)OriginalNtOpenProcess, HookedNtOpenProcess);
    OriginalNtWriteVirtualMemory = reinterpret_cast<RealNtWriteVirtualMemory>(DetourFindFunction("ntdll.dll", "NtWriteVirtualMemory"));
    DetourAttach(&(LPVOID&)OriginalNtWriteVirtualMemory, HookedNtWriteVirtualMemory);
    OriginalNtReadVirtualMemory = reinterpret_cast<RealNtReadVirtualMemory>(DetourFindFunction("ntdll.dll", "NtReadVirtualMemory"));
    DetourAttach(&(LPVOID&)OriginalNtReadVirtualMemory, HookedNtReadVirtualMemory);
    OriginalNtSetInformationProcess = reinterpret_cast<RealNtSetInformationProcess>(DetourFindFunction("ntdll.dll", "NtSetInformationProcess"));
    DetourAttach(&(LPVOID&)OriginalNtSetInformationProcess, HookedNtSetInformationProcess);
    OriginalNtSetInformationThread = reinterpret_cast<RealNtSetInformationThread>(DetourFindFunction("ntdll.dll", "NtSetInformationThread"));
    DetourAttach(&(LPVOID&)OriginalNtSetInformationThread, HookedNtSetInformationThread);
    OriginalNtAllocateVirtualMemory = reinterpret_cast<RealNtAllocateVirtualMemory>(DetourFindFunction("ntdll.dll", "NtAllocateVirtualMemory"));
    DetourAttach(&(LPVOID&)OriginalNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);
    OriginalCreateProcessInternalW = reinterpret_cast<RealCreateProcessInternalW>(DetourFindFunction("kernelbase.dll", "CreateProcessInternalW"));
    DetourAttach(&(LPVOID&)OriginalCreateProcessInternalW, HookedCreateProcessInternalW);
    OriginalNtQuerySystemInformation = reinterpret_cast<RealNtQuerySystemInformation>(DetourFindFunction("ntdll.dll", "NtQuerySystemInformation"));
    DetourAttach(&(LPVOID&)OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
    DetourTransactionCommit();
}

void HookRegistryAPIs()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalRegOpenKeyExW = reinterpret_cast<RealRegOpenKeyExW>(DetourFindFunction("kernelbase.dll", "RegOpenKeyExW"));
    DetourAttach(&(LPVOID&)OriginalRegOpenKeyExW, HookedRegOpenKeyExW);
    OriginalRegSetValueExW = reinterpret_cast<RealRegSetValueExW>(DetourFindFunction("kernelbase.dll", "RegSetValueExW"));
    DetourAttach(&(LPVOID&)OriginalRegSetValueExW, HookedRegSetValueExW);
    DetourTransactionCommit();
}

void HookUserAPIs()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalSetWindowsHookExAW = reinterpret_cast<RealSetWindowsHookExAW> (DetourFindFunction("user32.dll", "SetWindowsHookExAW"));
    DetourAttach(&(LPVOID&)OriginalSetWindowsHookExAW, HookedSetWindowsHookExAW);
    OriginalNtUserSendInput = reinterpret_cast<RealNtUserSendInput>(DetourFindFunction("win32u.dll", "NtUserSendInput"));
    DetourAttach(&(LPVOID&)OriginalNtUserSendInput, HookedNtUserSendInput);
    OriginalNtUserBlockInput = reinterpret_cast<RealNtUserBlockInput>(DetourFindFunction("win32u.dll", "NtUserBlockInput"));
    DetourAttach(&(LPVOID&)OriginalNtUserBlockInput, HookedNtUserBlockInput);
    OriginalNtUserFindWindowEx = reinterpret_cast<RealNtUserFindWindowEx>(DetourFindFunction("win32u.dll", "NtUserFindWindowEx"));
    DetourAttach(&(LPVOID&)OriginalNtUserFindWindowEx, HookedNtUserFindWindowEx);
    OriginalGetLastInputInfo = reinterpret_cast<RealGetLastInputInfo>(DetourFindFunction("user32.dll", "GetLastInputInfo"));
    DetourAttach(&(LPVOID&)OriginalGetLastInputInfo, HookedGetLastInputInfo);
    OriginalNtUserGetClipboardData = reinterpret_cast<RealNtUserGetClipboardData>(DetourFindFunction("win32u.dll", "NtUserGetClipboardData"));
    DetourAttach(&(LPVOID&)OriginalNtUserGetClipboardData, HookedNtUserGetClipboardData);
    DetourTransactionCommit();
}

void HookDriverRelatedAPIs()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalCreateServiceA = reinterpret_cast<RealCreateServiceA>(DetourFindFunction("sechost.dll", "CreateServiceA"));
    DetourAttach(&(LPVOID&)OriginalCreateServiceA, HookedCreateServiceA);
    OriginalCreateServiceW = reinterpret_cast<RealCreateServiceW>(DetourFindFunction("sechost.dll", "CreateServiceW"));
    DetourAttach(&(LPVOID&)OriginalCreateServiceW, HookedCreateServiceW);
    OriginalNtLoadDriver = reinterpret_cast<RealNtLoadDriver>(DetourFindFunction("ntdll.dll", "NtLoadDriver"));
    DetourAttach(&(LPVOID&)OriginalNtLoadDriver, HookedNtLoadDriver);
    OriginalNtDeviceIoControlFile = reinterpret_cast<RealNtDeviceIoControlFile>(DetourFindFunction("ntdll.dll", "NtDeviceIoControlFile"));
    DetourAttach(&(LPVOID&)OriginalNtDeviceIoControlFile, HookedNtDeviceIoControlFile);
    DetourTransactionCommit();
}

void HookMisc()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalRtlQueryEnvironmentVariable = reinterpret_cast<RealRtlQueryEnvironmentVariable>(DetourFindFunction("ntdll.dll", "RtlQueryEnvironmentVariable"));
    DetourAttach(&(LPVOID&)OriginalRtlQueryEnvironmentVariable, HookedRtlQueryEnvironmentVariable);
    OriginalNtShutdownSystem = reinterpret_cast<RealNtShutdownSystem>(DetourFindFunction("ntdll.dll", "NtShutdownSystem"));
    DetourAttach(&(LPVOID&)OriginalNtShutdownSystem, HookedNtShutdownSystem);
    OriginalNtSetSystemPowerState = reinterpret_cast<RealNtSetSystemPowerState>(DetourFindFunction("ntdll.dll", "NtSetSystemPowerState"));
    DetourAttach(&(LPVOID&)OriginalNtSetSystemPowerState, HookedNtSetSystemPowerState);
    OriginalNtRaiseHardError = reinterpret_cast<RealNtRaiseHardError>(DetourFindFunction("ntdll.dll", "NtRaiseHardError"));
    DetourAttach(&(LPVOID&)OriginalNtRaiseHardError, HookedNtRaiseHardError);
    DetourTransactionCommit();
}

void HookAll()
{
    HookConnectionsAPIs();
    HookFileSystemAPIs();
    HookProcessRelatedAPIs();
    HookRegistryAPIs();
    HookUserAPIs();
    HookDriverRelatedAPIs();
    HookMisc();
}

void MainThread()
{
    hPipe = CreatePipeServer();
    if (hPipe != NULL)
    {
        if (ConnectNamedPipe(hPipe, NULL))
        {
            while (true)
            {
                char Buffer[512];
                memset(Buffer, 0, sizeof(Buffer));
                DWORD BytesRead = 0;
                ReadFile(hPipe, Buffer, sizeof(Buffer), &BytesRead, NULL);
                if (BytesRead > 0)
                {
                    if (strcmp(Buffer, "begin") == 0)
                    {
                        HookAll();
                        break;
                    }
                }
            }
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainThread, NULL, 0, NULL);
        if (hThread != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hThread);
            return TRUE;
        }
    }
    return FALSE;
}