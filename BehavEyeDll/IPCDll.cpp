#include "pch.h"
#include "IPCDll.h"
#include <Windows.h>
#include <string>
#include <codecvt>

void* CreatePipeServer()
{
    HANDLE hPipe = CreateNamedPipe(L"\\\\.\\pipe\\behaveye",PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 0, 0, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
        ExitProcess(0);
    return hPipe;
}

bool WritePipeServer(void* hPipe, const char* Buffer)
{
    if (!hPipe || hPipe == INVALID_HANDLE_VALUE)
        ExitProcess(0);
    DWORD BytesWritten = 0;
    if (!WriteFile(hPipe, Buffer, strlen(Buffer), &BytesWritten, NULL))
    {
        DWORD LastError = GetLastError();
        if (LastError == ERROR_BROKEN_PIPE)
            ExitProcess(0);
        return false;
    }
}

bool WritePipeServer(void* hPipe, const wchar_t* Buffer)
{
    if (!hPipe || hPipe == INVALID_HANDLE_VALUE)
        ExitProcess(0);
    DWORD BytesWritten = 0;
    std::wstring_convert<std::codecvt_utf8<wchar_t>> Converter;
    std::string message2 = Converter.to_bytes(Buffer);
    if (!WriteFile(hPipe, message2.c_str(), message2.size(), &BytesWritten, NULL))
    {
        DWORD LastError = GetLastError();
        if (LastError == ERROR_BROKEN_PIPE)
            ExitProcess(0);
        return false;
    }
    return true;
}