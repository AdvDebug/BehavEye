#include "IPC.h"
#include <Windows.h>

void* GetPipe()
{
    char Pipe[] = "\\\\.\\pipe\\behaveye";
    void* hPipe = NULL;
    while (true)
    {
        hPipe = CreateFileA(Pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            break;
        }
        Sleep(500);
    }
    return hPipe;
}

bool WritePipe(void* hPipe, char* Buffer)
{
    if (!hPipe || hPipe == INVALID_HANDLE_VALUE)
        return false;
    DWORD BytesWritten = 0;
    return WriteFile(hPipe, Buffer, strlen(Buffer), &BytesWritten, NULL);
}