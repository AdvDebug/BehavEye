#include <iostream>
#include <Windows.h>
#include <string>
#include "IPC.h"
#include <fcntl.h>
#include <corecrt_io.h>
#include <algorithm>
#include <psapi.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

#define DEFAULT_COLOR FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE

void ChangeConsoleColor(int Color)
{
    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hStd, Color);
}

void PrintLogo()
{
    ChangeConsoleColor(FOREGROUND_GREEN);
    _setmode(_fileno(stdout), _O_U16TEXT);
    wprintf(L"%s", L"██████╗ ███████╗██╗  ██╗ █████╗ ██╗   ██╗███████╗██╗   ██╗███████╗\n██╔══██╗██╔════╝██║  ██║██╔══██╗██║   ██║██╔════╝╚██╗ ██╔╝██╔════╝\n██████╔╝█████╗  ███████║███████║██║   ██║█████╗   ╚████╔╝ █████╗\n██╔══██╗██╔══╝  ██╔══██║██╔══██║╚██╗ ██╔╝██╔══╝    ╚██╔╝  ██╔══╝\n██████╔╝███████╗██║  ██║██║  ██║ ╚████╔╝ ███████╗   ██║   ███████╗\n╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝   ╚═╝   ╚══════╝\n\n");
    _setmode(_fileno(stdout), _O_TEXT);
    ChangeConsoleColor(DEFAULT_COLOR);
}

void PrintColored(const char* Text, int Color)
{
    ChangeConsoleColor(Color);
    printf("%s", Text);
    ChangeConsoleColor(DEFAULT_COLOR);
}

bool Inject(HANDLE hProcess)
{
    char DllPath[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH - 1, DllPath) != 0)
    {
        strcat_s(DllPath, sizeof(DllPath), "\\BehavEyeDll.dll");
        DWORD attrib = GetFileAttributesA(DllPath);
        if (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            LPVOID LoadLibraryAddress = GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "LoadLibraryA");
            if (LoadLibraryAddress != NULL)
            {
                LPVOID Allocation = VirtualAllocEx(hProcess, NULL, strlen(DllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                WriteProcessMemory(hProcess, Allocation, DllPath, strlen(DllPath), NULL);
                HANDLE InjectionThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, Allocation, 0, NULL);
                WaitForSingleObject(InjectionThread, INFINITE);
                VirtualFreeEx(hProcess, Allocation, strlen(DllPath), MEM_RELEASE);
                CloseHandle(InjectionThread);
                return true;
            }
        }
    }
    return false;
}

bool SetCurrentDirectoryEx(HANDLE hProcess)
{
    char szFullPath[MAX_PATH + 1];
    if (GetModuleFileNameExA(hProcess, NULL, szFullPath, MAX_PATH) > 0)
    {
        if (PathRemoveFileSpecA(szFullPath))
        {
            LPVOID Allocation = VirtualAllocEx(hProcess, NULL, strlen(szFullPath), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            LPVOID SetCurrentDir = GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "SetCurrentDirectoryA");
            if (Allocation != NULL)
            {
                if (WriteProcessMemory(hProcess, Allocation, szFullPath, strlen(szFullPath), NULL))
                {
                    HANDLE InjectionThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)SetCurrentDir, Allocation, 0, NULL);
                    WaitForSingleObject(InjectionThread, INFINITE);
                    VirtualFreeEx(hProcess, Allocation, strlen(szFullPath), MEM_RELEASE);
                    CloseHandle(InjectionThread);
                    return true;
                }
            }
        }
    }
    return false;
}

bool CreateAndInject(const char* Path)
{
    STARTUPINFOA Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    std::string Contain(Path);
    std::string FinalBuffer;
    if (Contain.rfind(" ") == 0)
    {
        std::string FinalBuffer;
        FinalBuffer.append("\"");
        FinalBuffer.append(Path);
        FinalBuffer.append("\"");
    }
    else
    {
        FinalBuffer.append(Path);
    }
    if (CreateProcessA(NULL, (LPSTR)FinalBuffer.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &Si, &Pi))
    {
        SetCurrentDirectoryEx(Pi.hProcess);
        if (Inject(Pi.hProcess))
        {
            CloseHandle(Pi.hProcess);
            ResumeThread(Pi.hThread);
            CloseHandle(Pi.hThread);
            return true;
        }
    }
    return false;
}

void Exit()
{
    ChangeConsoleColor(DEFAULT_COLOR);
    exit(0);
}

BOOL IsPresentCreate(char* Path)
{
    HANDLE hFile = CreateFileA(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD LastError = GetLastError();
        if (LastError == ERROR_FILE_EXISTS)
            return true;
        else
            return false;
    }
    CloseHandle(hFile);
    return true;
}

BOOL WriteData(char* Buffer)
{
    char StoringPath[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH - 1, StoringPath) != 0)
    {
        strcat_s(StoringPath, sizeof(StoringPath), "\\BehaviorLogs.txt");
        if (IsPresentCreate(StoringPath))
        {
            std::string NewBuf(Buffer);
            NewBuf.append("\n\n");
            HANDLE hFile = CreateFileA(StoringPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                BOOL Success = WriteFile(hFile, NewBuf.c_str(), NewBuf.size(), NULL, NULL);
                CloseHandle(hFile);
                return Success;
            }
        }
    }
    return false;
}

BOOL SaveFile()
{
    char Buffer[3];
    printf("\nSave results to a file (Y/N): ");
    std::cin >> Buffer;
    std::string Decide(Buffer);
    std::transform(Decide.begin(), Decide.end(), Decide.begin(),
        [](unsigned char c) { return std::tolower(c); });
    if (Decide.compare("y") == 0)
        return true;
    else if (Decide.compare("n") == 0)
        return false;
    else
        Exit();
}

void ReadPipe(BOOL SaveToFile)
{
    printf("Waiting for the pipe...\n");
    void* hPipe = GetPipe();
    if (hPipe != NULL)
    {
        system("cls");
        PrintLogo();
        printf("Connected to the process...\n");
        char Start[] = "begin";
        if (WritePipe(hPipe, Start))
        {
            char SavePath[MAX_PATH];
            if (SaveToFile)
                printf("Began Monitoring, now all the output will be written to the current program directory.\n");
            else
                printf("Began monitoring, now waiting for anything...\n\n");
            ChangeConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            while (true)
            {
                char Buffer[4096];
                memset(Buffer, 0, sizeof(Buffer));
                DWORD BytesRead = 0;
                if (!ReadFile(hPipe, Buffer, sizeof(Buffer) - 1, &BytesRead, NULL))
                {
                    DWORD LastError = GetLastError();
                    if (LastError == ERROR_BROKEN_PIPE)
                    {
                        PrintColored("Lost Connection with the process...", FOREGROUND_RED);
                        getchar();
                        break;
                    }
                }
                else
                {
                    if (BytesRead > 0)
                    {
                        if (Buffer != NULL)
                        {
                            if (SaveToFile)
                            {
                                WriteData(Buffer);
                            }
                            else
                            {
                                printf_s("%s\n\n", Buffer);
                            }
                        }
                    }
                }
            }
        }
        else
        {
            printf("Error writing to pipe, error code: %i", GetLastError());
        }
    }
    else
    {
        system("cls");
        printf("Error getting pipe handle, error code: %i", GetLastError());
    }
}

int main(int argc, char** argv)
{
    SetConsoleTitle(L"BehavEye Monitoring");
    PrintLogo();
    if (argc > 1)
    {
        std::string Arg = argv[1];
        int value = std::atoi(Arg.c_str());
        if (value != 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, value);
            if (hProcess != INVALID_HANDLE_VALUE)
            {
                if (GetProcessId(hProcess) == GetCurrentProcessId())
                {
                    PrintColored("What the...?", FOREGROUND_RED);
                    getchar();
                    ExitProcess(0);
                }
                else
                {
                    if (Inject(hProcess))
                    {
                        BOOL Save = SaveFile();
                        ReadPipe(Save);
                    }
                    else
                    {
                        printf("Failed to inject to the process, error code: %i", GetLastError());
                    }
                }
            }
            else
            {
                printf("Failed to open a handle to the process...");
            }
            getchar();
            Exit();
        }
        else
        {
            if (CreateAndInject(Arg.c_str()))
            {
                BOOL Save = SaveFile();
                ReadPipe(Save);
            }
            else
            {
                printf("Failed, error code: %i", GetLastError());
            }
            getchar();
            Exit();
        }
    }
    ChangeConsoleColor(FOREGROUND_GREEN);
    printf("1. Create and Monitor a program.\n2. Monitor an already running program.\n\n");
    ChangeConsoleColor(DEFAULT_COLOR);
    printf("Option: ");
    int Option = 0;
    std::cin >> Option;
    system("cls");
    if (Option == 1)
    {
        PrintLogo();
        PrintColored("Program Path: ", FOREGROUND_GREEN);
        std::string Path;
        std::cin.ignore(1);
        std::getline(std::cin, Path);
        BOOL Save = SaveFile();
        if (CreateAndInject(Path.c_str()))
        {
            ReadPipe(Save);
        }
        else
        {
            printf("Error creating the process: %i", GetLastError());
        }
        getchar();
    }
    else if (Option == 2)
    {
        PrintLogo();
        PrintColored("Process ID: ", FOREGROUND_GREEN);
        int PID = 0;
        std::cin >> PID;
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
        if (hProcess != INVALID_HANDLE_VALUE)
        {
            if (GetProcessId(hProcess) == GetCurrentProcessId())
            {
                PrintColored("What the...?", FOREGROUND_RED);
            }
            else
            {
                BOOL Save = SaveFile();
                if (Inject(hProcess))
                {
                    ReadPipe(Save);
                }
                else
                {
                    system("cls");
                    printf("Error injecting the library to the process: %i", GetLastError());
                }
            }
        }
        else
        {
            printf("Error opening a handle to the process: %i", GetLastError());
        }
    }
    ChangeConsoleColor(DEFAULT_COLOR);
    return 0;
}