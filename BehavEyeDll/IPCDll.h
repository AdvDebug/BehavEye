#pragma once
void* CreatePipeServer();
bool WritePipeServer(void* hPipe, const char* Buffer);
bool WritePipeServer(void* hPipe, const wchar_t* Buffer);