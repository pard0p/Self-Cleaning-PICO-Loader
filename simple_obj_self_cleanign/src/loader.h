
#include <windows.h>

#define NT_SUCCESS(Status)      ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread()       ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess()      ((HANDLE)(LONG_PTR)-1)

typedef struct {
	DWORD   Length;
	DWORD   MaximumLength;
	PVOID   Buffer;
} USTRING;

/* Dynamic Function Resolution (DFR) Prototypes */

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
);

WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
);

WINBASEAPI HANDLE WINAPI KERNEL32$CreateTimerQueue(VOID);

WINBASEAPI BOOL WINAPI KERNEL32$CreateTimerQueueTimer(
	PHANDLE phNewTimer,
	HANDLE TimerQueue,
	WAITORTIMERCALLBACK Callback,
	PVOID Parameter,
	DWORD DueTime,
	DWORD Period,
	ULONG Flags
);

WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(
	HANDLE hHandle,
	DWORD dwMilliseconds
);

WINBASEAPI BOOL WINAPI KERNEL32$TerminateThread(
	HANDLE hThread,
	DWORD dwExitCode
);

WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread(VOID);

WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);

WINBASEAPI VOID WINAPI NTDLL$RtlZeroMemory(
	PVOID Destination,
	SIZE_T Length
);

WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD dwFreeType
);

WINBASEAPI BOOL WINAPI KERNEL32$DuplicateHandle(
	HANDLE hSourceProcessHandle,
	HANDLE hSourceHandle,
	HANDLE hTargetProcessHandle,
	LPHANDLE lpTargetHandle,
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	DWORD dwOptions
);