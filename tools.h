#pragma once
#include "Windows.h"

bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminsGroup;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminsGroup)) {
        CheckTokenMembership(NULL, adminsGroup, &isAdmin);
        FreeSid(adminsGroup);
    }
    return isAdmin != 0;
}

void SetAdmin() {
    if (!IsAdmin()) {
        wchar_t szFilePath[MAX_PATH];
        if (GetModuleFileName(NULL, szFilePath, MAX_PATH)) {
            SHELLEXECUTEINFO seInfo = { 0 };
            seInfo.cbSize = sizeof(SHELLEXECUTEINFO);
            seInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
            seInfo.hwnd = NULL;
            seInfo.lpVerb = L"runas";
            seInfo.lpFile = szFilePath;
            seInfo.nShow = SW_NORMAL;

            if (ShellExecuteEx(&seInfo)) {
                if (seInfo.hProcess) {
                    WaitForSingleObject(seInfo.hProcess, INFINITE);
                    CloseHandle(seInfo.hProcess);
                }
                ExitProcess(0);
            }
            else {
                std::cout << "Could not elevate program.\n";
                exit(0);
            }
        }
    }
}



void say_open()
{ 
    std::wcout << L"> ";
}

void say_options() { 
    //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    std::cout << "'exit' to exit, 'gcp' to check current garbage collected programs, 'open <file_name.gcl> to load a garbage collection list." << std::endl;
    std::cout << "enter a running program's name: " << std::endl;

    say_open();
}