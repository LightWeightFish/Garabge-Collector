#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>

namespace fs = std::filesystem;

typedef std::string string;
typedef std::wstring wstring;

#include "tools.h"

std::vector<wstring> gcp;
bool SUPRESS_ERRORS = false;

struct Kernel32Functions {
    FARPROC VirtualProtect;
    FARPROC VirtualAlloc;
    FARPROC GetProcAddress;
    FARPROC LoadLibraryW;
    FARPROC FreeLibrary;
};

bool StringEqualsIgnoreCase(const std::wstring& a, const std::wstring& b) {
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
}

struct KernelOptimisedDll {
    wstring name;
    std::vector<DWORD> pids;
};

std::vector<KernelOptimisedDll> kernelOptimisedDlls_vec;
std::vector<wstring> KODConstraints;

bool IsDllRegistered(const std::wstring& dllName) {
    for (const auto& kernelDll : kernelOptimisedDlls_vec) {
        if (_wcsicmp(kernelDll.name.c_str(), dllName.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

bool IsConstrained(const std::wstring& dllName) {
    return std::find(KODConstraints.begin(), KODConstraints.end(), dllName) != KODConstraints.end();
}

void ConstrainWorkerUsers(const wstring& targetDllName) {
    if (!IsConstrained(targetDllName))
        KODConstraints.push_back(targetDllName);
}

void OptimiseWorkerUsers(const wstring& targetDllName) {
    if (IsDllRegistered(targetDllName)) {
        if (IsConstrained(targetDllName)) {
            std::wcout << "DLL " << targetDllName << L" is constrained." << std::endl;
            return;
        }
        if (!SUPRESS_ERRORS) {
            std::wcout << L"> DLL " << targetDllName << L" is already on on the KOD Stack." << std::endl;
            std::wcout << L"> Reregistering DLL: " << targetDllName << std::endl;
        }
    }

    KernelOptimisedDll kernelOptimisedDll;
    kernelOptimisedDll.name = targetDllName;

    DWORD processes[1024], bytesReturned;
    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        std::wcerr << L"EnumProcesses failed. Error: " << GetLastError() << std::endl;
        return;
    }

    DWORD processCount = bytesReturned / sizeof(DWORD);
    TCHAR currentProcessPath[MAX_PATH];
    GetModuleFileName(NULL, currentProcessPath, MAX_PATH);

    for (DWORD i = 0; i < processCount; ++i) {
        DWORD pid = processes[i];
        if (pid == 0) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SET_QUOTA, FALSE, pid);
        if (!hProcess) continue;

        TCHAR processPath[MAX_PATH] = {};
        if (GetModuleFileNameExW(hProcess, NULL, processPath, MAX_PATH)) {
            if (StringEqualsIgnoreCase(currentProcessPath, processPath)) {
                CloseHandle(hProcess);
                continue;
            }

            HMODULE hMods[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                DWORD modCount = cbNeeded / sizeof(HMODULE);

                for (DWORD j = 0; j < modCount; ++j) {
                    wchar_t modName[MAX_PATH] = {};
                    if (GetModuleFileNameExW(hProcess, hMods[j], modName, MAX_PATH)) {
                        std::wstring name = modName;
                        size_t pos = name.find_last_of(L"\\/");
                        std::wstring filename = (pos != std::wstring::npos) ? name.substr(pos + 1) : name;

                        if (_wcsicmp(filename.c_str(), targetDllName.c_str()) == 0) {
                            std::wcout << L"KOD Optimizing PID " << pid << L" using " << filename << std::endl;
                            if (!SetProcessWorkingSetSize(hProcess, -1, -1)) {
                                if (!SUPRESS_ERRORS)
                                    std::wcout << L"Failed to trim working set for PID " << pid << L". Error: " << GetLastError() << std::endl;
                            }
                            break;
                        }
                    }
                }
            }
        }

        SetProcessWorkingSetSize(hProcess, -1, -1);
        kernelOptimisedDll.pids.push_back(pid);
        CloseHandle(hProcess);
    }

    kernelOptimisedDlls_vec.push_back(kernelOptimisedDll);
    std::wcout << L"'" << targetDllName << L"' was pushed onto the KOD Stack." << std::endl;
}

DWORD GetTopProcessIDByName(const wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    DWORD pid = 0;
    SIZE_T maxMem = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, (processName + L".exe").c_str()) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
                if (hProc) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                        if (pmc.WorkingSetSize > maxMem) {
                            maxMem = pmc.WorkingSetSize;
                            pid = entry.th32ProcessID;
                        }
                    }
                    CloseHandle(hProc);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

std::vector<DWORD> GetChildProcesses(DWORD parentPid) {
    std::vector<DWORD> childPids;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return childPids;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ParentProcessID == parentPid) {
                childPids.push_back(entry.th32ProcessID);
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return childPids;
}

void LimitRamForProcess(DWORD pid, SIZE_T min, SIZE_T max) {
    HANDLE hProc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProc) {
        if (min > 0 && max > 0 && min <= max) {
            if (!SetProcessWorkingSetSize(hProc, min, max)) {
                if (!SUPRESS_ERRORS)
                    std::wcout << L"Failed to set working set size for process: " << GetLastError() << std::endl;
            }
        }
        else {
            if (!SUPRESS_ERRORS)
                std::wcout << L"Invalid memory size limits for process. Min: " << min << L", Max: " << max << std::endl;
        }
        CloseHandle(hProc);
    }
    else {
        if (!SUPRESS_ERRORS)
            std::wcout << L"Failed to open process for PID " << pid << std::endl;
    }
}

void GarbageCollectFrom(const wstring& processName, SIZE_T min, SIZE_T max, int interval) {
    std::wstring cleanProcessName = processName;
    cleanProcessName.erase(std::remove(cleanProcessName.begin(), cleanProcessName.end(), L' '), cleanProcessName.end());

    auto it = std::find(gcp.begin(), gcp.end(), cleanProcessName);
    if (it != gcp.end()) {
        if (!SUPRESS_ERRORS)
            std::wcout << L"Process '" << processName << L"' is already being garbage collected." << std::endl;
        return;
    }

    DWORD pid = GetTopProcessIDByName(cleanProcessName);
    if (pid == 0) {
        if (!SUPRESS_ERRORS)
            std::wcout << L"Failed to create Garbage Collector for '" << cleanProcessName << L"'" << std::endl;
        return;
    }

    gcp.push_back(cleanProcessName);
    std::thread([=]() {
        while (true) {
            DWORD pid = GetTopProcessIDByName(cleanProcessName);
            if (pid != 0) {
                LimitRamForProcess(pid, min, max);

                std::vector<DWORD> childPids = GetChildProcesses(pid);
                for (DWORD childPid : childPids) {
                    LimitRamForProcess(childPid, min, max);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }
        }).detach();

    std::wcout << L"   Process ID: " << pid << std::endl;
}

namespace GCL_INTERPRETER {
    void Interface(wstring cmd);

    wstring comment_tag = L"#";

    void clean_comments(wstring& line) {
        size_t pos = line.find(comment_tag);
        if (pos != std::wstring::npos) {
            line.erase(pos);
        }
    }

    void LoadGCL(std::vector<wstring> args) {
        if (args.size() < 2) {
            if (!SUPRESS_ERRORS)
                std::wcout << L"Please provide the filename to load." << std::endl;
            return;
        }

        std::wstring fileName = args[1];
        if (fileName.substr(fileName.size() - 4) != L".gcl") {
            fileName += L".gcl";
        }

        fs::path folderPath = fs::current_path() / L"garbage_lists";
        fs::path filePath = fs::exists(folderPath) && fs::is_directory(folderPath)
            ? folderPath / fileName
            : fs::current_path() / fileName;

        if (!fs::exists(filePath) || !fs::is_regular_file(filePath)) {
            if (!SUPRESS_ERRORS)
                std::wcout << L"The file '" << fileName << L"' does not exist or is not a regular file." << std::endl;
            return;
        }

        std::wifstream file(filePath);
        std::wstring line;
        while (std::getline(file, line)) {
            clean_comments(line);
            line.erase(0, line.find_first_not_of(L" \t\r\n"));
            line.erase(line.find_last_not_of(L" \t\r\n") + 1);
            if (!line.empty()) {
                std::wcout << line << std::endl;
                Interface(line);
            }
        }
        file.close();
    }

    void Interface(wstring cmd) {
        clean_comments(cmd);
        std::vector<std::wstring> args;
        size_t startPos = 0;
        for (size_t i = 0; i < cmd.length(); i++) {
            if (cmd[i] == L' ') {
                args.push_back(cmd.substr(startPos, i - startPos));
                startPos = i + 1;
            }
        }
        args.push_back(cmd.substr(startPos));

        if (args[0] == L"gcp") {
            if (!gcp.empty()) {
                std::wcout << L"These processes are being garbage collected: " << std::endl;
                for (wstring processName : gcp)
                    std::wcout << processName << L".exe" << std::endl;
            }
            else if (!SUPRESS_ERRORS)
                std::wcout << L"No processes are being garbage collected" << std::endl;
        }
        else if (args[0] == L"open" || args[0] == L"o" || args[0] == L"load") {
            LoadGCL(args);
        }
        else if (args[0] == L"help") {
            system("cls");
            say_options();
        }
        else if (args[0] == L"-suppress-errors") {
            SUPRESS_ERRORS = true;
        }
        else if (args[0] == L"-unsuppress-errors") {
            SUPRESS_ERRORS = false;
        }
        else if (args[0] == L"con" && args.size() >= 3 && args[1] == L"*KOD") {
            std::wstring dllName = args[2];
            HMODULE hModule = LoadLibraryW(dllName.c_str());
            if (hModule) {
                ConstrainWorkerUsers(dllName);
                FreeLibrary(hModule);
            }
            else if (!SUPRESS_ERRORS)
                std::wcout << L"Failed to constrain DLL: " << GetLastError() << std::endl;
        }
        else if (args[0] == L"kernel" && args.size() >= 3 && args[1] == L"*KOD") {
            HMODULE kernel = LoadLibraryW(L"kernel32.dll");
            if (!kernel) {
                std::wcout << L"Failed to load kernel32.dll: " << GetLastError() << std::endl;
                return;
            }

            BYTE* base = (BYTE*)kernel;

            IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)base;
            IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(base + dosHeader->e_lfanew);

            DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!exportDirRVA) {
                std::wcout << L"No export directory found." << std::endl;
                return;
            }

            IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(base + exportDirRVA);
            DWORD* nameRVAs = (DWORD*)(base + exportDir->AddressOfNames);
            WORD* ordinals = (WORD*)(base + exportDir->AddressOfNameOrdinals);
            DWORD* functions = (DWORD*)(base + exportDir->AddressOfFunctions);

            std::wstring dllName = args[2];

            using VirtualProtectFunc = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
            using VirtualAllocFunc = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
            using GetProcAddressFunc = FARPROC(WINAPI*)(HMODULE, LPCSTR);
            using LoadLibraryWFunc = HMODULE(WINAPI*)(LPCWSTR);
            using FreeLibraryFunc = BOOL(WINAPI*)(HMODULE);

            VirtualProtectFunc vp = (VirtualProtectFunc)GetProcAddress(kernel, "VirtualProtect");
            VirtualAllocFunc va = (VirtualAllocFunc)GetProcAddress(kernel, "VirtualAlloc");
            GetProcAddressFunc gpa = (GetProcAddressFunc)GetProcAddress(kernel, "GetProcAddress");
            LoadLibraryWFunc llw = (LoadLibraryWFunc)GetProcAddress(kernel, "LoadLibraryW");
            FreeLibraryFunc fl = (FreeLibraryFunc)GetProcAddress(kernel, "FreeLibrary");

            if (!vp || !va || !gpa || !llw || !fl) {
                std::wcout << L"Failed to load essential kernel32 exports." << std::endl;
                return;
            }

            DWORD oldProtect;
            vp(base, exportDir->Base, PAGE_READWRITE, &oldProtect);

            void* patchBuffer = va(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!patchBuffer) {
                std::wcout << L"VirtualAlloc failed: " << GetLastError() << std::endl;
                return;
            }

            HMODULE hModule = llw(dllName.c_str());
            if (hModule) {
                FARPROC entry = gpa(hModule, "DllMain");
                if (entry)
                    std::wcout << L"Found DllMain at: " << entry << std::endl;

                OptimiseWorkerUsers(dllName);

                fl(hModule);
            }
            else if (!SUPRESS_ERRORS) {
                std::wcout << L"Failed to load DLL: " << GetLastError() << std::endl;
            }
        }

        else if (args[0] == L"-gcexit") {
            if (args.size() >= 2)
                exit(std::stoi(args[1]));
            else
                std::wcout << L"-gcexit requires an exit code; use '-gcexit <exit code>'" << std::endl;
        }
        else {
            GarbageCollectFrom(cmd, 1024 * 1024, 200 * 1024 * 1024, 5000);
        }
    }
}

int main() {
    if (!IsAdmin())
        SetAdmin();

    say_options();

    wstring cmd;
    while (cmd != L"exit") {
        std::getline(std::wcin, cmd);
        GCL_INTERPRETER::Interface(cmd);
    }

    return 0;
}
