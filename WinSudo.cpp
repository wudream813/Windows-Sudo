// compile command line: -luserenv -lWtsApi32

#include <Windows.h>
#include <WtsApi32.h>
#include <Userenv.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include <vector>

// ==========================================
// 全局配置与日志系统
// ==========================================

void WriteToStdOut(const char* str) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == NULL) return;

    DWORD written;
    // 尝试作为控制台写入 (支持颜色)
    if (!WriteConsoleA(hOut, str, strlen(str), &written, NULL)) {
        // 如果重定向到了文件/管道，WriteConsole 会失败，回退到 WriteFile
        WriteFile(hOut, str, strlen(str), &written, NULL);
    }
}

bool g_bDebug = false;
enum LogLevel { LOG_ERROR, LOG_WARN, LOG_INFO, LOG_SUCCESS };
void Log(LogLevel level, const char* format, ...) {
    if (level == LOG_INFO && !g_bDebug) return;
    const char* prefix = "";
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hOut, &csbi);
    WORD wOldColor = csbi.wAttributes, wColor = wOldColor;
    switch (level) {
        case LOG_ERROR:   prefix = "[!] "; wColor = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
        case LOG_WARN:    prefix = "[-] "; wColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
        case LOG_INFO:    prefix = "[*] "; wColor = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
        case LOG_SUCCESS: prefix = "[+] "; wColor = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
    }
    SetConsoleTextAttribute(hOut, wColor);
    WriteToStdOut(prefix);
    {
        char buffer[4096];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        WriteToStdOut(buffer);
    }
    WriteToStdOut("\r\n");
    SetConsoleTextAttribute(hOut, wOldColor);
    
    if(level == LOG_ERROR)__builtin_ia32_pause();
}

// ==========================================
// 基础工具函数
// ==========================================

BOOL IsUserAnAdmin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    BOOL b = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
    if (b) { 
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &b)) b = FALSE; 
        FreeSid(AdministratorsGroup); 
    }
    return b;
}

DWORD GetActiveSessionID() {
    DWORD count = 0; PWTS_SESSION_INFOA pSessionInfo = NULL; DWORD activeSessionId = (DWORD)-1;
    if (WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &count)) {
        for (DWORD i = 0; i < count; ++i) { if (pSessionInfo[i].State == WTSActive) { activeSessionId = pSessionInfo[i].SessionId; break; } }
        WTSFreeMemory(pSessionInfo);
    }
    if (activeSessionId == (DWORD)-1) ProcessIdToSessionId(GetCurrentProcessId(), &activeSessionId);
    return activeSessionId;
}

void EnablePrivileges(HANDLE hToken) {
    DWORD dwSize = 0; GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return;
    std::vector<BYTE> buffer(dwSize); PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)buffer.data();
    if (GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize)) {
        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) pPrivs->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, pPrivs, 0, NULL, NULL);
    }
}

BOOL EnableCurrentProcessDebugPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
		CloseHandle(hToken);
		return result;
	}
	return FALSE;
}

// 判断当前是否是 System 权限
BOOL IsUserLocalSystem() {
    BOOL bIsLocalSystem = FALSE;
    PSID psidLocalSystem;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    BOOL fSuccess = AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0, &psidLocalSystem);
    if (fSuccess) {
        fSuccess = CheckTokenMembership(0, psidLocalSystem, &bIsLocalSystem);
        FreeSid(psidLocalSystem);
    }

    return bIsLocalSystem;
}

// ==========================================
// 令牌获取逻辑
// ==========================================

// 获取 System 令牌
HANDLE GetSystemToken(DWORD activeSessionId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;

    DWORD targetPid = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 尝试寻找当前 Session 的 winlogon
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, "winlogon.exe") == 0) {
                DWORD currentSessionId = 0;
                if (ProcessIdToSessionId(pe32.th32ProcessID, &currentSessionId)) {
                    if (currentSessionId == activeSessionId) {
                        targetPid = pe32.th32ProcessID;
                        break;
                    }
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    
    // 回退策略
    if (targetPid == 0) {
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, "winlogon.exe") == 0) {
                    targetPid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    if (targetPid == 0) {
        Log(LOG_ERROR, "未找到任何 winlogon.exe 进程");
        return NULL;
    }

    Log(LOG_INFO, "目标 winlogon PID: %lu", targetPid);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProcess) return NULL;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        CloseHandle(hProcess);
        return NULL;
    }

    HANDLE hDupToken = NULL;
    DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hDupToken);
    
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return hDupToken;
}

// 获取 TrustedInstaller 令牌
HANDLE GetTrustedInstallerToken(DWORD activeSessionId) {
    // 2. 操作服务
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        RevertToSelf();
        return NULL;
    }

    SC_HANDLE hService = OpenServiceA(hSCManager, "TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        RevertToSelf();
        return NULL;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);

    if (ssp.dwCurrentState != SERVICE_RUNNING) {
        Log(LOG_INFO, "启动 TrustedInstaller 服务...");
        StartServiceA(hService, 0, NULL);
        for (int i = 0; i < 40; i++) {
            Sleep(100);
            QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);
            if (ssp.dwCurrentState == SERVICE_RUNNING) break;
        }
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    if (ssp.dwCurrentState != SERVICE_RUNNING) {
        Log(LOG_ERROR, "TrustedInstaller 服务启动失败");
        return NULL;
    }

    // 3. 获取令牌
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ssp.dwProcessId);
    if (!hProcess) {
        return NULL;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken)) {
        CloseHandle(hProcess);
        return NULL;
    }

    HANDLE hDupToken = NULL;
    DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hDupToken);

    CloseHandle(hToken);
    CloseHandle(hProcess);

    return hDupToken;
}

// ==========================================
// 主程序
// ==========================================

int main(int argc, char* argv[]) {    
    if (argc < 2) {
        printf("用法: WinSudo.exe [选项] <命令行>\n\n");
        printf("选项:\n");
        printf("  -S,  --System            System 权限\n");
        printf("  -TI, --TrustedInstaller  TrustedInstaller 权限\n");
        printf("  -P,  --Privileged        启用所有特权\n");
        printf("  -i,  --inline            内联模式 (在当前窗口显示输出)\n");
        printf("  -D,  --debug             显示调试信息\n\n");
        printf("示例: WinSudo.exe -i -S cmd.exe\n");
        return 0;
    }

    bool bInline = false, bSystem = false, bTI = false, bPriv = false;
    int argStart = 1;

    for (int i = (strcmp(argv[1], "-e") ? 1 : 3); i < argc; i++) {
        if (_stricmp(argv[i], "-i") == 0 || _stricmp(argv[i], "--inline") == 0) bInline = true;
        else if (_stricmp(argv[i], "-S") == 0 || _stricmp(argv[i], "--System") == 0) bSystem = true;
        else if (_stricmp(argv[i], "-TI") == 0 || _stricmp(argv[i], "--TrustedInstaller") == 0) bTI = true;
        else if (_stricmp(argv[i], "-P") == 0 || _stricmp(argv[i], "--Privileged") == 0) bPriv = true;
        else if (_stricmp(argv[i], "-D") == 0 || _stricmp(argv[i], "--debug") == 0) g_bDebug = true;
        else if (argv[i][0] == '-') { Log(LOG_ERROR, "未知参数：%s", argv[i]); return 0; }
        else { argStart = i; break; }
    }
    
    if(bInline)SetConsoleCtrlHandler(NULL, TRUE);

    std::string cmdLine;
    if (argStart < argc) { for (int i = argStart; i < argc; i++) { cmdLine += argv[i]; if (i < argc - 1) cmdLine += " "; } }
    else Log(LOG_ERROR, "找不到要运行的参数");

    // -----------------------------------------------------
    // STAGE 1 & 2: 管理员/System 执行逻辑
    // -----------------------------------------------------
    if (IsUserAnAdmin()) {
        // 1. 内联挂载 (如果需要)
        if (bInline) {
            FreeConsole();
            if (AttachConsole(ATTACH_PARENT_PROCESS)) {
                Log(LOG_INFO, "已挂载到父控制台");
            } else {
                AllocConsole(); 
                Log(LOG_WARN, "挂载失败，创建新窗口");
            }
        }

        if(!EnableCurrentProcessDebugPrivilege()) {
            Log(LOG_WARN, "启动调试程序特权失败");
        }
        
        DWORD sess = GetActiveSessionID();

        // [核心中转逻辑]
        // 如果我们目前只是 Admin，
        // 我们因为缺特权无法直接启动 TI，
        // 那么我们先启动一个 System 权限的自己，
        // 让那个 System 进程去启动最终的 TI 进程。
        if (bTI && !IsUserLocalSystem()) {
            Log(LOG_INFO, "正在请求 System 中转以获取 TI 权限...");
            
            HANDLE hSysToken = GetSystemToken(sess);
            if (!hSysToken) { Log(LOG_ERROR, "System 令牌获取失败"); return 1; }

            STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi = { 0 };
            si.dwFlags = 0; // 继承控制台
            si.lpDesktop = (LPSTR)"winsta0\\default";
            
            // 以 System 权限启动自身
            if (CreateProcessAsUserA(hSysToken, NULL, GetCommandLineA(), 
                NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                // 等待中转进程结束
                WaitForSingleObject(pi.hProcess, INFINITE);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                return 0; // 任务完成
            } else {
                Log(LOG_ERROR, "System 中转启动失败: %lu", GetLastError());
                return 1;
            }
        }

        // [常规启动逻辑]
        // 此时我们要么是 Admin 启动 Admin/System，
        // 要么已经是 System 启动 TI (中转后的自己)
        HANDLE hTargetToken = NULL;
        
        if (bTI) {
            // 此时我们应该是 System 了
            hTargetToken = GetTrustedInstallerToken(sess);
        } else if (bSystem) {
            hTargetToken = GetSystemToken(sess);
        } else {
            // CurrentUser
            HANDLE hP; 
            OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hP);
            DuplicateTokenEx(hP, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hTargetToken);
            CloseHandle(hP);
        }

        if (!hTargetToken) { Log(LOG_ERROR, "目标令牌获取失败"); return 1; }

        // 修正 Session
        DWORD ts; DWORD rl; GetTokenInformation(hTargetToken, TokenSessionId, &ts, sizeof(DWORD), &rl);
        if (ts != sess) SetTokenInformation(hTargetToken, TokenSessionId, &sess, sizeof(DWORD));
        
        if (bPriv) EnablePrivileges(hTargetToken);

        LPVOID lpEnv = NULL; CreateEnvironmentBlock(&lpEnv, hTargetToken, FALSE);
        STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi = { 0 };
        si.lpDesktop = (LPSTR)"winsta0\\default";
        
        DWORD dwFlags = CREATE_UNICODE_ENVIRONMENT;
        if (!bInline) dwFlags |= CREATE_NEW_CONSOLE;

        Log(LOG_INFO, "启动最终进程: %s", cmdLine.c_str());

        if (CreateProcessAsUserA(hTargetToken, NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, FALSE, dwFlags, lpEnv, NULL, &si, &pi)) {
            if (bInline) WaitForSingleObject(pi.hProcess, INFINITE);
            else Log(LOG_SUCCESS, "新窗口 PID: %lu", pi.dwProcessId);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        } else {
            Log(LOG_ERROR, "启动失败: %lu", GetLastError());
        }

        if (lpEnv) DestroyEnvironmentBlock(lpEnv);
        CloseHandle(hTargetToken);
    }

    // -----------------------------------------------------
    // STAGE 0: 普通用户提权
    // -----------------------------------------------------
    else {
        char selfPath[MAX_PATH]; GetModuleFileNameA(NULL, selfPath, MAX_PATH);
        std::string args = "-e "; args += GetCommandLineA();
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas"; sei.lpFile = selfPath; sei.lpParameters = args.c_str();
        sei.nShow = SW_HIDE; 
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        Log(LOG_INFO, "正在请求提权...");
        if (ShellExecuteExA(&sei)) {
            if (bInline) WaitForSingleObject(sei.hProcess, INFINITE);
            CloseHandle(sei.hProcess);
            Log(LOG_SUCCESS, "提权成功");
        } else {
            Log(LOG_ERROR, "提权失败");
        }
    }
    
    return 0;
}