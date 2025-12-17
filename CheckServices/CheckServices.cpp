#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <winsvc.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <atomic>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "psapi.lib")

const std::vector<std::wstring> MONITORED_SERVICES = {
    L"PcaSvc",
    L"PlugPlay",
    L"DPS",
    L"DiagTrack",
    L"SysMain",
    L"Sysmon",
    L"EventLog"
};

const wchar_t* LOG_FILE = L"check_services.log";
const wchar_t* SESSION_NAME = L"CheckServicesSession";

static const GUID ServiceProviderGuid =
{ 0x0063715b, 0xeeda, 0x4007, { 0x9c, 0xc0, 0x9a, 0x79, 0x5b, 0x65, 0x53, 0x4d } };

std::mutex g_logMutex;
std::mutex g_stateMutex;
std::map<std::wstring, DWORD> g_lastServiceState;
std::atomic<bool> g_running{ true };
TRACEHANDLE g_sessionHandle = 0;
TRACEHANDLE g_traceHandle = INVALID_PROCESSTRACE_HANDLE;

struct ScmAccessInfo {
    DWORD pid;
    std::wstring processName;
    FILETIME accessTime;
};
std::vector<ScmAccessInfo> g_recentScmAccess;
std::mutex g_scmAccessMutex;

std::wstring GetCurrentTimeString() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm_now;
    localtime_s(&tm_now, &time_t_now);

    std::wstringstream ss;
    ss << std::put_time(&tm_now, L"%Y-%m-%d %H:%M:%S")
        << L"." << std::setfill(L'0') << std::setw(3) << ms.count();
    return ss.str();
}

void LogMessage(const std::wstring& message, bool isAlert = false) {
    std::lock_guard<std::mutex> lock(g_logMutex);

    std::wstring timestamp = GetCurrentTimeString();
    std::wstring prefix = isAlert ? L"[ALERT]" : L"[INFO]";
    std::wstring fullMsg = timestamp + L" " + prefix + L" " + message;

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (isAlert) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    }
    else {
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    }

    DWORD written;
    WriteConsoleW(hConsole, fullMsg.c_str(), (DWORD)fullMsg.length(), &written, NULL);
    WriteConsoleW(hConsole, L"\n", 1, &written, NULL);

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    std::wofstream logFile(LOG_FILE, std::ios::app);
    if (logFile.is_open()) {
        logFile << fullMsg << std::endl;
    }
}

void PrintColored(const wchar_t* text, WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
    DWORD written;
    WriteConsoleW(hConsole, text, (DWORD)wcslen(text), &written, NULL);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void PrintBanner() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);

    printf("\n");
    printf("   _____ _               _      _____                 _               \n");
    printf("  / ____| |             | |    / ____|               (_)              \n");
    printf(" | |    | |__   ___  ___| | __| (___   ___ _ ____   ___  ___ ___  ___ \n");
    printf(" | |    | '_ \\ / _ \\/ __| |/ / \\___ \\ / _ \\ '__\\ \\ / / |/ __/ _ \\/ __|\n");
    printf(" | |____| | | |  __/ (__|   <  ____) |  __/ |   \\ V /| | (_|  __/\\__ \\\n");
    printf("  \\_____|_| |_|\\___|\\___|_|\\_\\|_____/ \\___|_|    \\_/ |_|\\___\\___||___/\n");
    printf("\n");

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("                        [ v1.0 - Service Monitor ]\n");
    printf("\n");

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

const wchar_t* ServiceStateToString(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED:          return L"STOPPED";
    case SERVICE_START_PENDING:    return L"START_PENDING";
    case SERVICE_STOP_PENDING:     return L"STOP_PENDING";
    case SERVICE_RUNNING:          return L"RUNNING";
    case SERVICE_CONTINUE_PENDING: return L"CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING:    return L"PAUSE_PENDING";
    case SERVICE_PAUSED:           return L"PAUSED";
    default:                       return L"UNKNOWN";
    }
}

std::wstring GetProcessNameByPid(DWORD pid) {
    std::wstring result = L"<unknown>";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        wchar_t path[MAX_PATH] = { 0 };
        if (GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH)) {
            result = path;
            size_t pos = result.rfind(L'\\');
            if (pos != std::wstring::npos) {
                result = result.substr(pos + 1);
            }
        }
        CloseHandle(hProcess);
    }

    return result;
}

void CaptureScmAccessSnapshot() {
    std::lock_guard<std::mutex> lock(g_scmAccessMutex);
    g_recentScmAccess.clear();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    std::set<std::wstring> suspiciousNames = {
        L"sc.exe", L"net.exe", L"net1.exe", L"powershell.exe",
        L"pwsh.exe", L"cmd.exe", L"taskkill.exe", L"wmic.exe",
        L"services.exe", L"mmc.exe"
    };

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring name = pe.szExeFile;
            for (auto& c : name) c = towlower(c);

            if (suspiciousNames.count(name)) {
                ScmAccessInfo info;
                info.pid = pe.th32ProcessID;
                info.processName = pe.szExeFile;
                GetSystemTimeAsFileTime(&info.accessTime);

                g_recentScmAccess.push_back(info);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
}

void MonitorScmAccessThread() {
    LogMessage(L"Thread de monitoramento SCM iniciada");

    while (g_running) {
        CaptureScmAccessSnapshot();
        Sleep(500);
    }

    LogMessage(L"Thread de monitoramento SCM finalizada");
}

void WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord) {
    if (!pEventRecord) return;

    DWORD processId = pEventRecord->EventHeader.ProcessId;
    DWORD bufferSize = 0;
    TDHSTATUS status = TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);

    if (status == ERROR_INSUFFICIENT_BUFFER && bufferSize > 0) {
        std::vector<BYTE> buffer(bufferSize);
        PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)buffer.data();

        status = TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize);

        if (status == ERROR_SUCCESS) {
            std::wstring taskName;
            if (pInfo->TaskNameOffset) {
                taskName = (PWCHAR)((PBYTE)pInfo + pInfo->TaskNameOffset);
            }

            if (taskName.find(L"Service") != std::wstring::npos ||
                taskName.find(L"SCM") != std::wstring::npos) {

                std::wstringstream ss;
                ss << L"[ETW] Evento: PID=" << processId
                    << L" Task=" << taskName
                    << L" Process=" << GetProcessNameByPid(processId);
                LogMessage(ss.str(), false);
            }
        }
    }
}

ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW pLogFile) {
    return g_running ? TRUE : FALSE;
}

bool StartEtwSession() {
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) +
        (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t);

    std::vector<BYTE> buffer(bufferSize, 0);
    PEVENT_TRACE_PROPERTIES pSessionProperties = (PEVENT_TRACE_PROPERTIES)buffer.data();

    pSessionProperties->Wnode.BufferSize = bufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1;
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceW(0, SESSION_NAME, pSessionProperties, EVENT_TRACE_CONTROL_STOP);

    ZeroMemory(buffer.data(), bufferSize);
    pSessionProperties->Wnode.BufferSize = bufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1;
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&g_sessionHandle, SESSION_NAME, pSessionProperties);

    if (status != ERROR_SUCCESS) {
        LogMessage(L"Erro ao iniciar sessao ETW: " + std::to_wstring(status), true);
        return false;
    }

    status = EnableTraceEx2(
        g_sessionHandle,
        &ServiceProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0, 0, 0, NULL
    );

    if (status != ERROR_SUCCESS) {
        LogMessage(L"Aviso: Nao foi possivel habilitar provider ETW: " + std::to_wstring(status), false);
    }

    LogMessage(L"Sessao ETW iniciada com sucesso");
    return true;
}

void EtwConsumerThread() {
    EVENT_TRACE_LOGFILEW trace = { 0 };
    trace.LoggerName = (LPWSTR)SESSION_NAME;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = EventRecordCallback;
    trace.BufferCallback = BufferCallback;

    g_traceHandle = OpenTraceW(&trace);

    if (g_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        LogMessage(L"Erro ao abrir trace ETW: " + std::to_wstring(GetLastError()), true);
        return;
    }

    LogMessage(L"Consumer ETW iniciado");
    ProcessTrace(&g_traceHandle, 1, NULL, NULL);
    LogMessage(L"Consumer ETW finalizado");
}

void StopEtwSession() {
    if (g_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_traceHandle);
        g_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    if (g_sessionHandle) {
        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) +
            (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t);
        std::vector<BYTE> buffer(bufferSize, 0);
        PEVENT_TRACE_PROPERTIES pProps = (PEVENT_TRACE_PROPERTIES)buffer.data();
        pProps->Wnode.BufferSize = bufferSize;
        pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ControlTraceW(g_sessionHandle, SESSION_NAME, pProps, EVENT_TRACE_CONTROL_STOP);
        g_sessionHandle = 0;
    }
}

DWORD GetServiceState(SC_HANDLE hSCManager, const std::wstring& serviceName) {
    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!hService) return 0;

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    DWORD state = 0;

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
        state = status.dwCurrentState;
    }

    CloseServiceHandle(hService);
    return state;
}

void ServicePollingThread() {
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        LogMessage(L"Erro ao abrir SCManager: " + std::to_wstring(GetLastError()), true);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_stateMutex);

        printf("\n");
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  [+] Servicos monitorados:\n");
        printf("  +-----------------------+-------------+\n");
        printf("  | Servico               | Estado      |\n");
        printf("  +-----------------------+-------------+\n");

        for (const auto& svc : MONITORED_SERVICES) {
            DWORD state = GetServiceState(hSCManager, svc);
            g_lastServiceState[svc] = state;

            char svcName[64] = { 0 };
            WideCharToMultiByte(CP_ACP, 0, svc.c_str(), -1, svcName, 64, NULL, NULL);

            char stateName[32] = { 0 };
            WideCharToMultiByte(CP_ACP, 0, ServiceStateToString(state), -1, stateName, 32, NULL, NULL);

            if (state == SERVICE_RUNNING) {
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            }
            else if (state == SERVICE_STOPPED || state == 0) {
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
            }
            else {
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            }

            printf("  | %-21s | %-11s |\n", svcName, stateName);
        }

        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  +-----------------------+-------------+\n");
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("\n");
    }

    LogMessage(L"Monitoramento ativo (polling 500ms)");
    LogMessage(L"Pressione Ctrl+C para encerrar");
    printf("\n");

    while (g_running) {
        for (const auto& svc : MONITORED_SERVICES) {
            DWORD currentState = GetServiceState(hSCManager, svc);

            std::lock_guard<std::mutex> lock(g_stateMutex);
            DWORD lastState = g_lastServiceState[svc];

            if (currentState != lastState && currentState != 0) {
                HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

                printf("\n");
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                printf("  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                printf("  !!                    ALERTA DETECTADO                   !!\n");
                printf("  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

                std::wstringstream ss;
                ss << L"Servico: " << svc;
                LogMessage(ss.str(), true);

                ss.str(L"");
                ss << L"Estado: " << ServiceStateToString(lastState)
                    << L" -> " << ServiceStateToString(currentState);
                LogMessage(ss.str(), true);

                ss.str(L"");
                ss << L"Hora: " << GetCurrentTimeString();
                LogMessage(ss.str(), true);

                if (currentState == SERVICE_STOPPED || currentState == SERVICE_STOP_PENDING) {
                    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                    printf("\n  >>> TENTATIVA DE DESABILITAR/PARAR DETECTADA! <<<\n\n");
                    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                }

                {
                    std::lock_guard<std::mutex> scmLock(g_scmAccessMutex);
                    if (!g_recentScmAccess.empty()) {
                        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                        printf("  [!] Processos suspeitos ativos:\n");
                        for (const auto& proc : g_recentScmAccess) {
                            char procName[256] = { 0 };
                            WideCharToMultiByte(CP_ACP, 0, proc.processName.c_str(), -1, procName, 256, NULL, NULL);
                            printf("      - PID: %-6lu | Processo: %s\n", proc.pid, procName);
                        }
                        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                    }
                }

                HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnapshot != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32W pe;
                    pe.dwSize = sizeof(pe);

                    std::vector<std::wstring> checkProcesses = {
                        L"sc.exe", L"net.exe", L"net1.exe", L"taskkill.exe",
                        L"powershell.exe", L"pwsh.exe"
                    };

                    bool foundAny = false;
                    if (Process32FirstW(hSnapshot, &pe)) {
                        do {
                            std::wstring name = pe.szExeFile;
                            std::wstring nameLower = name;
                            for (auto& c : nameLower) c = towlower(c);

                            for (const auto& check : checkProcesses) {
                                if (nameLower == check) {
                                    if (!foundAny) {
                                        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                                        printf("\n  [!!!] PROCESSOS ENCONTRADOS QUE PODEM TER CAUSADO:\n");
                                        foundAny = true;
                                    }
                                    char procName[256] = { 0 };
                                    WideCharToMultiByte(CP_ACP, 0, name.c_str(), -1, procName, 256, NULL, NULL);
                                    printf("        >>> PID: %-6lu | %s\n", pe.th32ProcessID, procName);
                                }
                            }
                        } while (Process32NextW(hSnapshot, &pe));
                    }
                    if (foundAny) {
                        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                    }
                    CloseHandle(hSnapshot);
                }

                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                printf("\n  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

                g_lastServiceState[svc] = currentState;
            }
        }

        Sleep(500);
    }

    CloseServiceHandle(hSCManager);
    LogMessage(L"Thread de polling finalizada");
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        printf("\n\n  [*] Encerrando monitoramento...\n");
        g_running = false;
        StopEtwSession();
        return TRUE;
    }
    return FALSE;
}

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleTitleA("Check Services - Monitor de Servicos");
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    system("cls");

    PrintBanner();

    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    if (isAdmin) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("  [OK] Executando como Administrador\n");
    }
    else {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("  [!!] AVISO: Execute como Admin para melhor deteccao!\n");
    }

    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("  [*] Log: check_services.log\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    std::thread pollingThread(ServicePollingThread);
    std::thread scmMonitorThread(MonitorScmAccessThread);

    std::thread etwThread;
    if (StartEtwSession()) {
        etwThread = std::thread(EtwConsumerThread);
    }

    while (g_running) {
        Sleep(100);
    }

    StopEtwSession();

    if (pollingThread.joinable()) pollingThread.join();
    if (scmMonitorThread.joinable()) scmMonitorThread.join();
    if (etwThread.joinable()) etwThread.join();

    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n  [*] Monitoramento encerrado.\n\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    return 0;
}