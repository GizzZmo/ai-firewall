// aifw_service – Windows-tjeneste for AI-Firewall.
//
//   aifw_service.exe --console     kjør i forgrunnen (Ctrl+C stopper) – best for utvikling
//   aifw_service.exe --install     registrer som tjeneste (automatisk oppstart)
//   aifw_service.exe --uninstall   stopp og fjern tjenesten
//   aifw_service.exe --wfp-cleanup fjern alle persistente WFP-filtre fra AI-Firewall
//   aifw_service.exe               (startet av Service Control Manager)
//
// Alle moduser krever elevert administrator.
#ifndef _WIN32
#error "aifw_service er kun for Windows"
#endif

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <iostream>
#include <memory>
#include <string>

#include <spdlog/spdlog.h>

#include "ServiceHost.hpp"
#include "WfpManager.hpp"
#include "WinUtil.hpp"

using namespace aifw;

namespace {

constexpr wchar_t kServiceName[] = L"AiFirewall";
constexpr wchar_t kDisplayName[] = L"AI-Firewall (KI-basert brannmur)";

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status{};
win::UniqueHandle g_stopEvent;

void setStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHintMs = 0) {
    static DWORD checkpoint = 1;
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint = waitHintMs;
    g_status.dwControlsAccepted = state == SERVICE_START_PENDING ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    SetServiceStatus(g_statusHandle, &g_status);
}

DWORD WINAPI controlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            setStatus(SERVICE_STOP_PENDING, NO_ERROR, 10000);
            SetEvent(g_stopEvent.get());
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI serviceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, controlHandler, nullptr);
    if (!g_statusHandle) return;
    setStatus(SERVICE_START_PENDING, NO_ERROR, 30000);
    g_stopEvent.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    try {
        ServiceHost host(win::exeDirectory());
        host.start();
        setStatus(SERVICE_RUNNING);
        WaitForSingleObject(g_stopEvent.get(), INFINITE);
        host.stop();
        setStatus(SERVICE_STOPPED);
    } catch (const std::exception& e) {
        spdlog::critical("Tjenesten feilet: {}", e.what());
        spdlog::default_logger()->flush();
        setStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
    }
}

BOOL WINAPI consoleHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        SetEvent(g_stopEvent.get());
        return TRUE;
    }
    return FALSE;
}

int runConsole() {
    g_stopEvent.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    SetConsoleCtrlHandler(consoleHandler, TRUE);
    SetConsoleOutputCP(CP_UTF8);
    ServiceHost host(win::exeDirectory());
    host.start();
    std::puts("AI-Firewall kjører i konsollmodus. Trykk Ctrl+C for å stoppe.");
    WaitForSingleObject(g_stopEvent.get(), INFINITE);
    host.stop();
    return 0;
}

struct ScHandle {
    SC_HANDLE h;
    explicit ScHandle(SC_HANDLE x) : h(x) {}
    ~ScHandle() { if (h) CloseServiceHandle(h); }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
};

int install() {
    wchar_t path[MAX_PATH * 4];
    if (!GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)))) win::throwLastError("GetModuleFileNameW");
    const std::wstring cmd = L"\"" + std::wstring(path) + L"\"";  // anførselstegn: unngå "unquoted service path"
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (!scm.h) win::throwLastError("OpenSCManager");
    ScHandle svc(CreateServiceW(scm.h, kServiceName, kDisplayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr,
                                L"BFE\0\0",  // avhenger av Base Filtering Engine (WFP)
                                nullptr, nullptr));
    if (!svc.h) win::throwLastError("CreateService");
    SERVICE_DESCRIPTIONW desc{const_cast<wchar_t*>(L"KI-basert brannmur: WinDivert + WFP + ONNX Runtime")};
    ChangeServiceConfig2W(svc.h, SERVICE_CONFIG_DESCRIPTION, &desc);
    // Gjenstart automatisk ved krasj (5 s, 30 s, deretter 2 min).
    SC_ACTION actions[3] = {{SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 30000}, {SC_ACTION_RESTART, 120000}};
    SERVICE_FAILURE_ACTIONSW fa{86400, nullptr, nullptr, 3, actions};
    ChangeServiceConfig2W(svc.h, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    std::puts("Tjenesten 'AiFirewall' er installert. Start med: sc start AiFirewall");
    return 0;
}

int uninstall() {
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.h) win::throwLastError("OpenSCManager");
    ScHandle svc(OpenServiceW(scm.h, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (!svc.h) win::throwLastError("OpenService");
    SERVICE_STATUS st{};
    if (ControlService(svc.h, SERVICE_CONTROL_STOP, &st)) {
        for (int i = 0; i < 50 && QueryServiceStatus(svc.h, &st) && st.dwCurrentState != SERVICE_STOPPED; ++i) Sleep(200);
    }
    if (!DeleteService(svc.h)) win::throwLastError("DeleteService");
    std::puts("Tjenesten er fjernet. Persistente WFP-regler ligger fortsatt inne – kjør --wfp-cleanup for å fjerne dem.");
    return 0;
}

int wfpCleanup() {
    WfpManager wfp;
    wfp.uninstall();
    std::puts("Alle AI-Firewall WFP-filtre, sublayer og provider er fjernet.");
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    const std::wstring arg = argc > 1 ? argv[1] : L"";
    try {
        if (!arg.empty() && !win::isElevatedAdmin()) {
            std::fputs("Feil: må kjøres som administrator (høyreklikk -> Kjør som administrator).\n", stderr);
            return 5;  // ERROR_ACCESS_DENIED
        }
        if (arg == L"--console") return runConsole();
        if (arg == L"--install") return install();
        if (arg == L"--uninstall") return uninstall();
        if (arg == L"--wfp-cleanup") return wfpCleanup();
        if (!arg.empty()) {
            std::fputs("Bruk: aifw_service [--console | --install | --uninstall | --wfp-cleanup]\n", stderr);
            return 2;
        }
        SERVICE_TABLE_ENTRYW table[] = {{const_cast<wchar_t*>(kServiceName), serviceMain}, {nullptr, nullptr}};
        if (!StartServiceCtrlDispatcherW(table)) {
            if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                std::fputs("Startet utenfor Service Control Manager. Bruk --console for forgrunnsmodus.\n", stderr);
                return 1;
            }
            win::throwLastError("StartServiceCtrlDispatcher");
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Feil: %s\n", e.what());
        return 1;
    }
}
