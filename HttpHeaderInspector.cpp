/*
Tool: HttpHeaderInspector
File: HttpHeaderInspector.cpp
Author: Ayi NEDJIMI Consultants
URL: https://www.ayinedjimi-consultants.fr
Version: 1.0
Description:
  Interroge une ou plusieurs URLs HTTP/HTTPS et analyse les headers de réponse pour
  détecter configurations de sécurité faibles : absence HSTS, CSP, X-Frame-Options,
  cookies non sécurisés, etc. Utile pour audit de sécurité web.
Prerequisites:
  - Windows 10 / Windows Server 2016+ (x64)
  - Visual Studio Developer Command Prompt (x64)
  - Accès réseau (Internet ou intranet)
Notes:
  - Outil en mode audit par défaut. Voir section LAB-CONTROLLED dans README pour démonstration en VM isolée.

WinToolsSuite – Security Tools for Network & Pentest
Developed by Ayi NEDJIMI Consultants
https://www.ayinedjimi-consultants.fr
© 2025 – Cybersecurity Research & Training
*/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winhttp.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <thread>
#include <mutex>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "comctl32.lib")

#define WM_TOOL_RESULT   (WM_APP + 200)
#define WM_TOOL_ERROR    (WM_APP + 201)

#define IDC_LISTVIEW     1001
#define IDC_EDIT_URL     1002
#define IDC_BTN_SCAN     1003
#define IDC_BTN_EXPORT   1004
#define IDC_BTN_CLEAR    1005
#define ID_FILE_EXPORT   2001
#define ID_FILE_EXIT     2002
#define ID_HELP_ABOUT    2003

class AutoHINTERNET {
    HINTERNET h;
public:
    explicit AutoHINTERNET(HINTERNET handle = NULL) : h(handle) {}
    ~AutoHINTERNET() { if (h) WinHttpCloseHandle(h); }
    operator HINTERNET() const { return h; }
    HINTERNET* operator&() { return &h; }
    HINTERNET get() const { return h; }
};

struct ScanResult {
    std::wstring url;
    int statusCode;
    std::wstring server;
    bool hasHSTS;
    bool hasCSP;
    bool hasXFrameOptions;
    bool hasXContentTypeOptions;
    std::wstring notes;
};

HWND g_hwnd = NULL;
HWND g_hwndList = NULL;
HWND g_hwndEdit = NULL;
std::vector<ScanResult> g_results;
std::mutex g_mutex;
std::wofstream g_logFile;
bool g_scanning = false;
std::thread g_scanThread;

void LogMessage(const std::wstring& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timeBuf[100];
    swprintf_s(timeBuf, L"[%04d-%02d-%02d %02d:%02d:%02d] ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    if (g_logFile.is_open()) {
        g_logFile << timeBuf << msg << std::endl;
        g_logFile.flush();
    }
}

void InitLog() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = std::wstring(tempPath) + L"WinTools_HttpHeaderInspector_log.txt";
    g_logFile.open(logPath, std::ios::app);
    LogMessage(L"=== HttpHeaderInspector démarré ===");
}

std::wstring ToLower(const std::wstring& str) {
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

ScanResult ScanUrl(const std::wstring& url) {
    ScanResult result = {};
    result.url = url;
    result.statusCode = 0;

    URL_COMPONENTSW urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t hostName[256] = {};
    wchar_t urlPath[1024] = {};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
        result.notes = L"URL invalide";
        return result;
    }

    AutoHINTERNET hSession(WinHttpOpen(L"HttpHeaderInspector/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0));

    if (!hSession.get()) {
        result.notes = L"Échec WinHttpOpen";
        return result;
    }

    AutoHINTERNET hConnect(WinHttpConnect(hSession.get(), hostName, urlComp.nPort, 0));
    if (!hConnect.get()) {
        result.notes = L"Échec WinHttpConnect";
        return result;
    }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;

    AutoHINTERNET hRequest(WinHttpOpenRequest(hConnect.get(), L"GET", urlPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags));

    if (!hRequest.get()) {
        result.notes = L"Échec WinHttpOpenRequest";
        return result;
    }

    if (!WinHttpSendRequest(hRequest.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        result.notes = L"Échec WinHttpSendRequest";
        return result;
    }

    if (!WinHttpReceiveResponse(hRequest.get(), NULL)) {
        result.notes = L"Échec WinHttpReceiveResponse";
        return result;
    }

    // Status code
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &statusCode, &size, NULL);
    result.statusCode = statusCode;

    // Server header
    wchar_t serverBuf[256] = {};
    DWORD serverSize = sizeof(serverBuf);
    if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_SERVER, NULL,
        serverBuf, &serverSize, NULL)) {
        result.server = serverBuf;
    }

    // Check security headers
    wchar_t headerBuf[4096] = {};
    DWORD headerSize = sizeof(headerBuf);

    // HSTS
    headerSize = sizeof(headerBuf);
    if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_CUSTOM, L"Strict-Transport-Security",
        headerBuf, &headerSize, NULL)) {
        result.hasHSTS = true;
    }

    // CSP
    headerSize = sizeof(headerBuf);
    if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_CUSTOM, L"Content-Security-Policy",
        headerBuf, &headerSize, NULL)) {
        result.hasCSP = true;
    }

    // X-Frame-Options
    headerSize = sizeof(headerBuf);
    if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_CUSTOM, L"X-Frame-Options",
        headerBuf, &headerSize, NULL)) {
        result.hasXFrameOptions = true;
    }

    // X-Content-Type-Options
    headerSize = sizeof(headerBuf);
    if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_CUSTOM, L"X-Content-Type-Options",
        headerBuf, &headerSize, NULL)) {
        result.hasXContentTypeOptions = true;
    }

    // Build notes
    std::wstringstream notes;
    if (!result.hasHSTS) notes << L"Pas de HSTS; ";
    if (!result.hasCSP) notes << L"Pas de CSP; ";
    if (!result.hasXFrameOptions) notes << L"Pas de X-Frame-Options; ";
    if (!result.hasXContentTypeOptions) notes << L"Pas de X-Content-Type-Options; ";

    if (notes.str().empty()) {
        notes << L"Tous headers présents";
    }

    result.notes = notes.str();

    return result;
}

void ScanThread(std::wstring url) {
    LogMessage(L"Scan démarré: " + url);

    ScanResult result = ScanUrl(url);

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_results.push_back(result);
    }

    PostMessageW(g_hwnd, WM_TOOL_RESULT, 0, 0);

    LogMessage(L"Scan terminé: " + url);
    g_scanning = false;
}

void UpdateListView() {
    ListView_DeleteAllItems(g_hwndList);

    std::lock_guard<std::mutex> lock(g_mutex);

    int index = 0;
    for (const auto& res : g_results) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = index;
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(res.url.c_str());
        ListView_InsertItem(g_hwndList, &lvi);

        wchar_t buf[32];
        swprintf_s(buf, L"%d", res.statusCode);
        ListView_SetItemText(g_hwndList, index, 1, buf);

        ListView_SetItemText(g_hwndList, index, 2, const_cast<LPWSTR>(res.server.c_str()));

        std::wstring security;
        if (res.hasHSTS) security += L"HSTS ";
        if (res.hasCSP) security += L"CSP ";
        if (res.hasXFrameOptions) security += L"X-Frame ";
        if (res.hasXContentTypeOptions) security += L"X-Content-Type ";
        if (security.empty()) security = L"Aucun";

        ListView_SetItemText(g_hwndList, index, 3, const_cast<LPWSTR>(security.c_str()));
        ListView_SetItemText(g_hwndList, index, 4, const_cast<LPWSTR>(res.notes.c_str()));

        index++;
    }
}

void ExportToCsv(const std::wstring& filename) {
    std::wofstream file(filename);
    if (!file.is_open()) {
        MessageBoxW(g_hwnd, L"Impossible de créer le fichier CSV", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    file.put(0xFEFF);
    file << L"URL,Status,Server,HSTS,CSP,X-Frame-Options,X-Content-Type-Options,Notes\n";

    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& res : g_results) {
        file << L"\"" << res.url << L"\",";
        file << res.statusCode << L",";
        file << L"\"" << res.server << L"\",";
        file << (res.hasHSTS ? L"Oui" : L"Non") << L",";
        file << (res.hasCSP ? L"Oui" : L"Non") << L",";
        file << (res.hasXFrameOptions ? L"Oui" : L"Non") << L",";
        file << (res.hasXContentTypeOptions ? L"Oui" : L"Non") << L",";
        file << L"\"" << res.notes << L"\"\n";
    }

    file.close();
    MessageBoxW(g_hwnd, L"Export CSV réussi", L"Information", MB_OK | MB_ICONINFORMATION);
    LogMessage(L"Export CSV: " + filename);
}

void ShowAboutDialog() {
    MessageBoxW(g_hwnd,
        L"HttpHeaderInspector v1.0\n\n"
        L"Analyse les headers de sécurité HTTP/HTTPS\n\n"
        L"WinToolsSuite – Security Tools for Network & Pentest\n"
        L"Developed by Ayi NEDJIMI Consultants\n"
        L"https://www.ayinedjimi-consultants.fr\n"
        L"© 2025 – Cybersecurity Research & Training",
        L"À propos",
        MB_OK | MB_ICONINFORMATION);
}

void InitListView(HWND hwndList) {
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.cx = 250;
    lvc.pszText = const_cast<LPWSTR>(L"URL");
    ListView_InsertColumn(hwndList, 0, &lvc);

    lvc.cx = 70;
    lvc.pszText = const_cast<LPWSTR>(L"Status");
    ListView_InsertColumn(hwndList, 1, &lvc);

    lvc.cx = 120;
    lvc.pszText = const_cast<LPWSTR>(L"Server");
    ListView_InsertColumn(hwndList, 2, &lvc);

    lvc.cx = 200;
    lvc.pszText = const_cast<LPWSTR>(L"Headers Sécurité");
    ListView_InsertColumn(hwndList, 3, &lvc);

    lvc.cx = 300;
    lvc.pszText = const_cast<LPWSTR>(L"Notes");
    ListView_InsertColumn(hwndList, 4, &lvc);

    ListView_SetExtendedListViewStyle(hwndList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HMENU hMenu = CreateMenu();
            HMENU hFileMenu = CreateMenu();
            AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXPORT, L"&Exporter CSV...");
            AppendMenuW(hFileMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXIT, L"&Quitter");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&Fichier");

            HMENU hHelpMenu = CreateMenu();
            AppendMenuW(hHelpMenu, MF_STRING, ID_HELP_ABOUT, L"&À propos...");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"&Aide");
            SetMenu(hwnd, hMenu);

            CreateWindowExW(0, L"STATIC", L"URL (https://...):",
                WS_CHILD | WS_VISIBLE,
                10, 15, 120, 20,
                hwnd, NULL, GetModuleHandle(NULL), NULL);

            g_hwndEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"https://www.example.com",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                130, 12, 550, 24,
                hwnd, (HMENU)IDC_EDIT_URL, GetModuleHandle(NULL), NULL);

            CreateWindowExW(0, L"BUTTON", L"Scanner",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                690, 12, 100, 24,
                hwnd, (HMENU)IDC_BTN_SCAN, GetModuleHandle(NULL), NULL);

            g_hwndList = CreateWindowExW(0, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT,
                10, 50, 980, 380,
                hwnd, (HMENU)IDC_LISTVIEW, GetModuleHandle(NULL), NULL);
            InitListView(g_hwndList);

            CreateWindowExW(0, L"BUTTON", L"Exporter CSV",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 440, 150, 30,
                hwnd, (HMENU)IDC_BTN_EXPORT, GetModuleHandle(NULL), NULL);

            CreateWindowExW(0, L"BUTTON", L"Effacer",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                170, 440, 150, 30,
                hwnd, (HMENU)IDC_BTN_CLEAR, GetModuleHandle(NULL), NULL);

            break;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
                case IDC_BTN_SCAN: {
                    if (g_scanning) {
                        MessageBoxW(hwnd, L"Un scan est déjà en cours", L"Information", MB_OK);
                        break;
                    }

                    wchar_t url[1024] = {};
                    GetWindowTextW(g_hwndEdit, url, 1024);
                    if (wcslen(url) == 0) {
                        MessageBoxW(hwnd, L"Veuillez entrer une URL", L"Erreur", MB_OK | MB_ICONERROR);
                        break;
                    }

                    g_scanning = true;
                    if (g_scanThread.joinable()) g_scanThread.join();
                    g_scanThread = std::thread(ScanThread, std::wstring(url));
                    break;
                }

                case IDC_BTN_EXPORT:
                case ID_FILE_EXPORT: {
                    wchar_t filename[MAX_PATH] = L"headers.csv";
                    OPENFILENAMEW ofn = {};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFile = filename;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
                    ofn.Flags = OFN_OVERWRITEPROMPT;
                    if (GetSaveFileNameW(&ofn)) {
                        ExportToCsv(filename);
                    }
                    break;
                }

                case IDC_BTN_CLEAR:
                    {
                        std::lock_guard<std::mutex> lock(g_mutex);
                        g_results.clear();
                    }
                    UpdateListView();
                    LogMessage(L"Résultats effacés");
                    break;

                case ID_FILE_EXIT:
                    PostMessageW(hwnd, WM_CLOSE, 0, 0);
                    break;

                case ID_HELP_ABOUT:
                    ShowAboutDialog();
                    break;
            }
            break;
        }

        case WM_TOOL_RESULT:
            UpdateListView();
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_SCAN), TRUE);
            break;

        case WM_DESTROY:
            g_scanning = false;
            if (g_scanThread.joinable()) g_scanThread.join();
            if (g_logFile.is_open()) {
                LogMessage(L"=== HttpHeaderInspector arrêté ===");
                g_logFile.close();
            }
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    InitLog();

    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"HttpHeaderInspector";

    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(0, L"HttpHeaderInspector",
        L"HttpHeaderInspector - Analyse Headers HTTP",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1020, 540,
        NULL, NULL, hInstance, NULL);

    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
