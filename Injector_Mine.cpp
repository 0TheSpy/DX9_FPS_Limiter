#include <iostream> 
#include <Windows.h>

//#define CONSOLE

#ifdef CONSOLE
#define printfdbg printf
#else
#define printfdbg(...) 
#endif
 
#include "resource.h"

using namespace std;

string author = "Author: 0TheSpy";

struct pass_args
{
	int fps;
	int key;
	bool hold; 
	char* proc; 
}; 

pass_args injarg;
char procname_[256];
bool hold = 0;
int injectcount_global = 0;
int hk = 45; 

LONG GetDWORDRegKey(HKEY hKey, const std::string& strValueName, DWORD& nValue, DWORD nDefaultValue)
{
	nValue = nDefaultValue;
	DWORD dwBufferSize(sizeof(DWORD));
	DWORD nResult(0);
	LONG nError = ::RegQueryValueEx(hKey,strValueName.c_str(),0,NULL,reinterpret_cast<LPBYTE>(&nResult),&dwBufferSize);
	if (ERROR_SUCCESS == nError) nValue = nResult; 
	return nError;
}

LONG GetBoolRegKey(HKEY hKey, const std::string& strValueName, bool& bValue, bool bDefaultValue)
{
	DWORD nDefValue((bDefaultValue) ? 1 : 0);
	DWORD nResult(nDefValue);
	LONG nError = GetDWORDRegKey(hKey, strValueName.c_str(), nResult, nDefValue);
	if (ERROR_SUCCESS == nError) bValue = (nResult != 0) ? true : false; 
	return nError;
}

LONG GetStringRegKey(HKEY hKey, const std::string& strValueName, std::string& strValue, const std::string& strDefaultValue)
{
	strValue = strDefaultValue;
	CHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;
	nError = RegQueryValueEx(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
	if (ERROR_SUCCESS == nError) strValue = szBuffer; 
	return nError;
}

#include <tlhelp32.h> 

int FindProcByName(const char* processname) { 
	HANDLE hSnapshot;
	PROCESSENTRY32 pe;
	int pid = 0;
	BOOL hResult;
	 
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) return 0;
	 
	pe.dwSize = sizeof(PROCESSENTRY32); 
	hResult = Process32First(hSnapshot, &pe);
	 
	while (hResult) { 
		if (strcmp(processname, pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		hResult = Process32Next(hSnapshot, &pe);
	}
	 
	CloseHandle(hSnapshot);
	return pid;
}

#include <string>
#define ReCa reinterpret_cast

uintptr_t GetModuleBaseEx(DWORD procId, const char* modName)
{
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!_stricmp(modEntry.szModule, modName))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}


uintptr_t GetProcAddressEx(HANDLE hProcess, uintptr_t moduleBase, const char* function)
{
	if (!function || !hProcess || !moduleBase)
		return 0;
	  
	IMAGE_DOS_HEADER Image_Dos_Header = { 0 };

	if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(moduleBase), &Image_Dos_Header, sizeof(IMAGE_DOS_HEADER), nullptr))
		return 0;

	if (Image_Dos_Header.e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	IMAGE_NT_HEADERS Image_Nt_Headers = { 0 };

	if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(moduleBase + Image_Dos_Header.e_lfanew), &Image_Nt_Headers, sizeof(IMAGE_NT_HEADERS), nullptr))
		return 0;

	if (Image_Nt_Headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	IMAGE_EXPORT_DIRECTORY Image_Export_Directory = { 0 };
	uintptr_t img_exp_dir_rva = 0;

	if (!(img_exp_dir_rva = Image_Nt_Headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))
		return 0;

	if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(moduleBase + img_exp_dir_rva), &Image_Export_Directory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr))
		return 0;

	uintptr_t EAT = moduleBase + Image_Export_Directory.AddressOfFunctions;
	uintptr_t ENT = moduleBase + Image_Export_Directory.AddressOfNames;
	uintptr_t EOT = moduleBase + Image_Export_Directory.AddressOfNameOrdinals;

	WORD ordinal = 0;
	SIZE_T len_buf = strlen(function) + 1;
	char* temp_buf = new char[len_buf];

	for (size_t i = 0; i < Image_Export_Directory.NumberOfNames; i++)
	{
		uintptr_t tempRvaString = 0;

		if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(ENT + (i * sizeof(uintptr_t))), &tempRvaString, sizeof(uintptr_t), nullptr))
			return 0;

		if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(moduleBase + tempRvaString), temp_buf, len_buf, nullptr))
			return 0;

		if (!lstrcmpi(function, temp_buf))
		{
			if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(EOT + (i * sizeof(WORD))), &ordinal, sizeof(WORD), nullptr))
				return 0;

			uintptr_t temp_rva_func = 0;

			if (!ReadProcessMemory(hProcess, ReCa<LPCVOID>(EAT + (ordinal * sizeof(uintptr_t))), &temp_rva_func, sizeof(uintptr_t), nullptr))
				return 0;

			delete[] temp_buf;
			return moduleBase + temp_rva_func;
		}
	}
	delete[] temp_buf;
	return 0;
}

typedef struct {
	PBYTE imageBase;
	HMODULE(WINAPI* loadLibraryA)(PCSTR);
	FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
} LoaderData;

DWORD WINAPI loadLibrary(LoaderData* loaderData)
{
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(loaderData->imageBase + ((PIMAGE_DOS_HEADER)loaderData->imageBase)->e_lfanew);
	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(loaderData->imageBase
		+ ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD delta = (DWORD)(loaderData->imageBase - ntHeaders->OptionalHeader.ImageBase);
	while (relocation->VirtualAddress) {
		PWORD relocationInfo = (PWORD)(relocation + 1);
		for (int i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++)
			if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
				*(PDWORD)(loaderData->imageBase + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += delta;

		relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(loaderData->imageBase
		+ ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (importDirectory->Characteristics) {
		PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->OriginalFirstThunk);
		PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->FirstThunk);

		HMODULE module = loaderData->loadLibraryA((LPCSTR)loaderData->imageBase + importDirectory->Name);

		if (!module)
			return FALSE;

		while (originalFirstThunk->u1.AddressOfData) {
			DWORD Function = (DWORD)loaderData->getProcAddress(module, originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->imageBase + originalFirstThunk->u1.AddressOfData))->Name);

			if (!Function)
				return FALSE;

			firstThunk->u1.Function = Function;
			originalFirstThunk++;
			firstThunk++;
		}
		importDirectory++;
	}

	if (ntHeaders->OptionalHeader.AddressOfEntryPoint) {
		DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
			(loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint))
			((HMODULE)loaderData->imageBase, DLL_PROCESS_ATTACH, NULL);

		return result;
	}
	return TRUE;
}

VOID stub(VOID) { }

HWND hwndEdit_proc;
HWND hwndProcLabel;
HANDLE hProcess = 0;
bool injected = false;
DWORD dllptr = 0;

 
bool Inject(pass_args* inject_args);
void IsProcessAlive(pass_args * inject_args)
{
	DWORD exitcode = STILL_ACTIVE;
	while (exitcode == STILL_ACTIVE)
	{
		GetExitCodeProcess(hProcess, &exitcode);
		Sleep(1000);
	}
	hProcess = 0;
	injected = false;
	dllptr = 0;
	EnableWindow(hwndEdit_proc, 1);
#ifdef DEBUG
	SetWindowText(hwndProcLabel, "Process "); //not selected 
#endif
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Inject, inject_args, 0, 0);
}
 
bool IsX64win()
{
	UINT x64test = GetSystemWow64DirectoryA(NULL, 0);
	if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)  return FALSE;
	else return TRUE;
} 
 
bool Inject(pass_args * inject_args)
{	
	injectcount_global++;
	int injectcount = injectcount_global; 
	char* procname = inject_args->proc; 
	printfdbg("injectargs %d %d %d %s\n", inject_args->fps, inject_args->key, inject_args->hold, procname); 
	DWORD procID = FindProcByName(procname);

#ifdef DEBUG
	string procwait = "Process: awaiting " + string(procname);
	SetWindowText(hwndProcLabel, procwait.c_str());
#endif

	while (procID == 0)
	{
		if (injectcount != injectcount_global) 
			return 0;
		printfdbg("Waiting for %s...\n", procname);
		procID = FindProcByName(procname);
		Sleep(500); 
	}

	DWORD d3d9_dll = GetModuleBaseEx(procID, "d3d9.dll");
	while (d3d9_dll == 0)
	{
		if (injectcount != injectcount_global)
			return 0;
		printfdbg("Waiting for d3d9.dll...\n");
		d3d9_dll = GetModuleBaseEx(procID, "d3d9.dll");
		Sleep(500);
	}
	   
#ifdef DEBUG
	SetWindowText(hwndProcLabel, "Process"); //ok
#endif

	printfdbg("procid %x\n", procID);
	  
	if (!hProcess)
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);

	printfdbg("OpenProcess %x (%x)\n", hProcess, GetLastError());

	if (!hProcess) 
		return 0;

	printfdbg("Handle %x\n", hProcess);

	if (!injected) {

		HRSRC hResInfo = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL1), "DLL");
		HANDLE hRes = LoadResource(NULL, hResInfo);
		LPVOID binary = LockResource(hRes);

		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((char*)binary + ((PIMAGE_DOS_HEADER)binary)->e_lfanew);

		PBYTE executableImage = (PBYTE)VirtualAllocEx(hProcess, NULL, ntHeaders->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		WriteProcessMemory(hProcess, executableImage, binary,
			ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

		PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
			WriteProcessMemory(hProcess, executableImage + sectionHeaders[i].VirtualAddress,
				(char*)binary + sectionHeaders[i].PointerToRawData, sectionHeaders[i].SizeOfRawData, NULL);

		LoaderData* loaderMemory = (LoaderData*)VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READ);

		LoaderData loaderParams;
		loaderParams.imageBase = executableImage;
		loaderParams.loadLibraryA = LoadLibraryA;
		loaderParams.getProcAddress = GetProcAddress;

		WriteProcessMemory(hProcess, loaderMemory, &loaderParams, sizeof(LoaderData),
			NULL);
		WriteProcessMemory(hProcess, loaderMemory + 1, loadLibrary,
			(DWORD)stub - (DWORD)loadLibrary, NULL);
		WaitForSingleObject(CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(loaderMemory + 1),
			loaderMemory, 0, NULL), INFINITE);
		VirtualFreeEx(hProcess, loaderMemory, 0, MEM_RELEASE);

		dllptr = (DWORD)executableImage;
		printfdbg("Dll allocated at %x\n", dllptr);
		if (!dllptr) 
			return false;

		injected = true;
		EnableWindow(hwndEdit_proc, 0);
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)IsProcessAlive, &injarg, 0, 0);
	}
	 
	LPVOID param = VirtualAllocEx(hProcess, NULL, sizeof(pass_args), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, param, inject_args, sizeof(pass_args), 0);

	HANDLE hLoadThread_setfpshotkey = CreateRemoteThread(hProcess, 0, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddressEx(hProcess, dllptr, "setFpsHotkey"),
		param, 0, 0);

	return 1;
}

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
 
char* KeycodeToText(int wParam, char* kktt)
{
	unsigned int scanCode = MapVirtualKey(wParam, MAPVK_VK_TO_VSC);

	// because MapVirtualKey strips the extended bit for some keys
	switch (wParam)
	{
	case VK_LEFT:
	case VK_UP:
	case VK_RIGHT:
	case VK_DOWN: // arrow keys
	case VK_PRIOR:
	case VK_NEXT: // page up and page down
	case VK_END:
	case VK_HOME:
	case VK_INSERT:
	case VK_DELETE:
	case VK_DIVIDE: // numpad slash
	case VK_NUMLOCK:
	case VK_LWIN:
	case VK_RWIN: 
	{
		scanCode |= 0x100; // set extended bit
		break;
	}
	}

	char keyName[50];
	if (GetKeyNameText(scanCode << 16, keyName, sizeof(keyName)) != 0)
	{
		memcpy(kktt, keyName, sizeof(keyName));
		printfdbg("keyName %d : %s\n", wParam, keyName);
		return keyName;
	}
	else
	{
		string err = "UnkBtn " + to_string(wParam);
		memcpy(kktt, err.c_str(), err.length() * sizeof(char) + 1);
		printfdbg("keyName ERROR\n");
		return (char*)"ERROR";
	}
}

HWND hwndPressBtn;
LRESULT CALLBACK MyWndProcHandler(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{   
	switch (uMsg)
	{ 
	case WM_KEYDOWN: 
	{
		printfdbg("key %d pressed\n", wParam); 
		hk = wParam;
		char kktt[255];
		KeycodeToText(wParam, (char*) &kktt); 
		SetWindowText(hwndPressBtn, kktt); 
		SetFocus(hwndPressBtn);  
		return TRUE;
	}

	case WM_KILLFOCUS:
	{
		char kktt[255];
		KeycodeToText(hk, (char*) & kktt);
		SetWindowText(hwndPressBtn, kktt); 
		return TRUE;
	}
	  
	break; 
	} 
	return DefWindowProc(hwndDlg, uMsg, wParam, lParam);
}

HINSTANCE hInstanceGlobal;
  
bool LoadSettings(HWND hp, HWND hf, HWND hb)
{
	HKEY key; REGSAM flag;
	if (IsX64win())  flag = KEY_WOW64_64KEY;  else  flag = KEY_WOW64_32KEY;
	const char* loc = TEXT("SOFTWARE\\_FPS_limiter");

	LONG ret = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, loc, 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | flag, &key);
	printfdbg("RegOpenKeyEx returned %x\n", ret);

	if (ret == ERROR_SUCCESS)
	{
		std::string strProcName;
		GetStringRegKey(key, "procname", strProcName, "");
		DWORD dwFpsMax; DWORD dwHotKey; bool bHold;
		GetDWORDRegKey(key, "fpsmax", dwFpsMax, 0);
		GetDWORDRegKey(key, "hotkey", dwHotKey, 0);
		GetBoolRegKey(key, "hold", bHold, 0);
		printfdbg("Settings found %s %d %d %d\n", strProcName.c_str(), dwFpsMax, dwHotKey, bHold);
		hold = bHold;
		RegCloseKey(key);

		SetWindowText(hp, strProcName.c_str());
		SetWindowText(hf, std::to_string(dwFpsMax).c_str()); 
		
		hk = dwHotKey;
		char kktt[255];
		KeycodeToText(dwHotKey, (char*)&kktt);
		SetWindowText(hwndPressBtn, kktt);

		if (bHold) 
			SetWindowText(hb, "Hold"); 
		else 
			SetWindowText(hb, "Toggle"); 

		char* procname = (char*)strProcName.c_str();
		int size = strlen(&procname[0]);  

		ZeroMemory(procname_, 256);
		memcpy(procname_, procname, size); 
		injarg.fps = dwFpsMax; injarg.hold = bHold; 
		injarg.key = dwHotKey; injarg.proc = (char*) & procname_;
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Inject, &injarg, 0, 0);
		  
		return true;
	}
	printfdbg("No settings found\n");
	return false;
}

bool SaveSettings(char* procname, int fps, int hkey, bool hold)
{ 
	HKEY key; REGSAM flag;
	if (IsX64win())  flag = KEY_WOW64_64KEY;  else  flag = KEY_WOW64_32KEY;
	const char* loc = TEXT("SOFTWARE\\_FPS_limiter");

	LONG ret = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, loc, 0, KEY_SET_VALUE | flag, &key);
	if (ret != ERROR_SUCCESS)
		ret = RegCreateKeyExA(HKEY_LOCAL_MACHINE, loc, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | flag, NULL, &key, NULL);

	if (ret == ERROR_SUCCESS)
	{
		char* arr_ptr = &procname[0];
		RegSetValueExA(key, "procname", 0, REG_SZ, (LPCBYTE)procname, strlen(arr_ptr));
		int status = RegSetValueExA(key, "fpsmax", 0, REG_DWORD, (LPCBYTE)&fps, 4);
		RegSetValueExA(key, "hotkey", 0, REG_DWORD, (LPCBYTE)&hkey, 4);
		int inthold = (int)hold;
		RegSetValueExA(key, "hold", 0, REG_DWORD, (LPCBYTE)&inthold, 4);
		RegCloseKey(key);
		return status == ERROR_SUCCESS;
	}
	return 0;
}


#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
 
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	LPSTR lpCmdLine, int nCmdShow)
{
#ifdef CONSOLE
	AllocConsole();
	FILE* fp;
	freopen_s(&fp, "CONOUT$", "w", stdout);
	printfdbg("console alloc\n");
#endif 
	hInstanceGlobal = hInstance;

	MSG  msg; 
	WNDCLASS wc = { 0 };
	wc.lpszClassName = TEXT("DX9 FPS Limiter");
	wc.hInstance = hInstance;
	wc.hbrBackground = GetSysColorBrush(COLOR_3DFACE);
	wc.lpfnWndProc = WndProc;
	wc.hCursor = LoadCursor(0, IDC_ARROW);
	wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
	 
	RegisterClass(&wc);
	CreateWindow(wc.lpszClassName, TEXT("DX9 FPS Limiter"),
		WS_VISIBLE | WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX,
		150, 150, 235, 260, 0, 0, hInstance, 0);
	  
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;
}
 
bool CALLBACK SetFont(HWND child, LPARAM font) {
	SendMessage(child, WM_SETFONT, font, true);
	return true;
}
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{ 
	static HWND hwndEdit_fps;
	static HWND hwndEdit_key;
	static HWND hwndCheckbox;
	  
	static HFONT s_hFont = NULL;

	switch (msg)
	{
	case WM_CREATE:
	{   
		const long nFontSize = 10;
		HDC hdc = GetDC(hwnd);
		LOGFONT logFont = { 0 };
		logFont.lfHeight = -MulDiv(nFontSize, GetDeviceCaps(hdc, LOGPIXELSY), 72);
		logFont.lfWeight = FW_NORMAL; 
		s_hFont = CreateFontIndirect(&logFont);
		  
		ReleaseDC(hwnd, hdc); 

		CreateWindow(TEXT("button"), TEXT("Save Settings"),
			WS_VISIBLE | WS_CHILD,
			20, 180, 180, 25,
			hwnd, (HMENU)1, NULL, NULL);

		hwndProcLabel = CreateWindow("STATIC", "Process", WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU, 20, 10, 1000, 20, hwnd, (HMENU)3, NULL, NULL);

		hwndEdit_proc=CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "castle.exe",
			WS_VISIBLE | WS_CHILD | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
			20, 30, 180, 25,
			hwnd,
			(HMENU)4, NULL, NULL);
		  
		CreateWindow("STATIC", "FPS Limit", WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU, 20, 65, 100, 20, hwnd, (HMENU)5, NULL, NULL);

		hwndEdit_fps=CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "13",
			WS_VISIBLE | WS_CHILD | WS_BORDER | ES_LEFT,
			20, 85, 180, 25,
			hwnd,
			(HMENU)6, NULL, NULL);

		CreateWindow("STATIC", "Hotkey", WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU, 20, 120, 100, 20, hwnd, (HMENU)7, NULL, NULL);
		CreateWindow("STATIC", "Mode", WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU, 120, 120, 100, 20, hwnd, (HMENU)7, NULL, NULL);

		hwndEdit_key=CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "45",
			WS_CHILD | WS_BORDER | ES_LEFT | WS_OVERLAPPED,  
			20, 145, 1, 1,
			hwnd,
			(HMENU)8, NULL, NULL);
		
		WNDPROC OldWndProc = (WNDPROC)SetWindowLongPtr(hwndEdit_key,
			GWLP_WNDPROC, (LONG_PTR)MyWndProcHandler);
		 
		hwndCheckbox = CreateWindow(TEXT("button"), TEXT("Hold"),
			WS_VISIBLE | WS_CHILD,
			120, 140, 80, 25,
			hwnd, (HMENU)2, NULL, NULL);
		  
		hwndPressBtn = CreateWindow(TEXT("button"), TEXT("Insert"),
			WS_VISIBLE | WS_CHILD,
			20, 140, 80, 25,
			hwnd, (HMENU)11, NULL, NULL);
		 
		if (!LoadSettings(hwndEdit_proc, hwndEdit_fps, hwndCheckbox)) {
			injarg.fps = 13; injarg.key = VK_INSERT; injarg.hold = 1; injarg.proc = (char*)"castle.exe";
			CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Inject, &injarg, 0, 0);
		}
		  
		EnumChildWindows(hwnd, (WNDENUMPROC)SetFont, (LPARAM)s_hFont); //GetStockObject(DEFAULT_GUI_FONT) 

		break;
	}
  
	case WM_COMMAND:
	{
		if (LOWORD(wParam) == 1) {

			int len = GetWindowTextLength(hwndEdit_proc) + 1;
			char hwndEdit_proc_text[256];
			GetWindowText(hwndEdit_proc, hwndEdit_proc_text, len); 

			len = GetWindowTextLength(hwndEdit_proc) + 1;
			char hwndEdit_fps_text[256];
			GetWindowText(hwndEdit_fps, hwndEdit_fps_text, len); 

			SaveSettings(hwndEdit_proc_text, atoi(hwndEdit_fps_text), hk, hold);
			 
			char* procname = (char*)hwndEdit_proc_text;
			int size = strlen(&procname[0]);  
			ZeroMemory(procname_, 256);
			memcpy(procname_, procname, size);

			injarg.fps = atoi(hwndEdit_fps_text); injarg.hold = hold;
			injarg.key = hk; injarg.proc = (char*)&procname_;
			CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Inject, &injarg, 0, 0); 

			 
#ifdef CONSOLE
			Beep(40, 50);  
#endif
		}
		 
		if (LOWORD(wParam) == 2) {
			hold = !hold;
			if (hold)
				SetWindowText(hwndCheckbox, "Hold");
			else
				SetWindowText(hwndCheckbox, "Toggle"); 
		}
		  
		if (LOWORD(wParam) == 11) { 
			SetWindowText(hwndPressBtn, "Press");
			SetFocus(hwndEdit_key);
			 
			break;
		}

		break;
	}

	case WM_DESTROY:
	{
		if (injected) {
			HANDLE hLoadThread_NeedExit = CreateRemoteThread(hProcess, 0, 0,
				(LPTHREAD_START_ROUTINE)GetProcAddressEx(hProcess, dllptr, "NeedExit"),
				0, 0, 0);

			//WaitForSingleObjectEx(hLoadThread_NeedExit, INFINITE, false); 
		}

		PostQuitMessage(0);
		break;
	}
	}
	return DefWindowProc(hwnd, msg, wParam, lParam);
}

 


