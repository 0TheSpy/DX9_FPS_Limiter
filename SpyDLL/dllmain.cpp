// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <iostream> 
using namespace std;

#include <d3d9.h>
#include <d3dx9.h>
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3dx9.lib")
#include "detours.h"
#pragma comment(lib, "detours.lib") 

//#define DEBUG

bool IsEnabled = false;
int FPS = 13;
int HOTKEY = VK_INSERT;
bool HOLD = 0;
float refreshrate = 1.0f / FPS;
bool bNeedExit = false;

struct args
{
    int fps;
    int key;
    bool hold;
};

#ifdef DEBUG
#define CONSOLE
#define printfdbg printf
#else
#define printfdbg(...) 
#endif

extern "C" __declspec(dllexport) int NeedExit()
{
    bNeedExit = true;
    return bNeedExit;
}

extern "C" __declspec(dllexport) int setFpsHotkey(args* argumento) 
{
    FPS = argumento->fps;
    HOTKEY = argumento->key;
    HOLD = argumento->hold;
    refreshrate = 1.0f / FPS;
#ifdef DEBUG
    Beep(500, 200); 
#endif
    printfdbg("changed fps %d key %d hold %d\n", FPS, HOTKEY, HOLD); 
    return 1;
}

#include <chrono> 
#include <tchar.h>
#include <stdio.h>
#include <string>

HMODULE myhModule;

chrono::system_clock::time_point mElapsedTime = chrono::system_clock::now();

typedef HRESULT(__stdcall* pPresent)(IDirect3DDevice9* pDevice, const RECT* pSourceRect, const RECT* pDestRect, HWND hDestWindowOverride, const RGNDATA* pDirtyRegion);
pPresent oPresent;

HRESULT __stdcall hkPresent(IDirect3DDevice9* pDevice, const RECT* pSourceRect, const RECT* pDestRect, HWND hDestWindowOverride, const RGNDATA* pDirtyRegion) 
{
    if (IsEnabled) { 
        again:
        std::chrono::duration<float> diff = chrono::system_clock::now() - mElapsedTime;
        float remaining = diff.count(); 
        if (remaining < refreshrate)
        { 
            Sleep(1);
            goto again;
        } 
        mElapsedTime = chrono::system_clock::now();  
    }
    return oPresent(pDevice, pSourceRect, pDestRect, hDestWindowOverride, pDirtyRegion);
}

#include <Psapi.h>
#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

DWORD FindPattern(std::string moduleName, std::string pattern)
{
    printfdbg("findpattern %s %s\n", moduleName.c_str(), pattern.c_str());
    const char* pat = pattern.c_str();
    DWORD firstMatch = 0;
    DWORD rangeStart = (DWORD)GetModuleHandleA(moduleName.c_str());
    MODULEINFO miModInfo; GetModuleInformation(GetCurrentProcess(), (HMODULE)rangeStart, &miModInfo, sizeof(MODULEINFO));
    DWORD rangeEnd = rangeStart + miModInfo.SizeOfImage;
    for (DWORD pCur = rangeStart; pCur < rangeEnd; pCur++)
    {
        if (!*pat)
            return firstMatch;

        if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat))
        {
            if (!firstMatch)
                firstMatch = pCur;

            if (!pat[2])
                return firstMatch;

            if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
                pat += 3;

            else
                pat += 2;
        }
        else
        {
            pat = pattern.c_str();
            firstMatch = 0;
        }
    }
    return NULL;
}
 
#pragma comment(lib, "Winmm.lib")

DWORD WINAPI InitFunc() {

#ifdef CONSOLE
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    printfdbg("console alloc\n");
#endif 
    printfdbg("limiting FPS to %d\n", FPS);
    
    PVOID addrObj = (PVOID*)((FindPattern((string)"d3d9.dll",
            (string)"C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86")) + 2);
    PVOID addrPresent = *(PVOID*)((DWORD)*(PVOID*)addrObj + 0x11 * 4);

    BYTE safebytes[5] = { 0,0,0,0,0 }; 
    DWORD oldProtect = 0;
    VirtualProtect(addrPresent, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(&safebytes, addrPresent, 5);
    VirtualProtect(addrPresent, 5, oldProtect, &oldProtect);

    printfdbg("Hooking Present @ %x\n", addrPresent);
    oPresent = (pPresent)DetourFunction((PBYTE)addrPresent, (PBYTE)hkPresent);
     
    printfdbg("Present hooked\n");
    Sleep(1500); 
    while (1) { 

        if (!HOLD)
        {
            if (GetAsyncKeyState(HOTKEY) < 0)
            {
                IsEnabled = !IsEnabled;
                Sleep(200);
            }
        }
        else
        {
            if (GetAsyncKeyState(HOTKEY) < 0)
                IsEnabled = 1;
            else IsEnabled = 0;
        }

        Sleep(10);

        if (bNeedExit) break;
        //if (GetAsyncKeyState(VK_DELETE)) { IsEnabled = 0;  break; }
    }
      
    IsEnabled = 0; 
   
    bool bIsUnhooked = DetourRemove(reinterpret_cast<BYTE*>(oPresent), reinterpret_cast<BYTE*>(hkPresent));
    if (bIsUnhooked)
        printfdbg("Unhooked successfully\n");
    else 
    {  
        sndPlaySound("Error", SND_SYSTEM); 
        printfdbg("DetourRemove error\n");  

        VirtualProtect(addrPresent, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(addrPresent, &safebytes, 5);
        VirtualProtect(addrPresent, 5, oldProtect, &oldProtect);
    }
        
#ifdef CONSOLE
    fclose(fp);
    FreeConsole();
#endif

    FreeLibraryAndExitThread(myhModule, 0); 
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        myhModule = hModule; 
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitFunc, NULL, 0, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH: 
        break;
    }
    return TRUE;
}

