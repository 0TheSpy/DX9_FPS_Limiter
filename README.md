First build FpsLimiterLib project (Release x86) then DX9_FPS_LIMITER project (Release x86)

![Screenshot](https://i.imgur.com/DDEH6EB.png)

Features:

Initially, the program was written for Castle Crashers speedruns, so it supports only X86 DX9 processes

Interface of the injector is written on GDI

FPS restriction is carried out using a D3D9::Present hook

DLL is embedded in the injector file

Change the FPS, button and mode (Hold/Toggle) at any time while target process is running

Communication between injector and DLL is carried out using exported functions

Program settings are stored in the Registry

DLL injects in the specified process automatically 

When the target process is closed, the injector resumes its awaiting

When closing injector, the hooks inside the process are removed
