// Shell.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "Shell.h"
#include "aplib.h"
#include <stdlib.h>
#pragma comment(lib,"./aplib.lib")
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")


typedef struct _TYPEOFFSET
{
	WORD offset : 12;		//偏移值
	WORD Type : 4;			//重定位属性(方式)
}TYPEOFFSET, *PTYPEOFFSET;


//函数和变量的声明
DWORD MyGetProcAddress();		//自定义GetProcAddress
HMODULE	GetKernel32Addr();		//获取Kernel32加载基址
void Start();					//启动函数(Shell部分的入口函数)
void InitFun();					//初始化函数指针和变量
BOOL DePack();					//解压缩操作
void DeXorCode();				//解密操作
void RecReloc();				//修复重定位操作
void RecIAT();					//修复IAT操作
int CreatWin();					//创建一个窗口
BOOL CheckValue();				//检测验证码是否正确
unsigned char * CalcStr(DWORD num);		//计算出一个字符串
BOOL ExcFun(char *pArr);
SHELL_DATA g_stcShellData = { (DWORD)Start };
								//Shell用到的全局变量结构体
DWORD dwImageBase	= 0;		//整个程序的镜像基址
DWORD dwPEOEP		= 0;		//PE文件的OEP

char ShellOpCode[] = { "\x60\xE8\x27\x00\x00\x00\x36\x8D\x64\x24\x04\x36\x89\x45\xB8\xE8\x00\x00\x00\x00\x75\x0D\xEB\x15\x36\x8D\x64\x24\x04\xEB\x04\x36\x89\x45\xA8\xEB\xF8\x3E\x8B\x10\xE8\x17\x00\x00\x00\x36\x8D\x64\x24\x04\xE8\x03\x00\x00\x00\xE8\xEB\x04\x5D\x45\x55\xC3\xE8\x01\x00\x00\x00\xE9\x58\x83\xC0\x10\x8B\xD8\x61" };

//Shell部分用到的函数定义
fnGetProcAddress	g_pfnGetProcAddress		= NULL;
fnLoadLibraryA		g_pfnLoadLibraryA		= NULL;
fnGetModuleHandleA	g_pfnGetModuleHandleA	= NULL;
fnVirtualProtect	g_pfnVirtualProtect		= NULL;
fnVirtualAlloc		g_pfnVirtualAlloc		= NULL;
fnExitProcess		g_pfnExitProcess		= NULL;
fnMessageBox		g_pfnMessageBoxA		= NULL;
fnVirtualFree       g_pfnVirtualFree        = NULL;
fnmemmove           g_pfnMemcopy			= NULL;
fnmemset            g_pfnMemSet				= NULL;
fnDefWindowProcW	g_pfnDefWindowProcW		= NULL;
fnRegisterClassExA	g_pfnRegisterClassExA	= NULL;
fnCreateWindowExA	g_pfnCreateWindowExA	= NULL;
fnShowWindow		g_pfnShowWindow			= NULL;
fnUpdateWindow		g_pfnfnUpdateWindow		= NULL;
fnGetMessageW		g_pfnGetMessageW		= NULL;
fnTranslateMessage	g_PfnTranslateMessage	= NULL;
fnDispatchMessageA  g_fnDispatchMessageA	= NULL;
fnCreateDialogParamA g_pfnfnCreateDialogParamA = NULL;
fnDialogBoxParamA	g_pfnfnDialogBoxParamA	= NULL;
fnDialogBoxParamW	g_pfnfnDialogBoxParamW	= NULL;
fnCreateWindowExW	g_pfnfnCreateWindowExW	= NULL;
fnRegisterClassW	g_pfnfnRegisterClassW	= NULL;
fnGetDlgItem		g_pfnfnGetDlgItem		= NULL;
fnGetWindowTextA	g_pfnGetWindowTextA		= NULL;
fnPostQuitMessage	g_pfnfnPostQuitMessage	= NULL;
fnRegCreateKeyA		g_pfnfnRegCreateKeyA	= NULL;
fnRegSetValueExA	g_pfnfnRegSetValueExA	= NULL;
fnRegOpenKeyExA		g_pfnfnRegOpenKeyExA	= NULL;
fnRegQueryValueExA	g_pfnfnRegQueryValueExA = NULL;
fnRegCloseKey		g_pfnfnRegCloseKey		= NULL;
//窗口回调
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CREATE:
	{
		//创建按钮
		g_pfnfnCreateWindowExW(NULL, L"button", L"确定", WS_CHILD | WS_VISIBLE, 60, 120, 80, 30, hWnd, (HMENU)10001, (HINSTANCE)dwImageBase, NULL);
		//创建文本框
		g_pfnfnCreateWindowExW(NULL, L"edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER, 20, 60, 200, 30, hWnd, (HMENU)10002, (HINSTANCE)dwImageBase, NULL);
	}
	break;
	case WM_COMMAND:
	{
		WORD wHign = HIWORD(wParam);//高位代表句柄
		WORD wLow = LOWORD(wParam);//低位代表控件ID
		HWND hEdit = g_pfnfnGetDlgItem(hWnd, 10002);//获得文本框的句柄
		DWORD n = 0;
		DWORD NumInt = 0;//计算出数字的和
		DWORD CharSumS = 0;//计算出小写字母的和
		DWORD CharSumB = 0;//计算出大写数字的和
		char buff[100] = { 0 };
		switch (wLow)
		{
		case 10001://表明是按钮
			g_pfnGetWindowTextA(hEdit, buff, 100);//获取文本框中的内容
			while (buff[n])
			{
				if (buff[n] >= '0'&&buff[n] <= '9')
					NumInt += buff[n];
				else if (buff[n] <= 'Z' && buff[n] >= 'A')
					CharSumB += buff[n];
				else if (buff[n] >= 'z' && buff[n] >= 'a')
					CharSumS += buff[n];
				n++;
			}
			NumInt += CharSumS + CharSumB;//获取字符数字的ASCII总和
			//2、接下来将其保存到注册表中
			HKEY hMyKey = 0;//句柄
			if (g_pfnfnRegCreateKeyA(HKEY_CURRENT_USER, "Software\\ZXN", &hMyKey))
				g_pfnMessageBoxA(NULL, "有误", "提示", MB_OK);//打开或者创建一个注册表
			if (g_pfnfnRegSetValueExA(hMyKey, "UserInput", 0, REG_DWORD, (const BYTE *)&NumInt, 4))
				g_pfnMessageBoxA(NULL, "有误", "提示", MB_OK);//将键值写入注册表
			//3、关闭注册表键值
			g_pfnfnRegCloseKey(hMyKey);
			//弹框，结束整个程序
			g_pfnMessageBoxA(NULL, "验证码已接收，重启程序", "提示", MB_OK);
			g_pfnExitProcess(0);
			break;
		}
	}
	break;	
	}


	return g_pfnDefWindowProcW(hWnd, uMsg, wParam, lParam);
}
__declspec(naked) void Start()
{
 	__asm pushad

	InitFun();
	//进行重启验证
	if (!CheckValue())
		CreatWin();//如果检测到有错误，再次输入验证码
	g_pfnMessageBoxA(NULL, "验证通过", "提示", MB_OK);
	DePack();
	DeXorCode();
	if (g_stcShellData.stcPERelocDir.VirtualAddress)//判断有没有重定位
		RecReloc();
	RecIAT();
	//获取OEP信息
	dwPEOEP = g_stcShellData.dwPEOEP + dwImageBase;
	__asm popad
	__asm jmp dwPEOEP
	
	g_pfnExitProcess(0);
}

//修复iat
void RecIAT()
{
	//1.获取导入表结构体指针
	PIMAGE_IMPORT_DESCRIPTOR pPEImport = 
		(PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase + g_stcShellData.stcPEImportDir.VirtualAddress);
	
	//2.修改内存属性为可写
	DWORD dwProSize = g_stcShellData.dwIATSectionSize;
	DWORD dwOldProtect = 0;
	g_pfnVirtualProtect((LPBYTE)(dwImageBase + g_stcShellData.dwIATSectionBase), g_stcShellData.dwIATSectionSize,
		PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//3.开始修复IAT
	while (pPEImport->Name)//结构体数组以全零结尾
	{
		//获取模块名
		DWORD dwModNameRVA = pPEImport->Name;
		char* pModName = (char*)(dwImageBase + dwModNameRVA);
		BOOL Sign = ExcFun(pModName);//加密部分函数
		HMODULE hMod = g_pfnLoadLibraryA(pModName);//得到模块加载基址
		//获取IAT和INT首地址
		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(dwImageBase + pPEImport->FirstThunk);
		PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(dwImageBase + pPEImport->OriginalFirstThunk);
		//通过INT循环获取该模块下的所有函数信息
		while (pINT->u1.AddressOfData)
		{
			DWORD dwFunAddr = 0;
			//判断是输出函数名还是序号
			if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
			{
				//输出序号
				DWORD dwFunOrdinal = (pINT->u1.Ordinal) & 0x7FFFFFFF;//得到序号
				dwFunAddr = g_pfnGetProcAddress(hMod, (char*)dwFunOrdinal);//得到序号导出的函数的地址			
			}
			else
			{
				//输出函数名
				DWORD dwFunNameRVA = pINT->u1.AddressOfData;
				PIMAGE_IMPORT_BY_NAME pstcFunName = (PIMAGE_IMPORT_BY_NAME)(dwImageBase + dwFunNameRVA);
				dwFunAddr = g_pfnGetProcAddress(hMod, pstcFunName->Name);
			}
			//申请出一片空间
			BYTE OpCode[5] = { 0XE9 };
			LPVOID pNewFunAddr = g_pfnVirtualAlloc(NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			//将OPCODE花指令混淆，写到分配的内存空间中
			g_pfnMemcopy(pNewFunAddr, ShellOpCode, 75);
			//计算出偏移
			*(DWORD *)(OpCode + 1) = dwFunAddr - (DWORD)((LPBYTE)pNewFunAddr + 75) - 5;
			g_pfnMemcopy((LPBYTE)pNewFunAddr + 75, OpCode, 5);
			if (!Sign)
			{
				*(DWORD*)pIAT = (DWORD)pNewFunAddr;
			}
			else
			{
				*(DWORD*)pIAT = dwFunAddr;
				g_pfnVirtualFree(pNewFunAddr, 100, MEM_RELEASE | MEM_DECOMMIT);
			}
			++pIAT;
			++pINT;
		}
		//遍历下一个模块
		pPEImport++;
	}
}
//重定位
void RecReloc()
{
	//1.获取重定位表结构体指针
	PIMAGE_BASE_RELOCATION	pPEReloc=
		(PIMAGE_BASE_RELOCATION)(dwImageBase + g_stcShellData.stcPERelocDir.VirtualAddress);
	
	//2.开始修复重定位
	while (pPEReloc->VirtualAddress)
	{
		//2.1修改内存属性为可写
		DWORD dwOldProtect = 0;
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);

		//2.2修复重定位
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pPEReloc + 1);
		DWORD dwNumber = (pPEReloc->SizeOfBlock - 8) / 2;
		for (DWORD i = 0; i < dwNumber; i++)
		{
			if (*(PWORD)(&pTypeOffset[i]) == NULL)
				break;
			//RVA
			DWORD dwRVA = pTypeOffset[i].offset + pPEReloc->VirtualAddress;
			//FAR地址
			DWORD AddrOfNeedReloc = *(PDWORD)((DWORD)dwImageBase + dwRVA);
			*(PDWORD)((DWORD)dwImageBase + dwRVA) = 
				AddrOfNeedReloc - g_stcShellData.dwPEImageBase + dwImageBase;
		}

		//2.3恢复内存属性
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, dwOldProtect, &dwOldProtect);

		//2.4修复下一个区段
		pPEReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pPEReloc + pPEReloc->SizeOfBlock);
	}
}
//异或解密
void DeXorCode()
{
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew + dwImageBase);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	for (int n = 0; n < pNt->FileHeader.NumberOfSections - 1; ++n)//去掉新增加的区段
	{
		if (g_stcShellData.dwRecur == n)//过滤掉资源表
			continue;
		PBYTE pBase = (PBYTE)((DWORD)dwImageBase + pSec[n].VirtualAddress);
		DWORD dwOldProtect = 0;
		g_pfnVirtualProtect(pBase, pSec[n].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		for (DWORD nCount = 0; nCount < pSec[n].Misc.VirtualSize; ++nCount)
		{
			pBase[nCount] ^= nCount;
		}
		g_pfnVirtualProtect(pBase, pSec[n].Misc.VirtualSize, dwOldProtect, &dwOldProtect);
	}
}
//初始化函数
void InitFun()
{
	//从Kenel32中获取函数
	HMODULE hKernel32		= GetKernel32Addr();
	g_pfnGetProcAddress		= (fnGetProcAddress)MyGetProcAddress();
	g_pfnLoadLibraryA		= (fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");
	g_pfnGetModuleHandleA	= (fnGetModuleHandleA)g_pfnGetProcAddress(hKernel32, "GetModuleHandleA");
	g_pfnVirtualProtect		= (fnVirtualProtect)g_pfnGetProcAddress(hKernel32, "VirtualProtect");
	g_pfnExitProcess		= (fnExitProcess)g_pfnGetProcAddress(hKernel32, "ExitProcess");
	g_pfnVirtualAlloc		= (fnVirtualAlloc)g_pfnGetProcAddress(hKernel32, "VirtualAlloc");
	g_pfnVirtualFree		= (fnVirtualFree)g_pfnGetProcAddress(hKernel32, "VirtualFree");
	g_pfnMemcopy			= (fnmemmove)g_pfnGetProcAddress(hKernel32, "RtlMoveMemory");
	g_pfnMemSet				= (fnmemset)g_pfnGetProcAddress(hKernel32, "RtlZeroMemory");
	//从user32中获取函数
	HMODULE hUser32			= g_pfnLoadLibraryA("user32.dll");
	g_pfnMessageBoxA		= (fnMessageBox)g_pfnGetProcAddress(hUser32, "MessageBoxA");
	g_pfnDefWindowProcW		= (fnDefWindowProcW)g_pfnGetProcAddress(hUser32, "DefWindowProcW");
	g_pfnRegisterClassExA   = (fnRegisterClassExA)g_pfnGetProcAddress(hUser32, "RegisterClassExA");
	g_pfnCreateWindowExA	= (fnCreateWindowExA)g_pfnGetProcAddress(hUser32, "CreateWindowExA");
	g_pfnShowWindow			= (fnShowWindow)g_pfnGetProcAddress(hUser32, "ShowWindow");
	g_pfnfnUpdateWindow		= (fnUpdateWindow)g_pfnGetProcAddress(hUser32, "UpdateWindow");
	g_pfnGetMessageW		= (fnGetMessageW)g_pfnGetProcAddress(hUser32, "GetMessageW");
	g_PfnTranslateMessage	= (fnTranslateMessage)g_pfnGetProcAddress(hUser32, "TranslateMessage");
	g_fnDispatchMessageA	= (fnDispatchMessageA)g_pfnGetProcAddress(hUser32, "DispatchMessageA");
	g_pfnfnCreateDialogParamA = (fnCreateDialogParamA)g_pfnGetProcAddress(hUser32, "CreateDialogParamA");
	g_pfnfnCreateWindowExW	= (fnCreateWindowExW)g_pfnGetProcAddress(hUser32, "CreateWindowExW");
	g_pfnfnDialogBoxParamA	= (fnDialogBoxParamA)g_pfnGetProcAddress(hUser32, "DialogBoxParamA");
	g_pfnfnDialogBoxParamW	= (fnDialogBoxParamW)g_pfnGetProcAddress(hUser32, "DialogBoxParamW");
	g_pfnfnRegisterClassW	= (fnRegisterClassW)g_pfnGetProcAddress(hUser32, "RegisterClassW");
	g_pfnfnGetDlgItem		= (fnGetDlgItem)g_pfnGetProcAddress(hUser32, "GetDlgItem");
	g_pfnGetWindowTextA		= (fnGetWindowTextA)g_pfnGetProcAddress(hUser32, "GetWindowTextA");
	g_pfnfnPostQuitMessage  = (fnPostQuitMessage)g_pfnGetProcAddress(hUser32, "PostQuitMessage");
	//加载Advapi32.dll
	HMODULE Advapi32 = g_pfnLoadLibraryA("Advapi32.dll");
	g_pfnfnRegCreateKeyA	= (fnRegCreateKeyA)g_pfnGetProcAddress(Advapi32, "RegCreateKeyA");
	g_pfnfnRegSetValueExA	= (fnRegSetValueExA)g_pfnGetProcAddress(Advapi32, "RegSetValueExA");
	g_pfnfnRegOpenKeyExA	= (fnRegOpenKeyExA)g_pfnGetProcAddress(Advapi32, "RegOpenKeyExA");
	g_pfnfnRegQueryValueExA  = (fnRegQueryValueExA)g_pfnGetProcAddress(Advapi32, "RegQueryValueExA");
	g_pfnfnRegCloseKey		= (fnRegCloseKey)g_pfnGetProcAddress(Advapi32, "RegCloseKey");
	//初始化镜像基址
	dwImageBase =			(DWORD)g_pfnGetModuleHandleA(NULL);
}
//解压缩
BOOL DePack()
{
	//1、取必要信息
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew + dwImageBase);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	for (int n = 0; n < pNt->FileHeader.NumberOfSections - 2; ++n)//减一是去掉新加的区段
	{
		//if (g_stcShellData.dwRecur == n)
		//	continue;
		DWORD SecAddr = pSec[n].VirtualAddress + (DWORD)dwImageBase;
		//接下来进行解压缩操作，用来进行测试
		SIZE_T DePackSize = aPsafe_get_orig_size((LPVOID)SecAddr);//压缩的数据指针,返回解压缩的数据长度
		const LPVOID pDePack = g_pfnVirtualAlloc(NULL, DePackSize, MEM_COMMIT, PAGE_READWRITE);
		//LPVOID Allock = pDePack;
		if (!pDePack)
			return FALSE;//申请一块内存空间用来存放解压后的数据
		//对数据进行解压
		SIZE_T ReDePack = aPsafe_depack((LPBYTE)SecAddr, pSec[n].Misc.VirtualSize, pDePack, DePackSize);
		if (ReDePack != DePackSize)
			return FALSE;
		DWORD dwOldPro = 0;
		//修改内存属性
		g_pfnVirtualProtect(&pSec[n], 40, PAGE_EXECUTE_READWRITE, &dwOldPro);
		DWORD AlSize = DePackSize;
		if (DWORD Ali = (AlSize % pNt->OptionalHeader.FileAlignment))
			AlSize += (pNt->OptionalHeader.FileAlignment - Ali);//得到对齐之后的大小
		pSec[n].SizeOfRawData = AlSize;//将大小进行赋值
		pSec[n].Misc.VirtualSize = ReDePack;//得到对齐之前的大小
		g_pfnVirtualProtect(&pSec[n], 40, dwOldPro, &dwOldPro);//将区段属性修改回去
		//对内存属性进行修改
		DWORD dwOldProtect = 0;
		g_pfnVirtualProtect((LPVOID)SecAddr, DePackSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		//接下来进行拷贝
		g_pfnMemSet((LPVOID)SecAddr, 0, AlSize);//先进行清零,字符串以0结尾
		g_pfnMemcopy((LPVOID)SecAddr, pDePack, ReDePack);//将压缩的内容拷贝过来
		g_pfnVirtualFree(pDePack, ReDePack, MEM_RELEASE);

		//将内存属性修改回去
		//g_pfnVirtualProtect((LPVOID)SecAddr, ReDePack, dwOldProtect, &dwOldProtect);
	}
	return TRUE;
}
//获取模块的加载基址
HMODULE GetKernel32Addr()
{
	HMODULE dwKernel32Addr = 0;
	__asm
	{
		push eax
			mov eax, dword ptr fs : [0x30]   // eax = PEB的地址
			mov eax, [eax + 0x0C]            // eax = 指向PEB_LDR_DATA结构的指针
			mov eax, [eax + 0x1C]            // eax = 模块初始化链表的头指针InInitializationOrderModuleList
			mov eax, [eax]                   // eax = 列表中的第二个条目
			mov eax, [eax]                   // eax = 列表中的第三个条目
			mov eax, [eax + 0x08]            // eax = 获取到的Kernel32.dll基址(Win7下第三个条目是Kernel32.dll)
			mov dwKernel32Addr, eax
			pop eax
	}
	return dwKernel32Addr;
}
//获取函数名
DWORD MyGetProcAddress()
{
	HMODULE hModule = GetKernel32Addr();

	//1.获取DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(PBYTE)hModule;
	//2.获取NT头
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
	//3.获取导出表的结构体指针
	PIMAGE_DATA_DIRECTORY pExportDir =
		&(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

	PIMAGE_EXPORT_DIRECTORY pExport = 
		(PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + pExportDir->VirtualAddress);

	//EAT
	PDWORD pEAT = (PDWORD)((DWORD)hModule + pExport->AddressOfFunctions);
	//ENT
	PDWORD pENT = (PDWORD)((DWORD)hModule + pExport->AddressOfNames);
	//EIT
	PWORD pEIT = (PWORD)((DWORD)hModule + pExport->AddressOfNameOrdinals);

	//4.遍历导出表，获取GetProcAddress()函数地址
	DWORD dwNumofFun = pExport->NumberOfFunctions;
	DWORD dwNumofName = pExport->NumberOfNames;
	for (DWORD i = 0; i < dwNumofFun; i++)
	{
		//如果为无效函数，跳过
		if (pEAT[i] == NULL)
			continue;
		//判断是以函数名导出还是以序号导出
		DWORD j = 0;
		for (; j < dwNumofName; j++)
		{
			if (i == pEIT[j])
			{
				break;
			}
		}
		if (j != dwNumofName)
		{
			//如果是函数名方式导出的
			//函数名
			char* ExpFunName = (CHAR*)((PBYTE)hModule + pENT[j]);
			//进行对比,如果正确返回地址
			if (!strcmp(ExpFunName, "GetProcAddress"))
			{
				return pEAT[i] + pNtHeader->OptionalHeader.ImageBase;
			}
		}
		else
		{
			//序号
		}
	}
	return 0;
}
//创建窗口
int CreatWin()
{	
	//设计一个窗口类
	WNDCLASSW wce = { 0 };
	wce.lpfnWndProc = WindowProc;
	wce.hInstance = (HINSTANCE)0x400000;
	wce.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wce.lpszClassName = L"ZXN";
	//注册窗口类
	g_pfnfnRegisterClassW(&wce);
	HWND hWnd = g_pfnfnCreateWindowExW(NULL, L"ZXN", L"ZXN", WS_OVERLAPPEDWINDOW, 600, 200, 250, 320, 0, 0, (HINSTANCE)dwImageBase, 0);
	//显示刷新窗口
	g_pfnShowWindow(hWnd, SW_SHOW);
	g_pfnfnUpdateWindow(hWnd);
	MSG msg = {};
	while (g_pfnGetMessageW(&msg, NULL, 0, 0))
	{
		g_PfnTranslateMessage(&msg);
		g_fnDispatchMessageA(&msg);
	}
	return 0;
}
//检查校验码
BOOL CheckValue()
{
	//1、打开注册表
	HKEY hMyKey = 0;
	if (g_pfnfnRegOpenKeyExA(HKEY_CURRENT_USER, "Software\\ZXN\\", 0, KEY_QUERY_VALUE, &hMyKey))
		return FALSE;
	//2、获取键值
	DWORD UserArry = 0;
	unsigned long Type = REG_DWORD;
	DWORD dwLen = 4;
	if (g_pfnfnRegQueryValueExA(hMyKey, "UserInput", 0, &Type, (LPBYTE)&UserArry, &dwLen))
		return FALSE;
	//3、关闭键值
	g_pfnfnRegCloseKey(hMyKey);
	//4、进行比较
	if (UserArry == 0X100)
		return TRUE;
	return FALSE;
}
//数字-->字符串
unsigned char * CalcStr(DWORD num)
{
	DWORD nCount = 0;
	unsigned char * pArry = (unsigned char *)g_pfnVirtualAlloc(NULL, 0X100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	g_pfnMemSet(pArry, 0, 0X1000);
	while (num)
	{
		DWORD Val = num % 10;
		pArry[nCount] = Val + 30;
		num /= 10;
		++nCount;
	}
	return pArry;
}
//排除掉一些DLL
BOOL ExcFun(char * pArr)
{
	if (strcmp(pArr, "USER32.dll") && strcmp(pArr, "KERNEL32.dll"))
		return TRUE;
	else
		return FALSE;
}
