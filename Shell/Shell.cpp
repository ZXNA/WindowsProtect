// Shell.cpp : ���� DLL Ӧ�ó���ĵ���������
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
	WORD offset : 12;		//ƫ��ֵ
	WORD Type : 4;			//�ض�λ����(��ʽ)
}TYPEOFFSET, *PTYPEOFFSET;


//�����ͱ���������
DWORD MyGetProcAddress();		//�Զ���GetProcAddress
HMODULE	GetKernel32Addr();		//��ȡKernel32���ػ�ַ
void Start();					//��������(Shell���ֵ���ں���)
void InitFun();					//��ʼ������ָ��ͱ���
BOOL DePack();					//��ѹ������
void DeXorCode();				//���ܲ���
void RecReloc();				//�޸��ض�λ����
void RecIAT();					//�޸�IAT����
int CreatWin();					//����һ������
BOOL CheckValue();				//�����֤���Ƿ���ȷ
unsigned char * CalcStr(DWORD num);		//�����һ���ַ���
BOOL ExcFun(char *pArr);
SHELL_DATA g_stcShellData = { (DWORD)Start };
								//Shell�õ���ȫ�ֱ����ṹ��
DWORD dwImageBase	= 0;		//��������ľ����ַ
DWORD dwPEOEP		= 0;		//PE�ļ���OEP

char ShellOpCode[] = { "\x60\xE8\x27\x00\x00\x00\x36\x8D\x64\x24\x04\x36\x89\x45\xB8\xE8\x00\x00\x00\x00\x75\x0D\xEB\x15\x36\x8D\x64\x24\x04\xEB\x04\x36\x89\x45\xA8\xEB\xF8\x3E\x8B\x10\xE8\x17\x00\x00\x00\x36\x8D\x64\x24\x04\xE8\x03\x00\x00\x00\xE8\xEB\x04\x5D\x45\x55\xC3\xE8\x01\x00\x00\x00\xE9\x58\x83\xC0\x10\x8B\xD8\x61" };

//Shell�����õ��ĺ�������
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
//���ڻص�
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CREATE:
	{
		//������ť
		g_pfnfnCreateWindowExW(NULL, L"button", L"ȷ��", WS_CHILD | WS_VISIBLE, 60, 120, 80, 30, hWnd, (HMENU)10001, (HINSTANCE)dwImageBase, NULL);
		//�����ı���
		g_pfnfnCreateWindowExW(NULL, L"edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER, 20, 60, 200, 30, hWnd, (HMENU)10002, (HINSTANCE)dwImageBase, NULL);
	}
	break;
	case WM_COMMAND:
	{
		WORD wHign = HIWORD(wParam);//��λ������
		WORD wLow = LOWORD(wParam);//��λ����ؼ�ID
		HWND hEdit = g_pfnfnGetDlgItem(hWnd, 10002);//����ı���ľ��
		DWORD n = 0;
		DWORD NumInt = 0;//��������ֵĺ�
		DWORD CharSumS = 0;//�����Сд��ĸ�ĺ�
		DWORD CharSumB = 0;//�������д���ֵĺ�
		char buff[100] = { 0 };
		switch (wLow)
		{
		case 10001://�����ǰ�ť
			g_pfnGetWindowTextA(hEdit, buff, 100);//��ȡ�ı����е�����
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
			NumInt += CharSumS + CharSumB;//��ȡ�ַ����ֵ�ASCII�ܺ�
			//2�����������䱣�浽ע�����
			HKEY hMyKey = 0;//���
			if (g_pfnfnRegCreateKeyA(HKEY_CURRENT_USER, "Software\\ZXN", &hMyKey))
				g_pfnMessageBoxA(NULL, "����", "��ʾ", MB_OK);//�򿪻��ߴ���һ��ע���
			if (g_pfnfnRegSetValueExA(hMyKey, "UserInput", 0, REG_DWORD, (const BYTE *)&NumInt, 4))
				g_pfnMessageBoxA(NULL, "����", "��ʾ", MB_OK);//����ֵд��ע���
			//3���ر�ע����ֵ
			g_pfnfnRegCloseKey(hMyKey);
			//���򣬽�����������
			g_pfnMessageBoxA(NULL, "��֤���ѽ��գ���������", "��ʾ", MB_OK);
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
	//����������֤
	if (!CheckValue())
		CreatWin();//�����⵽�д����ٴ�������֤��
	g_pfnMessageBoxA(NULL, "��֤ͨ��", "��ʾ", MB_OK);
	DePack();
	DeXorCode();
	if (g_stcShellData.stcPERelocDir.VirtualAddress)//�ж���û���ض�λ
		RecReloc();
	RecIAT();
	//��ȡOEP��Ϣ
	dwPEOEP = g_stcShellData.dwPEOEP + dwImageBase;
	__asm popad
	__asm jmp dwPEOEP
	
	g_pfnExitProcess(0);
}

//�޸�iat
void RecIAT()
{
	//1.��ȡ�����ṹ��ָ��
	PIMAGE_IMPORT_DESCRIPTOR pPEImport = 
		(PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase + g_stcShellData.stcPEImportDir.VirtualAddress);
	
	//2.�޸��ڴ�����Ϊ��д
	DWORD dwProSize = g_stcShellData.dwIATSectionSize;
	DWORD dwOldProtect = 0;
	g_pfnVirtualProtect((LPBYTE)(dwImageBase + g_stcShellData.dwIATSectionBase), g_stcShellData.dwIATSectionSize,
		PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//3.��ʼ�޸�IAT
	while (pPEImport->Name)//�ṹ��������ȫ���β
	{
		//��ȡģ����
		DWORD dwModNameRVA = pPEImport->Name;
		char* pModName = (char*)(dwImageBase + dwModNameRVA);
		BOOL Sign = ExcFun(pModName);//���ܲ��ֺ���
		HMODULE hMod = g_pfnLoadLibraryA(pModName);//�õ�ģ����ػ�ַ
		//��ȡIAT��INT�׵�ַ
		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(dwImageBase + pPEImport->FirstThunk);
		PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(dwImageBase + pPEImport->OriginalFirstThunk);
		//ͨ��INTѭ����ȡ��ģ���µ����к�����Ϣ
		while (pINT->u1.AddressOfData)
		{
			DWORD dwFunAddr = 0;
			//�ж�������������������
			if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
			{
				//������
				DWORD dwFunOrdinal = (pINT->u1.Ordinal) & 0x7FFFFFFF;//�õ����
				dwFunAddr = g_pfnGetProcAddress(hMod, (char*)dwFunOrdinal);//�õ���ŵ����ĺ����ĵ�ַ			
			}
			else
			{
				//���������
				DWORD dwFunNameRVA = pINT->u1.AddressOfData;
				PIMAGE_IMPORT_BY_NAME pstcFunName = (PIMAGE_IMPORT_BY_NAME)(dwImageBase + dwFunNameRVA);
				dwFunAddr = g_pfnGetProcAddress(hMod, pstcFunName->Name);
			}
			//�����һƬ�ռ�
			BYTE OpCode[5] = { 0XE9 };
			LPVOID pNewFunAddr = g_pfnVirtualAlloc(NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			//��OPCODE��ָ�������д��������ڴ�ռ���
			g_pfnMemcopy(pNewFunAddr, ShellOpCode, 75);
			//�����ƫ��
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
		//������һ��ģ��
		pPEImport++;
	}
}
//�ض�λ
void RecReloc()
{
	//1.��ȡ�ض�λ��ṹ��ָ��
	PIMAGE_BASE_RELOCATION	pPEReloc=
		(PIMAGE_BASE_RELOCATION)(dwImageBase + g_stcShellData.stcPERelocDir.VirtualAddress);
	
	//2.��ʼ�޸��ض�λ
	while (pPEReloc->VirtualAddress)
	{
		//2.1�޸��ڴ�����Ϊ��д
		DWORD dwOldProtect = 0;
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);

		//2.2�޸��ض�λ
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pPEReloc + 1);
		DWORD dwNumber = (pPEReloc->SizeOfBlock - 8) / 2;
		for (DWORD i = 0; i < dwNumber; i++)
		{
			if (*(PWORD)(&pTypeOffset[i]) == NULL)
				break;
			//RVA
			DWORD dwRVA = pTypeOffset[i].offset + pPEReloc->VirtualAddress;
			//FAR��ַ
			DWORD AddrOfNeedReloc = *(PDWORD)((DWORD)dwImageBase + dwRVA);
			*(PDWORD)((DWORD)dwImageBase + dwRVA) = 
				AddrOfNeedReloc - g_stcShellData.dwPEImageBase + dwImageBase;
		}

		//2.3�ָ��ڴ�����
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, dwOldProtect, &dwOldProtect);

		//2.4�޸���һ������
		pPEReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pPEReloc + pPEReloc->SizeOfBlock);
	}
}
//������
void DeXorCode()
{
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew + dwImageBase);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	for (int n = 0; n < pNt->FileHeader.NumberOfSections - 1; ++n)//ȥ�������ӵ�����
	{
		if (g_stcShellData.dwRecur == n)//���˵���Դ��
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
//��ʼ������
void InitFun()
{
	//��Kenel32�л�ȡ����
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
	//��user32�л�ȡ����
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
	//����Advapi32.dll
	HMODULE Advapi32 = g_pfnLoadLibraryA("Advapi32.dll");
	g_pfnfnRegCreateKeyA	= (fnRegCreateKeyA)g_pfnGetProcAddress(Advapi32, "RegCreateKeyA");
	g_pfnfnRegSetValueExA	= (fnRegSetValueExA)g_pfnGetProcAddress(Advapi32, "RegSetValueExA");
	g_pfnfnRegOpenKeyExA	= (fnRegOpenKeyExA)g_pfnGetProcAddress(Advapi32, "RegOpenKeyExA");
	g_pfnfnRegQueryValueExA  = (fnRegQueryValueExA)g_pfnGetProcAddress(Advapi32, "RegQueryValueExA");
	g_pfnfnRegCloseKey		= (fnRegCloseKey)g_pfnGetProcAddress(Advapi32, "RegCloseKey");
	//��ʼ�������ַ
	dwImageBase =			(DWORD)g_pfnGetModuleHandleA(NULL);
}
//��ѹ��
BOOL DePack()
{
	//1��ȡ��Ҫ��Ϣ
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew + dwImageBase);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	for (int n = 0; n < pNt->FileHeader.NumberOfSections - 2; ++n)//��һ��ȥ���¼ӵ�����
	{
		//if (g_stcShellData.dwRecur == n)
		//	continue;
		DWORD SecAddr = pSec[n].VirtualAddress + (DWORD)dwImageBase;
		//���������н�ѹ���������������в���
		SIZE_T DePackSize = aPsafe_get_orig_size((LPVOID)SecAddr);//ѹ��������ָ��,���ؽ�ѹ�������ݳ���
		const LPVOID pDePack = g_pfnVirtualAlloc(NULL, DePackSize, MEM_COMMIT, PAGE_READWRITE);
		//LPVOID Allock = pDePack;
		if (!pDePack)
			return FALSE;//����һ���ڴ�ռ�������Ž�ѹ�������
		//�����ݽ��н�ѹ
		SIZE_T ReDePack = aPsafe_depack((LPBYTE)SecAddr, pSec[n].Misc.VirtualSize, pDePack, DePackSize);
		if (ReDePack != DePackSize)
			return FALSE;
		DWORD dwOldPro = 0;
		//�޸��ڴ�����
		g_pfnVirtualProtect(&pSec[n], 40, PAGE_EXECUTE_READWRITE, &dwOldPro);
		DWORD AlSize = DePackSize;
		if (DWORD Ali = (AlSize % pNt->OptionalHeader.FileAlignment))
			AlSize += (pNt->OptionalHeader.FileAlignment - Ali);//�õ�����֮��Ĵ�С
		pSec[n].SizeOfRawData = AlSize;//����С���и�ֵ
		pSec[n].Misc.VirtualSize = ReDePack;//�õ�����֮ǰ�Ĵ�С
		g_pfnVirtualProtect(&pSec[n], 40, dwOldPro, &dwOldPro);//�����������޸Ļ�ȥ
		//���ڴ����Խ����޸�
		DWORD dwOldProtect = 0;
		g_pfnVirtualProtect((LPVOID)SecAddr, DePackSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		//���������п���
		g_pfnMemSet((LPVOID)SecAddr, 0, AlSize);//�Ƚ�������,�ַ�����0��β
		g_pfnMemcopy((LPVOID)SecAddr, pDePack, ReDePack);//��ѹ�������ݿ�������
		g_pfnVirtualFree(pDePack, ReDePack, MEM_RELEASE);

		//���ڴ������޸Ļ�ȥ
		//g_pfnVirtualProtect((LPVOID)SecAddr, ReDePack, dwOldProtect, &dwOldProtect);
	}
	return TRUE;
}
//��ȡģ��ļ��ػ�ַ
HMODULE GetKernel32Addr()
{
	HMODULE dwKernel32Addr = 0;
	__asm
	{
		push eax
			mov eax, dword ptr fs : [0x30]   // eax = PEB�ĵ�ַ
			mov eax, [eax + 0x0C]            // eax = ָ��PEB_LDR_DATA�ṹ��ָ��
			mov eax, [eax + 0x1C]            // eax = ģ���ʼ�������ͷָ��InInitializationOrderModuleList
			mov eax, [eax]                   // eax = �б��еĵڶ�����Ŀ
			mov eax, [eax]                   // eax = �б��еĵ�������Ŀ
			mov eax, [eax + 0x08]            // eax = ��ȡ����Kernel32.dll��ַ(Win7�µ�������Ŀ��Kernel32.dll)
			mov dwKernel32Addr, eax
			pop eax
	}
	return dwKernel32Addr;
}
//��ȡ������
DWORD MyGetProcAddress()
{
	HMODULE hModule = GetKernel32Addr();

	//1.��ȡDOSͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(PBYTE)hModule;
	//2.��ȡNTͷ
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
	//3.��ȡ������Ľṹ��ָ��
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

	//4.������������ȡGetProcAddress()������ַ
	DWORD dwNumofFun = pExport->NumberOfFunctions;
	DWORD dwNumofName = pExport->NumberOfNames;
	for (DWORD i = 0; i < dwNumofFun; i++)
	{
		//���Ϊ��Ч����������
		if (pEAT[i] == NULL)
			continue;
		//�ж����Ժ�����������������ŵ���
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
			//����Ǻ�������ʽ������
			//������
			char* ExpFunName = (CHAR*)((PBYTE)hModule + pENT[j]);
			//���жԱ�,�����ȷ���ص�ַ
			if (!strcmp(ExpFunName, "GetProcAddress"))
			{
				return pEAT[i] + pNtHeader->OptionalHeader.ImageBase;
			}
		}
		else
		{
			//���
		}
	}
	return 0;
}
//��������
int CreatWin()
{	
	//���һ��������
	WNDCLASSW wce = { 0 };
	wce.lpfnWndProc = WindowProc;
	wce.hInstance = (HINSTANCE)0x400000;
	wce.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wce.lpszClassName = L"ZXN";
	//ע�ᴰ����
	g_pfnfnRegisterClassW(&wce);
	HWND hWnd = g_pfnfnCreateWindowExW(NULL, L"ZXN", L"ZXN", WS_OVERLAPPEDWINDOW, 600, 200, 250, 320, 0, 0, (HINSTANCE)dwImageBase, 0);
	//��ʾˢ�´���
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
//���У����
BOOL CheckValue()
{
	//1����ע���
	HKEY hMyKey = 0;
	if (g_pfnfnRegOpenKeyExA(HKEY_CURRENT_USER, "Software\\ZXN\\", 0, KEY_QUERY_VALUE, &hMyKey))
		return FALSE;
	//2����ȡ��ֵ
	DWORD UserArry = 0;
	unsigned long Type = REG_DWORD;
	DWORD dwLen = 4;
	if (g_pfnfnRegQueryValueExA(hMyKey, "UserInput", 0, &Type, (LPBYTE)&UserArry, &dwLen))
		return FALSE;
	//3���رռ�ֵ
	g_pfnfnRegCloseKey(hMyKey);
	//4�����бȽ�
	if (UserArry == 0X100)
		return TRUE;
	return FALSE;
}
//����-->�ַ���
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
//�ų���һЩDLL
BOOL ExcFun(char * pArr)
{
	if (strcmp(pArr, "USER32.dll") && strcmp(pArr, "KERNEL32.dll"))
		return TRUE;
	else
		return FALSE;
}
