#include "stdafx.h"
#include "PACK.h"
#include <psapi.h>
#include "../Shell/Shell.h"
#pragma comment(lib,"../Debug/Shell.lib")

CPACK::CPACK()
{
}


CPACK::~CPACK()
{
}

BOOL CPACK::Pack(CString strFilePath)
{
	//1.读取PE文件信息并保存
	CPE objPE;
	if (objPE.InitPE(strFilePath) == FALSE)
		return FALSE;
	//2.加密代码段操作
	DWORD dwXorSize = 0;
	dwXorSize = objPE.XorCode();
	objPE.PackCode();

	//3.将必要的信息保存到Shell
	HMODULE hShell = LoadLibrary(L"Shell.dll");
	if (hShell == NULL)
	{
		MessageBox(NULL, _T("加载Shell.dll模块失败，请确保程序的完整性！"), _T("提示"), MB_OK);
		//释放资源
		delete[] objPE.m_pFileBuf;
		return FALSE;
	}
	PSHELL_DATA pstcShellData = (PSHELL_DATA)GetProcAddress(hShell, "g_stcShellData");//获得导出结构体的指针
	pstcShellData->dwRecur = objPE.m_dwRescore;
	pstcShellData->dwSizeofBase = objPE.m_dwFileSize;
	pstcShellData->dwPEOEP = objPE.m_dwPEOEP;
	pstcShellData->dwPEImageBase = objPE.m_dwImageBase;
	pstcShellData->stcPERelocDir = objPE.m_PERelocDir;
	pstcShellData->stcPEImportDir = objPE.m_PEImportDir;
	pstcShellData->dwIATSectionBase = objPE.m_IATSectionBase;
	pstcShellData->dwIATSectionSize = objPE.m_IATSectionSize;

	//4.将Shell附加到PE文件
	//4.1.读取Shell代码
	MODULEINFO modinfo = { 0 };
	GetModuleInformation(GetCurrentProcess(), hShell, &modinfo, sizeof(MODULEINFO));
	PBYTE  pShellBuf = new BYTE[modinfo.SizeOfImage];
	memcpy_s(pShellBuf, modinfo.SizeOfImage, hShell, modinfo.SizeOfImage);
	//4.2.设置Shell重定位信息
	objPE.SetShellReloc(pShellBuf, (DWORD)hShell);	
	//4.3.修改被加壳程序的OEP，指向Shell
	DWORD dwShellOEP = pstcShellData->dwStartFun - (DWORD)hShell;
	objPE.SetNewOEP(dwShellOEP);

	//4.4.合并PE文件和Shell的代码到新的缓冲区
	LPBYTE pFinalBuf = NULL;
	DWORD dwFinalBufSize = 0;
	objPE.MergeBuf(objPE.m_pFileBuf, objPE.m_dwImageSize,
		pShellBuf, modinfo.SizeOfImage, 
		pFinalBuf, dwFinalBufSize);


	//5.保存文件（处理完成的缓冲区）
	SaveFinalFile(pFinalBuf, dwFinalBufSize, strFilePath);
	
	//6.释放资源
	delete[] objPE.m_pFileBuf;
	delete[] pShellBuf;
	delete[] pFinalBuf;
	objPE.InitValue();

	return TRUE;
}

BOOL CPACK::SaveFinalFile(LPBYTE pFinalBuf, DWORD pFinalBufSize, CString strFilePath)
{
	//获取合并之后相关的PE文件信息
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFinalBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFinalBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);//得到首区段头的信息
	PIMAGE_SECTION_HEADER pSecLast = pSectionHeader + pNtHeader->FileHeader.NumberOfSections - 1;//获得最后一个区段的信息
	//将内存偏移转换成文件偏移
	//所需要的内存空间
	DWORD NeedSize = pSecLast->PointerToRawData + pSecLast->SizeOfRawData;
	//申请空间
	LPBYTE SaveFile = new BYTE[NeedSize];
	if (!SaveFile)
		return FALSE;
	memset(SaveFile, 0, NeedSize);//对所申请的空间进行初始化
	//先将PE头进行赋值
	memcpy_s(SaveFile, pNtHeader->OptionalHeader.SizeOfHeaders, pFinalBuf, pNtHeader->OptionalHeader.SizeOfHeaders);
	//根据各个区段的文件偏移,以及文件大小将以内存对齐的格式修改为文件对齐的格式
	DWORD AliPost = pSectionHeader[0].PointerToRawData;
	for (DWORD n = 0; n < pNtHeader->FileHeader.NumberOfSections; ++n)
	{
		memcpy_s(SaveFile + AliPost, pSectionHeader[n].SizeOfRawData,
			pFinalBuf + pSectionHeader[n].VirtualAddress, pSectionHeader[n].SizeOfRawData);
		AliPost += pSectionHeader[n].SizeOfRawData;
	}
	//得到NT头
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)SaveFile)->e_lfanew + (DWORD)SaveFile);
	//清除不需要的目录表信息
	//只留输出表，重定位表，资源表
	DWORD dwCount = 15;
	for (DWORD i = 0; i < dwCount; i++)
	{
		if (i != IMAGE_DIRECTORY_ENTRY_EXPORT && 
			i != IMAGE_DIRECTORY_ENTRY_RESOURCE &&
			i != IMAGE_DIRECTORY_ENTRY_BASERELOC )
		{
			pNt->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
			pNt->OptionalHeader.DataDirectory[i].Size = 0;
		}
	}
	//获取保存路径
	TCHAR strOutputPath[MAX_PATH] = { 0 };
	LPWSTR strSuffix = PathFindExtension(strFilePath);
	wcsncpy_s(strOutputPath, MAX_PATH, strFilePath, wcslen(strFilePath));
	PathRemoveExtension(strOutputPath);
	wcscat_s(strOutputPath, MAX_PATH, L"_ZXN");
	wcscat_s(strOutputPath, MAX_PATH, strSuffix);

	//保存文件
	HANDLE hNewFile = CreateFile(strOutputPath,GENERIC_READ | GENERIC_WRITE,0,NULL,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNewFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, _T("保存文件失败！"), _T("提示"), MB_OK);
		return FALSE;
	}
	DWORD WriteSize = 0;
	BOOL bRes = WriteFile(hNewFile, SaveFile, NeedSize, &WriteSize, NULL);
	if (bRes)
	{
		CloseHandle(hNewFile);
		return TRUE;
	}
	else
	{
		CloseHandle(hNewFile);
		MessageBox(NULL, _T("保存文件失败！"), _T("提示"), MB_OK);
		return FALSE;
	}
}
