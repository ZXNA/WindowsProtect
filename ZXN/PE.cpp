#include "stdafx.h"
#include "PE.h"

typedef struct _TYPEOFFSET
{
	WORD offset : 12;			//偏移值
	WORD Type : 4;			//重定位属性(方式)
}TYPEOFFSET, *PTYPEOFFSET;

CPE::CPE()
{
	InitValue();
}


CPE::~CPE()
{
}
//初始化重要的PE文件数据
void CPE::InitValue()
{
	m_hFile				= NULL;
	m_pFileBuf			= NULL;
	m_pDosHeader		= NULL;
	m_pNtHeader			= NULL;
	m_pSecHeader		= NULL;
	m_dwFileSize		= 0;
	m_dwImageSize		= 0;
	m_dwImageBase		= 0;
	m_dwPEOEP			= 0;
	m_dwShellOEP		= 0;
	m_dwSizeOfHeader	= 0;
	m_dwSectionNum		= 0;
	m_dwFileAlign		= 0;
	m_dwMemAlign		= 0;
	m_PERelocDir		= { 0 };
	m_PEImportDir		= { 0 };
	m_IATSectionBase	= 0;
	m_IATSectionSize	= 0;
}
//将文件以内存对齐的方式读取到内存中读取
BOOL CPE::InitPE(CString strFilePath)
{
	//打开文件
	if (OpenPEFile(strFilePath) == FALSE)
		return FALSE;

	//将PE以文件分布格式读取到内存
	m_dwFileSize = GetFileSize(m_hFile, NULL);
	m_pFileBuf = new BYTE[m_dwFileSize];
	DWORD ReadSize = 0;
	ReadFile(m_hFile, m_pFileBuf, m_dwFileSize, &ReadSize, NULL);//读取文件
	CloseHandle(m_hFile);
	m_hFile = NULL;
	//判断是否为PE文件
	if (IsPE() == FALSE)
		return FALSE;
	//将PE以内存分布格式读取到内存
	//修正没镜像大小没有对齐的情况
	m_dwImageSize = m_pNtHeader->OptionalHeader.SizeOfImage;//获取映像的大小
	m_dwMemAlign = m_pNtHeader->OptionalHeader.SectionAlignment;//获取内存对齐粒度
	m_dwSizeOfHeader = m_pNtHeader->OptionalHeader.SizeOfHeaders;//头部的大小
	m_dwSectionNum = m_pNtHeader->FileHeader.NumberOfSections;//区段的数量

	if (m_dwImageSize % m_dwMemAlign)
		m_dwImageSize = (m_dwImageSize / m_dwMemAlign + 1) * m_dwMemAlign;//真正在内存中的大小
	LPBYTE pFileBuf_New = new BYTE[m_dwImageSize];//分配所需要的内存
	memset(pFileBuf_New, 0, m_dwImageSize);
	//拷贝文件头
	memcpy_s(pFileBuf_New, m_dwSizeOfHeader, m_pFileBuf, m_dwSizeOfHeader);
	//拷贝区段
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	for (DWORD i = 0; i < m_dwSectionNum; i++, pSectionHeader++)
	{
		memcpy_s(pFileBuf_New + pSectionHeader->VirtualAddress,
			pSectionHeader->SizeOfRawData,
			m_pFileBuf+pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData);
	}
	delete[] m_pFileBuf;
	m_pFileBuf = pFileBuf_New;
	pFileBuf_New = NULL;

	//获取PE信息
	GetPEInfo();
	
	return TRUE;
}
//打开文件
BOOL CPE::OpenPEFile(CString strFilePath)
{
	m_hFile = CreateFile(strFilePath,
		GENERIC_READ | GENERIC_WRITE, 0, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//判断文件打开是否成功
	if (m_hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	return TRUE;
}
//判断读取到内存中的文件是不是PE文件
BOOL CPE::IsPE()
{
	//判断是否为PE文件
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pFileBuf;
	m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE && m_pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	return TRUE;
}
//获取有用的PE文件信息
void CPE::GetPEInfo()
{
	m_pDosHeader	= (PIMAGE_DOS_HEADER)m_pFileBuf;
	m_pNtHeader		= (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);
	m_dwFileAlign	= m_pNtHeader->OptionalHeader.FileAlignment;
	m_dwMemAlign	= m_pNtHeader->OptionalHeader.SectionAlignment;
	m_dwImageBase	= m_pNtHeader->OptionalHeader.ImageBase;
	m_dwPEOEP		= m_pNtHeader->OptionalHeader.AddressOfEntryPoint;
	m_dwSizeOfHeader= m_pNtHeader->OptionalHeader.SizeOfHeaders;
	m_dwSectionNum	= m_pNtHeader->FileHeader.NumberOfSections;
	m_pSecHeader	= IMAGE_FIRST_SECTION(m_pNtHeader);
	m_pNtHeader->OptionalHeader.SizeOfImage = m_dwImageSize;
	//保存重定位目录信息
	m_PERelocDir = 
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[5]);

	//保存IAT信息目录信息
	m_PEImportDir =
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[1]);

	//获取IAT所在的区段的起始位置和大小
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	for (DWORD i = 0; i < m_dwSectionNum; i++, pSectionHeader++)
	{
		if (m_PEImportDir.VirtualAddress >= pSectionHeader->VirtualAddress&&
			m_PEImportDir.VirtualAddress <= pSectionHeader[1].VirtualAddress)
		{
			//保存该区段的起始地址和大小
			m_IATSectionBase = pSectionHeader->VirtualAddress;
			m_IATSectionSize = pSectionHeader[1].VirtualAddress - pSectionHeader->VirtualAddress;
			break;
		}
	}
	//获取区段表的位置
	for (DWORD n = 0; n < m_dwSectionNum; ++n)
	{
		if (!strcmp((const char *)m_pSecHeader[n].Name, ".rsrc"))
		{
			m_dwRescore = n;
			break;
		}
	}
}
//除去资源段之外，全部加密
DWORD CPE::XorCode()
{
	for (DWORD n = 0; n < m_dwSectionNum; ++n)//通过区段数量，依次进行加密
	{
		if (n == m_dwRescore)
			continue;//过滤掉资源表
		PBYTE pBase = (PBYTE)((DWORD)m_pFileBuf + m_pSecHeader[n].VirtualAddress);
		for (DWORD nCount = 0; nCount < m_pSecHeader[n].Misc.VirtualSize; ++nCount)
		{
			pBase[nCount] ^= nCount;
		}
	}
	return 0;
}
//设置Shell文件的重定位信息
BOOL CPE::SetShellReloc(LPBYTE pShellBuf, DWORD hShell)
{

	//1.获取被加壳PE文件的重定位目录表指针信息
	PIMAGE_DATA_DIRECTORY pPERelocDir =
		&(m_pNtHeader->OptionalHeader.DataDirectory[5]);
	//2.获取Shell的重定位表指针信息
	PIMAGE_DOS_HEADER		pShellDosHeader = (PIMAGE_DOS_HEADER)pShellBuf;
	PIMAGE_NT_HEADERS		pShellNtHeader = (PIMAGE_NT_HEADERS)(pShellBuf + pShellDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY	pShellRelocDir =
		&(pShellNtHeader->OptionalHeader.DataDirectory[5]);//重定位目录表信息
	PIMAGE_BASE_RELOCATION	pShellReloc = 
		(PIMAGE_BASE_RELOCATION)((DWORD)pShellBuf + pShellRelocDir->VirtualAddress);//定位到重定位地址
	//3.还原修复重定位信息
	while (pShellReloc->VirtualAddress && pShellReloc->SizeOfBlock)//重定位表以全零元素结尾
	{
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pShellReloc + 1);//定位到偏移数组
		DWORD nCount = (pShellReloc->SizeOfBlock - 8) / 2;//计算出有多少偏移
		DWORD OldPro = 0;
		VirtualProtect((LPVOID)(pShellReloc->VirtualAddress + pShellBuf), 0X1000, PAGE_READWRITE, &OldPro);//修改内存属性

		for (DWORD n = 0; n < nCount; ++n)//开始遍历偏移数组
		{
			PDWORD WaitAlterNum = (PDWORD)(pTypeOffset->offset + pShellReloc->VirtualAddress + pShellBuf);//得到的是待修改数值的地址
			*(WaitAlterNum) = *(WaitAlterNum)-(DWORD)pShellNtHeader->OptionalHeader.ImageBase + m_pNtHeader->OptionalHeader.ImageBase + m_dwImageSize;//修改重定位
			++pTypeOffset;
		}
		VirtualProtect((LPVOID)(pShellReloc->VirtualAddress + pShellBuf), 0X1000, OldPro, &OldPro);//修改内存属性
		pShellReloc->VirtualAddress += m_dwImageBase; //修改自身重定位表的第一个字段
		pShellReloc = (PIMAGE_BASE_RELOCATION)(pShellReloc->SizeOfBlock + (LPBYTE)pShellReloc);//得到下一个结构体	
	}

	//4.修改PE重定位目录指针，指向Shell的重定位表信息
	pPERelocDir->Size = pShellRelocDir->Size;
	pPERelocDir->VirtualAddress = pShellRelocDir->VirtualAddress + m_dwImageSize;

	return TRUE;
}
//合并区段信息
void CPE::MergeBuf(LPBYTE pFileBuf, DWORD pFileBufSize,
	LPBYTE pShellBuf, DWORD pShellBufSize, 
	LPBYTE& pFinalBuf, DWORD& pFinalBufSize)
{
	//获取最后一个区段的信息
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_SECTION_HEADER pLastSection =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];

	//1.修改区段数量
	pNtHeader->FileHeader.NumberOfSections += 1;

	//2.编辑区段表头结构体信息
	PIMAGE_SECTION_HEADER AddSectionHeader =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];
	memcpy_s(AddSectionHeader->Name, 8, ".ZXN", 7);

	//VOffset(1000对齐)
	DWORD dwTemp = 0;
	dwTemp = (pLastSection->Misc.VirtualSize / m_dwMemAlign) * m_dwMemAlign;
	if (pLastSection->Misc.VirtualSize % m_dwMemAlign)
	{
		dwTemp += 0x1000;
	}
	AddSectionHeader->VirtualAddress = pLastSection->VirtualAddress + dwTemp;

	//Vsize（实际添加的大小）
	AddSectionHeader->Misc.VirtualSize = pShellBufSize;

	//ROffset（旧文件的末尾）
	AddSectionHeader->PointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;


	//先计算出PShellBuff最后区段的大小
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)pShellBuf)->e_lfanew + (DWORD)pShellBuf);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pSecLast = pSec + (pNt->FileHeader.NumberOfSections - 1);
	DWORD TrueSize = (pSecLast->PointerToRawData + pSecLast->SizeOfRawData);
	//RSize(200对齐)
	dwTemp = (TrueSize / m_dwFileAlign) * m_dwFileAlign;
	if (TrueSize % m_dwFileAlign)
	{
		dwTemp += m_dwFileAlign;
	}
	AddSectionHeader->SizeOfRawData = dwTemp;

	//标志
	AddSectionHeader->Characteristics = 0XE0000040;

	//3.修改PE头文件大小属性，增加文件大小
	dwTemp = (pShellBufSize / m_dwMemAlign) * m_dwMemAlign;
	if (pShellBufSize % m_dwMemAlign)
	{
		dwTemp += m_dwMemAlign;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwTemp;


	//4.申请合并所需要的空间
	pFinalBuf = new BYTE[pFileBufSize + dwTemp];
	pFinalBufSize = pFileBufSize + dwTemp;
	memset(pFinalBuf, 0, pFileBufSize + dwTemp);
	memcpy_s(pFinalBuf, pFileBufSize, pFileBuf, pFileBufSize);
	memcpy_s(pFinalBuf + pFileBufSize, dwTemp, pShellBuf, dwTemp);
}
//设置新的OEP
void CPE::SetNewOEP(DWORD dwShellOEP)
{
	m_dwShellOEP = dwShellOEP + m_dwImageSize;
	m_pNtHeader->OptionalHeader.AddressOfEntryPoint = m_dwShellOEP;
}
//压缩除去资源表的区段
BOOL CPE::PackCode()
{
	//1、获得区段的数量进行循环遍历
	for (int n = 0; n < m_pNtHeader->FileHeader.NumberOfSections; ++n)//过滤掉资源表
	{
		if (n == m_dwRescore)
			continue;//过滤掉资源表
		SIZE_T sPackSize = aP_max_packed_size(m_pSecHeader[n].SizeOfRawData);
		//获取操作空间的大小
		SIZE_T sWorkMem = aP_workmem_size(m_pSecHeader[n].SizeOfRawData);
		//申请必要的空间
		LPBYTE pPackData = new BYTE[sPackSize];//压缩后数据存放的空间
		if (!pPackData)
			return FALSE;
		LPBYTE pWorkMem = new BYTE[sWorkMem];//进行压缩操作所需要的空间
		if (!pWorkMem)
			return FALSE;
		//对所申请的空间进行初始化
		memset(pPackData, 0, sPackSize);
		memset(pWorkMem, 0, sWorkMem);
		//现获取要压缩的区段的地址
		DWORD SecAddr = m_pSecHeader[n].VirtualAddress + (DWORD)m_pFileBuf;
		//进行压缩
		DWORD PackSize = aPsafe_pack((LPVOID)SecAddr, pPackData, m_pSecHeader[n].SizeOfRawData, pWorkMem, NULL, NULL);
		if (PackSize == APLIB_ERROR)//判断是否被压缩成功
			return FALSE;
		DWORD AliSize = PackSize;
		m_pSecHeader[n].Misc.VirtualSize = PackSize;//存储未对齐之前的值
		if (DWORD Ali = (AliSize % m_pNtHeader->OptionalHeader.FileAlignment))
			AliSize += (m_pNtHeader->OptionalHeader.FileAlignment - Ali);//得到对齐之后的大小
		m_pSecHeader[n].SizeOfRawData = AliSize;//将对齐之后的大小进行赋值
		//最后接下来进行拷贝
		memset((LPVOID)SecAddr, 0, AliSize);//先进行清零,字符串以0结尾
		memcpy_s((LPVOID)SecAddr, m_pSecHeader[n].SizeOfRawData, pPackData, PackSize);//将压缩的内容拷贝过来
		delete[]pPackData;//释放所申请的资源
		delete[]pWorkMem;
	}
	return 0;
}