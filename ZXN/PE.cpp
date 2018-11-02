#include "stdafx.h"
#include "PE.h"

typedef struct _TYPEOFFSET
{
	WORD offset : 12;			//ƫ��ֵ
	WORD Type : 4;			//�ض�λ����(��ʽ)
}TYPEOFFSET, *PTYPEOFFSET;

CPE::CPE()
{
	InitValue();
}


CPE::~CPE()
{
}
//��ʼ����Ҫ��PE�ļ�����
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
//���ļ����ڴ����ķ�ʽ��ȡ���ڴ��ж�ȡ
BOOL CPE::InitPE(CString strFilePath)
{
	//���ļ�
	if (OpenPEFile(strFilePath) == FALSE)
		return FALSE;

	//��PE���ļ��ֲ���ʽ��ȡ���ڴ�
	m_dwFileSize = GetFileSize(m_hFile, NULL);
	m_pFileBuf = new BYTE[m_dwFileSize];
	DWORD ReadSize = 0;
	ReadFile(m_hFile, m_pFileBuf, m_dwFileSize, &ReadSize, NULL);//��ȡ�ļ�
	CloseHandle(m_hFile);
	m_hFile = NULL;
	//�ж��Ƿ�ΪPE�ļ�
	if (IsPE() == FALSE)
		return FALSE;
	//��PE���ڴ�ֲ���ʽ��ȡ���ڴ�
	//����û�����Сû�ж�������
	m_dwImageSize = m_pNtHeader->OptionalHeader.SizeOfImage;//��ȡӳ��Ĵ�С
	m_dwMemAlign = m_pNtHeader->OptionalHeader.SectionAlignment;//��ȡ�ڴ��������
	m_dwSizeOfHeader = m_pNtHeader->OptionalHeader.SizeOfHeaders;//ͷ���Ĵ�С
	m_dwSectionNum = m_pNtHeader->FileHeader.NumberOfSections;//���ε�����

	if (m_dwImageSize % m_dwMemAlign)
		m_dwImageSize = (m_dwImageSize / m_dwMemAlign + 1) * m_dwMemAlign;//�������ڴ��еĴ�С
	LPBYTE pFileBuf_New = new BYTE[m_dwImageSize];//��������Ҫ���ڴ�
	memset(pFileBuf_New, 0, m_dwImageSize);
	//�����ļ�ͷ
	memcpy_s(pFileBuf_New, m_dwSizeOfHeader, m_pFileBuf, m_dwSizeOfHeader);
	//��������
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

	//��ȡPE��Ϣ
	GetPEInfo();
	
	return TRUE;
}
//���ļ�
BOOL CPE::OpenPEFile(CString strFilePath)
{
	m_hFile = CreateFile(strFilePath,
		GENERIC_READ | GENERIC_WRITE, 0, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//�ж��ļ����Ƿ�ɹ�
	if (m_hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	return TRUE;
}
//�ж϶�ȡ���ڴ��е��ļ��ǲ���PE�ļ�
BOOL CPE::IsPE()
{
	//�ж��Ƿ�ΪPE�ļ�
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pFileBuf;
	m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE && m_pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	return TRUE;
}
//��ȡ���õ�PE�ļ���Ϣ
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
	//�����ض�λĿ¼��Ϣ
	m_PERelocDir = 
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[5]);

	//����IAT��ϢĿ¼��Ϣ
	m_PEImportDir =
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[1]);

	//��ȡIAT���ڵ����ε���ʼλ�úʹ�С
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	for (DWORD i = 0; i < m_dwSectionNum; i++, pSectionHeader++)
	{
		if (m_PEImportDir.VirtualAddress >= pSectionHeader->VirtualAddress&&
			m_PEImportDir.VirtualAddress <= pSectionHeader[1].VirtualAddress)
		{
			//��������ε���ʼ��ַ�ʹ�С
			m_IATSectionBase = pSectionHeader->VirtualAddress;
			m_IATSectionSize = pSectionHeader[1].VirtualAddress - pSectionHeader->VirtualAddress;
			break;
		}
	}
	//��ȡ���α��λ��
	for (DWORD n = 0; n < m_dwSectionNum; ++n)
	{
		if (!strcmp((const char *)m_pSecHeader[n].Name, ".rsrc"))
		{
			m_dwRescore = n;
			break;
		}
	}
}
//��ȥ��Դ��֮�⣬ȫ������
DWORD CPE::XorCode()
{
	for (DWORD n = 0; n < m_dwSectionNum; ++n)//ͨ���������������ν��м���
	{
		if (n == m_dwRescore)
			continue;//���˵���Դ��
		PBYTE pBase = (PBYTE)((DWORD)m_pFileBuf + m_pSecHeader[n].VirtualAddress);
		for (DWORD nCount = 0; nCount < m_pSecHeader[n].Misc.VirtualSize; ++nCount)
		{
			pBase[nCount] ^= nCount;
		}
	}
	return 0;
}
//����Shell�ļ����ض�λ��Ϣ
BOOL CPE::SetShellReloc(LPBYTE pShellBuf, DWORD hShell)
{

	//1.��ȡ���ӿ�PE�ļ����ض�λĿ¼��ָ����Ϣ
	PIMAGE_DATA_DIRECTORY pPERelocDir =
		&(m_pNtHeader->OptionalHeader.DataDirectory[5]);
	//2.��ȡShell���ض�λ��ָ����Ϣ
	PIMAGE_DOS_HEADER		pShellDosHeader = (PIMAGE_DOS_HEADER)pShellBuf;
	PIMAGE_NT_HEADERS		pShellNtHeader = (PIMAGE_NT_HEADERS)(pShellBuf + pShellDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY	pShellRelocDir =
		&(pShellNtHeader->OptionalHeader.DataDirectory[5]);//�ض�λĿ¼����Ϣ
	PIMAGE_BASE_RELOCATION	pShellReloc = 
		(PIMAGE_BASE_RELOCATION)((DWORD)pShellBuf + pShellRelocDir->VirtualAddress);//��λ���ض�λ��ַ
	//3.��ԭ�޸��ض�λ��Ϣ
	while (pShellReloc->VirtualAddress && pShellReloc->SizeOfBlock)//�ض�λ����ȫ��Ԫ�ؽ�β
	{
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pShellReloc + 1);//��λ��ƫ������
		DWORD nCount = (pShellReloc->SizeOfBlock - 8) / 2;//������ж���ƫ��
		DWORD OldPro = 0;
		VirtualProtect((LPVOID)(pShellReloc->VirtualAddress + pShellBuf), 0X1000, PAGE_READWRITE, &OldPro);//�޸��ڴ�����

		for (DWORD n = 0; n < nCount; ++n)//��ʼ����ƫ������
		{
			PDWORD WaitAlterNum = (PDWORD)(pTypeOffset->offset + pShellReloc->VirtualAddress + pShellBuf);//�õ����Ǵ��޸���ֵ�ĵ�ַ
			*(WaitAlterNum) = *(WaitAlterNum)-(DWORD)pShellNtHeader->OptionalHeader.ImageBase + m_pNtHeader->OptionalHeader.ImageBase + m_dwImageSize;//�޸��ض�λ
			++pTypeOffset;
		}
		VirtualProtect((LPVOID)(pShellReloc->VirtualAddress + pShellBuf), 0X1000, OldPro, &OldPro);//�޸��ڴ�����
		pShellReloc->VirtualAddress += m_dwImageBase; //�޸������ض�λ��ĵ�һ���ֶ�
		pShellReloc = (PIMAGE_BASE_RELOCATION)(pShellReloc->SizeOfBlock + (LPBYTE)pShellReloc);//�õ���һ���ṹ��	
	}

	//4.�޸�PE�ض�λĿ¼ָ�룬ָ��Shell���ض�λ����Ϣ
	pPERelocDir->Size = pShellRelocDir->Size;
	pPERelocDir->VirtualAddress = pShellRelocDir->VirtualAddress + m_dwImageSize;

	return TRUE;
}
//�ϲ�������Ϣ
void CPE::MergeBuf(LPBYTE pFileBuf, DWORD pFileBufSize,
	LPBYTE pShellBuf, DWORD pShellBufSize, 
	LPBYTE& pFinalBuf, DWORD& pFinalBufSize)
{
	//��ȡ���һ�����ε���Ϣ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_SECTION_HEADER pLastSection =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];

	//1.�޸���������
	pNtHeader->FileHeader.NumberOfSections += 1;

	//2.�༭���α�ͷ�ṹ����Ϣ
	PIMAGE_SECTION_HEADER AddSectionHeader =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];
	memcpy_s(AddSectionHeader->Name, 8, ".ZXN", 7);

	//VOffset(1000����)
	DWORD dwTemp = 0;
	dwTemp = (pLastSection->Misc.VirtualSize / m_dwMemAlign) * m_dwMemAlign;
	if (pLastSection->Misc.VirtualSize % m_dwMemAlign)
	{
		dwTemp += 0x1000;
	}
	AddSectionHeader->VirtualAddress = pLastSection->VirtualAddress + dwTemp;

	//Vsize��ʵ����ӵĴ�С��
	AddSectionHeader->Misc.VirtualSize = pShellBufSize;

	//ROffset�����ļ���ĩβ��
	AddSectionHeader->PointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;


	//�ȼ����PShellBuff������εĴ�С
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)pShellBuf)->e_lfanew + (DWORD)pShellBuf);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pSecLast = pSec + (pNt->FileHeader.NumberOfSections - 1);
	DWORD TrueSize = (pSecLast->PointerToRawData + pSecLast->SizeOfRawData);
	//RSize(200����)
	dwTemp = (TrueSize / m_dwFileAlign) * m_dwFileAlign;
	if (TrueSize % m_dwFileAlign)
	{
		dwTemp += m_dwFileAlign;
	}
	AddSectionHeader->SizeOfRawData = dwTemp;

	//��־
	AddSectionHeader->Characteristics = 0XE0000040;

	//3.�޸�PEͷ�ļ���С���ԣ������ļ���С
	dwTemp = (pShellBufSize / m_dwMemAlign) * m_dwMemAlign;
	if (pShellBufSize % m_dwMemAlign)
	{
		dwTemp += m_dwMemAlign;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwTemp;


	//4.����ϲ�����Ҫ�Ŀռ�
	pFinalBuf = new BYTE[pFileBufSize + dwTemp];
	pFinalBufSize = pFileBufSize + dwTemp;
	memset(pFinalBuf, 0, pFileBufSize + dwTemp);
	memcpy_s(pFinalBuf, pFileBufSize, pFileBuf, pFileBufSize);
	memcpy_s(pFinalBuf + pFileBufSize, dwTemp, pShellBuf, dwTemp);
}
//�����µ�OEP
void CPE::SetNewOEP(DWORD dwShellOEP)
{
	m_dwShellOEP = dwShellOEP + m_dwImageSize;
	m_pNtHeader->OptionalHeader.AddressOfEntryPoint = m_dwShellOEP;
}
//ѹ����ȥ��Դ�������
BOOL CPE::PackCode()
{
	//1��������ε���������ѭ������
	for (int n = 0; n < m_pNtHeader->FileHeader.NumberOfSections; ++n)//���˵���Դ��
	{
		if (n == m_dwRescore)
			continue;//���˵���Դ��
		SIZE_T sPackSize = aP_max_packed_size(m_pSecHeader[n].SizeOfRawData);
		//��ȡ�����ռ�Ĵ�С
		SIZE_T sWorkMem = aP_workmem_size(m_pSecHeader[n].SizeOfRawData);
		//�����Ҫ�Ŀռ�
		LPBYTE pPackData = new BYTE[sPackSize];//ѹ�������ݴ�ŵĿռ�
		if (!pPackData)
			return FALSE;
		LPBYTE pWorkMem = new BYTE[sWorkMem];//����ѹ����������Ҫ�Ŀռ�
		if (!pWorkMem)
			return FALSE;
		//��������Ŀռ���г�ʼ��
		memset(pPackData, 0, sPackSize);
		memset(pWorkMem, 0, sWorkMem);
		//�ֻ�ȡҪѹ�������εĵ�ַ
		DWORD SecAddr = m_pSecHeader[n].VirtualAddress + (DWORD)m_pFileBuf;
		//����ѹ��
		DWORD PackSize = aPsafe_pack((LPVOID)SecAddr, pPackData, m_pSecHeader[n].SizeOfRawData, pWorkMem, NULL, NULL);
		if (PackSize == APLIB_ERROR)//�ж��Ƿ�ѹ���ɹ�
			return FALSE;
		DWORD AliSize = PackSize;
		m_pSecHeader[n].Misc.VirtualSize = PackSize;//�洢δ����֮ǰ��ֵ
		if (DWORD Ali = (AliSize % m_pNtHeader->OptionalHeader.FileAlignment))
			AliSize += (m_pNtHeader->OptionalHeader.FileAlignment - Ali);//�õ�����֮��Ĵ�С
		m_pSecHeader[n].SizeOfRawData = AliSize;//������֮��Ĵ�С���и�ֵ
		//�����������п���
		memset((LPVOID)SecAddr, 0, AliSize);//�Ƚ�������,�ַ�����0��β
		memcpy_s((LPVOID)SecAddr, m_pSecHeader[n].SizeOfRawData, pPackData, PackSize);//��ѹ�������ݿ�������
		delete[]pPackData;//�ͷ����������Դ
		delete[]pWorkMem;
	}
	return 0;
}