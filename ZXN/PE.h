#pragma once
#include "aplib.h"
#pragma comment(lib, "./aplib.lib")
class CPE
{
public:
	CPE();
	~CPE();
public:
	HANDLE					m_hFile;			//PE�ļ����
	LPBYTE					m_pFileBuf;			//PE�ļ�������
	DWORD					m_dwFileSize;		//�ļ���С
	DWORD					m_dwImageSize;		//�����С
	PIMAGE_DOS_HEADER		m_pDosHeader;		//Dosͷ
	PIMAGE_NT_HEADERS		m_pNtHeader;		//NTͷ
	PIMAGE_SECTION_HEADER	m_pSecHeader;		//��һ��SECTION�ṹ��ָ��
	DWORD					m_dwImageBase;		//�����ַ
	DWORD					m_dwPEOEP;			//OEP��ַ
	DWORD					m_dwShellOEP;		//��OEP��ַ
	DWORD					m_dwSizeOfHeader;	//�ļ�ͷ��С
	DWORD					m_dwSectionNum;		//��������
	DWORD                   m_dwRescore;		//��Դ���ڵ�����
	DWORD					m_dwFileAlign;		//�ļ�����
	DWORD					m_dwMemAlign;		//�ڴ����

	DWORD					m_IATSectionBase;	//IAT���ڶλ�ַ
	DWORD					m_IATSectionSize;	//IAT���ڶδ�С
	IMAGE_DATA_DIRECTORY	m_PERelocDir;		//�ض�λ����Ϣ
	IMAGE_DATA_DIRECTORY	m_PEImportDir;		//�������Ϣ
	

public:
	BOOL InitPE(CString strFilePath);			//��ʼ��PE����ȡPE�ļ�������PE��Ϣ
	void InitValue();							//��ʼ����
	BOOL OpenPEFile(CString strFilePath);		//���ļ�
	BOOL IsPE();								//�ж��Ƿ�ΪPE�ļ�
	void GetPEInfo();							//��ȡPE��Ϣ
	DWORD XorCode();					//����μ���
	BOOL SetShellReloc(LPBYTE pShellBuf, DWORD hShell);		
												//����Shell���ض�λ��Ϣ

	void MergeBuf(LPBYTE pFileBuf, DWORD pFileBufSize, 
		LPBYTE pShellBuf, DWORD pShellBufSize, 
		LPBYTE& pFinalBuf, DWORD& pFinalBufSize);
												//�ϲ�PE�ļ���Shell
	void SetNewOEP(DWORD dwShellOEP);			//�޸��µ�OEPΪShell��Start����

	BOOL PackCode();
};

