#pragma once
#include "PE.h"

class CPACK
{
public:
	CPACK();
	~CPACK();
public:
	//�ӿǴ���
	BOOL Pack(CString strFilePath/*,BOOL bIsShowMesBox*/);			

	//�������ռӿǺ���ļ�
	BOOL SaveFinalFile(LPBYTE pFinalBuf, DWORD pFinalBufSize,CString strFilePath);		
};

