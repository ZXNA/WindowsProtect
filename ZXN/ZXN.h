
// ZXN.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// ZXNApp: 
// �йش����ʵ�֣������ ZXN.cpp
//

class ZXNApp : public CWinApp
{
public:
	ZXNApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern ZXNApp theApp;