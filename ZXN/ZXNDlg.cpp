
// ZXNDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "ZXN.h"
#include "ZXNDlg.h"
#include "afxdialogex.h"
#include <tchar.h>
#include "PACK.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

ZXNDlg::ZXNDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(ZXNDlg::IDD, pParent)
	, m_strFilePath(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void ZXNDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, m_strFilePath);
}

BEGIN_MESSAGE_MAP(ZXNDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &ZXNDlg::OnBnClicked_OpenFile)
	ON_BN_CLICKED(IDC_BUTTON2, &ZXNDlg::OnBnClicked_Pack)
	ON_BN_CLICKED(IDC_BUTTON3, &ZXNDlg::OnBnClickedButton3)
END_MESSAGE_MAP()

BOOL ZXNDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void ZXNDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	CDialogEx::OnSysCommand(nID, lParam);
}

void ZXNDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR ZXNDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void ZXNDlg::OnBnClicked_OpenFile()
{
	CFileDialog dlg(TRUE);
	if (dlg.DoModal() == IDOK)
		m_strFilePath = dlg.GetPathName();
	else
		return;
	UpdateData(FALSE);
}

void ZXNDlg::OnBnClicked_Pack()
{
	if (m_strFilePath.IsEmpty())
	{
		MessageBox(_T("请选择被加壳的文件！"), _T("提示"), MB_OK);
		return;
	}
		
	CPACK objPACK;

	if (objPACK.Pack(m_strFilePath))
		MessageBox(_T("加壳成功！"), _T("提示"), MB_OK);

}


void ZXNDlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
	PostQuitMessage(0);
}
