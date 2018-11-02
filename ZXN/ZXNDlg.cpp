
// ZXNDlg.cpp : ʵ���ļ�
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

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO:  �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void ZXNDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	CDialogEx::OnSysCommand(nID, lParam);
}

void ZXNDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
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
		MessageBox(_T("��ѡ�񱻼ӿǵ��ļ���"), _T("��ʾ"), MB_OK);
		return;
	}
		
	CPACK objPACK;

	if (objPACK.Pack(m_strFilePath))
		MessageBox(_T("�ӿǳɹ���"), _T("��ʾ"), MB_OK);

}


void ZXNDlg::OnBnClickedButton3()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	PostQuitMessage(0);
}
