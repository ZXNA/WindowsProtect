
// ZXNDlg.h : ͷ�ļ�
//

#pragma once


// ZXNDlg �Ի���
class ZXNDlg : public CDialogEx
{
// ����
public:
	ZXNDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_CYXVCPROTECT_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CString m_strFilePath;					//���ӿ��ļ�·��
	afx_msg void OnBnClicked_OpenFile();	//���ļ���ť
	afx_msg void OnBnClicked_Pack();		//�ӿǰ�ť
	afx_msg void OnBnClickedButton3();
};
