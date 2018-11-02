#include<Windows.h>
#ifdef SHELL_EXPORTS
#define SHELL_API __declspec(dllexport)
#else
#define SHELL_API __declspec(dllimport)
#endif

//导出ShellData结构体
extern"C"  typedef struct _SHELL_DATA
{
	DWORD dwStartFun;							//启动函数
	DWORD dwPEOEP;								//程序入口点
	DWORD dwPEImageBase;						//PE文件映像基址
	DWORD dwSizeofBase;							//PE文件的大小
	DWORD dwRecur;								//资源所在的区段
	IMAGE_DATA_DIRECTORY	stcPERelocDir;		//重定位表信息
	IMAGE_DATA_DIRECTORY	stcPEImportDir;		//导入表信息
	DWORD					dwIATSectionBase;	//IAT所在段基址
	DWORD					dwIATSectionSize;	//IAT所在段大小
}SHELL_DATA, *PSHELL_DATA;

//导出ShellData结构体变量
extern"C" SHELL_API SHELL_DATA g_stcShellData;



//Shell部分用到的函数的类型定义
typedef DWORD(WINAPI *fnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef HMODULE(WINAPI *fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef HMODULE(WINAPI *fnGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
typedef BOOL(WINAPI *fnVirtualProtect)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef LPVOID(WINAPI *fnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef void(WINAPI *fnExitProcess)(_In_ UINT uExitCode);
typedef int(WINAPI *fnMessageBox)(HWND hWnd, LPSTR lpText, LPSTR lpCaption, UINT uType);
typedef BOOL(WINAPI *fnVirtualFree)(_Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress, _In_ SIZE_T dwSize,
	_In_ DWORD dwFreeType);
typedef void* (WINAPI *fnmemmove)(_Out_writes_bytes_all_opt_(_Size) void*       _Dst,_In_reads_bytes_opt_(_Size)       void const* _Src,
	_In_                              size_t      _Size);
typedef void* (WINAPI *fnmemset)(_Out_writes_bytes_all_(_Size) void*  _Dst,_In_                          int    _Val,
	_In_                          size_t _Size);
typedef LRESULT (WINAPI *fnDefWindowProcW)(_In_ HWND hWnd,_In_ UINT Msg,_In_ WPARAM wParam,_In_ LPARAM lParam);
typedef ATOM (WINAPI *fnRegisterClassExA)(_In_ CONST WNDCLASSEXA *);
typedef HWND(WINAPI *fnCreateWindowExA)(_In_ DWORD dwExStyle, _In_opt_ LPCSTR lpClassName, _In_opt_ LPCSTR lpWindowName, _In_ DWORD dwStyle, _In_ int X,
	_In_ int Y, _In_ int nWidth, _In_ int nHeight, _In_opt_ HWND hWndParent, _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance, _In_opt_ LPVOID lpParam);

typedef BOOL (WINAPI*fnShowWindow)(_In_ HWND hWnd, _In_ int nCmdShow);
typedef BOOL (WINAPI*fnUpdateWindow)(_In_ HWND hWnd);
typedef BOOL (WINAPI *fnGetMessageW)(_Out_ LPMSG lpMsg,_In_opt_ HWND hWnd,_In_ UINT wMsgFilterMin,_In_ UINT wMsgFilterMax);
typedef BOOL (WINAPI *fnTranslateMessage)(_In_ CONST MSG *lpMsg);
typedef LRESULT (WINAPI *fnDispatchMessageA)(_In_ CONST MSG *lpMsg);

typedef HWND (WINAPI*fnCreateDialogParamA)(_In_opt_ HINSTANCE hInstance, _In_ LPCSTR lpTemplateName,_In_opt_ HWND hWndParent,
_In_opt_ DLGPROC lpDialogFunc,_In_ LPARAM dwInitParam);

typedef HWND (WINAPI *fnCreateWindowExW)(_In_ DWORD dwExStyle,_In_opt_ LPCWSTR lpClassName,_In_opt_ LPCWSTR lpWindowName,
	_In_ DWORD dwStyle,_In_ int X,_In_ int Y,_In_ int nWidth,_In_ int nHeight,_In_opt_ HWND hWndParent,_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,_In_opt_ LPVOID lpParam);
typedef INT_PTR (WINAPI*fnDialogBoxParamA)(_In_opt_ HINSTANCE hInstance,_In_ LPCSTR lpTemplateName,
	_In_opt_ HWND hWndParent,_In_opt_ DLGPROC lpDialogFunc,_In_ LPARAM dwInitParam);

typedef INT_PTR (WINAPI*fnDialogBoxParamW)(_In_opt_ HINSTANCE hInstance,_In_ LPCWSTR lpTemplateName,_In_opt_ HWND hWndParent,
	_In_opt_ DLGPROC lpDialogFunc,_In_ LPARAM dwInitParam);

typedef ATOM (WINAPI *fnRegisterClassW)(_In_ CONST WNDCLASSW *lpWndClass);

typedef HWND (WINAPI *fnGetDlgItem)(_In_opt_  HWND hDlg,_In_      int nIDDlgItem);
typedef int (WINAPI *fnGetWindowTextA)(_In_ HWND hWnd,_Out_writes_(nMaxCount) LPSTR lpString,_In_ int nMaxCount);
typedef VOID (WINAPI *fnPostQuitMessage)(_In_  int nExitCode);

typedef LSTATUS (APIENTRY *fnRegSetValueExA)(_In_ HKEY hKey,_In_opt_ LPCSTR lpValueName,_Reserved_ DWORD Reserved,
	_In_ DWORD dwType,_In_reads_bytes_opt_(cbData) CONST BYTE* lpData,_In_ DWORD cbData);

typedef LSTATUS (APIENTRY *fnRegCreateKeyA)(_In_ HKEY hKey,_In_opt_ LPCSTR lpSubKey,_Out_ PHKEY phkResult);

typedef LSTATUS (APIENTRY *fnRegQueryValueExA)(_In_ HKEY hKey,_In_opt_ LPCSTR lpValueName,_Reserved_ LPDWORD lpReserved,
	_Out_opt_ LPDWORD lpType,_Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
	_When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData);

typedef LSTATUS (APIENTRY *fnRegOpenKeyExA)(_In_ HKEY hKey,_In_opt_ LPCSTR lpSubKey,_In_opt_ DWORD ulOptions,_In_ REGSAM samDesired,
	_Out_ PHKEY phkResult);

typedef LSTATUS (APIENTRY *fnRegCloseKey)(_In_ HKEY hKey);