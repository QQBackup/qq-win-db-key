#include <iostream>
#include <cstdio>
#include <Windows.h>
#include <unistd.h>
#include <iomanip>
//#include "sigscan.h"

// g++ t1.cpp -Wall -Wextra
// https://blog.csdn.net/cjz2005/article/details/104465290
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wconversion-null"

// SigScan code from https://github.com/aikar/SigScan , copyright belongs to original authors.
DWORD SigScan(const char* szPattern, int offset = 0);
void InitializeSigScan(DWORD ProcessID, const char* szModule);
void FinalizeSigScan();

#include <tlhelp32.h>
#include <map>
#include <string>
using std::map;
using std::string;
bool bIsLocal = false;
bool bInitialized = false;
BYTE *FFXiMemory = NULL;
DWORD BaseAddress = NULL;
DWORD ModSize = NULL;


typedef struct checks
{
	short start;
	short size;
	checks() { start = NULL; size = 0; }
	checks(short sstart, short ssize) { start = sstart; size = ssize; }
} checks;

void InitializeSigScan(DWORD ProcessID, const char* Module)
{
	MODULEENTRY32 uModule;
	SecureZeroMemory(&uModule, sizeof(MODULEENTRY32));
	uModule.dwSize = sizeof(MODULEENTRY32); 
	//Create snapshot of modules and Iterate them
	HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessID);
	for(BOOL bModule = Module32First(hModuleSnapshot, &uModule);bModule;bModule = Module32Next(hModuleSnapshot, &uModule))
	{
		uModule.dwSize = sizeof(MODULEENTRY32); 
		if(!_stricmp(uModule.szModule,Module))
		{
			FinalizeSigScan();
			BaseAddress = (DWORD)uModule.modBaseAddr;
			ModSize = uModule.modBaseSize;
			if(GetCurrentProcessId() == ProcessID)
			{
				bIsLocal = true;
				bInitialized = true;
				FFXiMemory = (BYTE*)BaseAddress;
			}else{
				bIsLocal = false;
				FFXiMemory = new BYTE[ModSize];
				HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, ProcessID);
				if(hProcess)
				{
					if(ReadProcessMemory(hProcess,(LPCVOID)BaseAddress,FFXiMemory,ModSize,NULL))
					{
						bInitialized = true;
					}
					CloseHandle(hProcess);
				}
			}
			break;
		}
	}
	CloseHandle(hModuleSnapshot);
}
void FinalizeSigScan()
{
	if(FFXiMemory)
	{
		if(!bIsLocal)
		{
			delete FFXiMemory;
		}
		FFXiMemory = NULL;
		bInitialized = false;
	}
}
DWORD SigScan(const char* szPattern, int offset)
{
    // std::cout<<"SigScan init"<<std::endl;
	//Get Pattern length
	unsigned int PatternLength = strlen(szPattern);
	//Pattern must be divisible by 2 to be valid.
	if(PatternLength % 2 != 0 || PatternLength < 2 || !bInitialized || !FFXiMemory || !BaseAddress) {
	   std::cout<<"SigScan check FAILED"<<std::endl;
	   return NULL;
	}
	//Get the buffer size
    // std::cout<<"SigScan check ok"<<std::endl;
	unsigned int buffersize = PatternLength/2;
	//Setup custom ptr location. Default to buffersize(first byte after signature)+offset
	int PtrOffset = buffersize + offset;
	bool Dereference = true;
	if(memcmp(szPattern,"##",2)==0)
	{
		Dereference = false;
		szPattern += 2;
		PtrOffset = 0 + offset;
		PatternLength -= 2;
		buffersize--;
	}
	//Dont follow the pointer, return the exact end of signature+offset.
	if(memcmp(szPattern,"@@",2)==0)
	{
		Dereference = false;
		szPattern += 2;
		PatternLength -= 2;
	}

	//Capitalize the strings and create a string for cache key.
	char Pattern[1024];
	ZeroMemory(Pattern,sizeof(Pattern));
	strcpy_s(Pattern,sizeof(Pattern),szPattern);
	_strupr_s(Pattern,sizeof(Pattern));


	//Create the buffer
	unsigned char* buffer = new unsigned char[buffersize];
	SecureZeroMemory(buffer,buffersize);

	//array for bytes we need to check and temporary holders for size/start
	checks memchecks[32];
	short cmpcount = 0;
	short cmpsize = 0;
	short cmpstart = 0;
	//Iterate the pattern and build the buffer.
	for(size_t i = 0; i < PatternLength / 2 ; i++)
	{
		//Read the values of the bytes for usage to reduce use of STL.
		unsigned char byte1 = Pattern[i*2];
		unsigned char byte2 = Pattern[(i*2)+1];
		//Check for valid hexadecimal digits.
		if(((byte1 >= '0' && byte1 <= '9') || (byte1 <= 'F' && byte1 >= 'A')) || ((byte2 >= '0' && byte2 <= '9') || (byte2 <= 'F' && byte2 >= 'A')))
		{
			//Increase the comparison size.
			cmpsize++;
			//convert the 2 byte string to a byte value ("14" == 0x14 == 20)
			if (byte1 <= '9') buffer[i] += byte1 - '0';
			else buffer[i] += byte1 - 'A' + 10;
			buffer[i] *= 16;	
			if (byte2 <= '9') buffer[i] += byte2 - '0';
			else buffer[i] += byte2 - 'A' + 10;
			continue;
		}
		//Wasnt valid hex, is it a custom ptr location?
		else if(byte1 == 'X' && byte2 == byte1 && (PatternLength/2) - i > 3) 
		{
			//Set the ptr to this current location + offset.
			PtrOffset = i + offset;
			//Fill the buffer with the ptr locations.
			buffer[i++]	= 'X';
			buffer[i++]	= 'X';
			buffer[i++]	= 'X';
			buffer[i]	= 'X';			
		}
		//Wasnt a custom ptr location nor valid hex, so set it as a wildcard.
		else 
		{
			//? for wildcard, unknown byte value.
			buffer[i]	= '?';
		}
		//Add the check to the array.
		if(cmpsize>0) memchecks[cmpcount++] = checks(cmpstart,cmpsize);
		//Increase the starting check byte and reset the size comparison size.
		cmpstart = i+1;
		cmpsize = 0;
	}
	//Add the final check 
	if(cmpsize>0) memchecks[cmpcount++] = checks(cmpstart,cmpsize);
	
	//Get the current base address and module size.
	char* mBaseAddr = (char*)FFXiMemory;
	unsigned int mModSize = ModSize;
	//Boolean that returns true or false for matching.
	bool bMatching = true;
	//Iterate the Module.
	int Match_Count = 0;
	DWORD Last_Address = NULL;
	for	(char* 
		addr = (char*)memchr(mBaseAddr	, buffer[0], mModSize - buffersize);
		addr && (DWORD)addr < (DWORD)((DWORD)mBaseAddr + mModSize - buffersize); 
		addr = (char*)memchr(addr+1		, buffer[0], mModSize - buffersize - (addr+1 - mBaseAddr))
		)
	{
		bMatching = true;
		//Iterate each comparison we need to do. (seperated by wildcards)
		for(short c = 0;c<cmpcount; c++)
		{
			//Compare the memory.
			if(memcmp(buffer + memchecks[c].start,(void*)(addr + memchecks[c].start),memchecks[c].size) != 0)
			{
				//Did not match, try next byte.
				bMatching = false;
				break;
			}
		}
		//After full Pattern scan, check if it matched.
		if(bMatching)
		{
			//Find address wanted in FFXI's memory space - not ours.
			DWORD Address = NULL;
			if(Dereference)
			{
				Address = (DWORD)*((void **)(addr + PtrOffset));
			}else{
				Address = BaseAddress + (DWORD)((addr + PtrOffset) - (DWORD)FFXiMemory);
			}
			//Clear buffer and return result.
			//delete [] buffer;
    //        std::cout<<"SigScan found success: "<<Address<<std::endl;
            Last_Address = Address;
            ++Match_Count;
			//return Address;
		}
	}
	//Nothing matched. Clear buffer
	delete [] buffer;
	if(Match_Count>1){
	    std::cout<<"!!! MULTI Addr found. total: "<< Match_Count << std::endl;
	}
	if(Match_Count==1){
    //    std::cout<<"SigScan return success: "<< Last_Address << std::endl;
	    return Last_Address;
	}
    std::cout<<"SigScan ret 2 NULL"<<std::endl;
	return NULL;
}

// SigScan code end.


using namespace std;


//DWORD SigScan(const char* szPattern, int offset = 0);
//void InitializeSigScan(DWORD ProcessID, const char* Module);
//void FinalizeSigScan();
//#pragma comment(lib,"SigScanStatic.lib")
#define ull unsigned long int

static PVOID originalFuncAddress = 0;
static PVOID sqlite3DbFilenameAddress = 0;

static int callback(void *data, int argc, char **argv, char **azColName)
{
    int i;
    printf( "%s ", (const char*)data);
    for(i=0; i<argc; i++)
    {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

typedef int (__cdecl *psqlite3_key)(void *, const void *, int);
typedef int (__cdecl *psqlite3_open)(
  const char *filename,   /* Database filename (UTF-8) */
  int **ppDb          /* OUT: SQLite db handle */
);
typedef int (__cdecl *psqlite3_exec)(void* db, const char *sql, 
    int (*callback)(void*,int,char**,char**), /* Callback function */
    void *, /* 1st argument to callback */
    char **errmsg /* Error msg written here */
);
int empty_key[16] = {0};
int main(){
    HMODULE current_module = GetModuleHandle(NULL); 
    HMODULE hModule = LoadLibraryEx("KernelUtil.Dll", NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (hModule == NULL){
        cout << "error loading: " << GetLastError() << endl;
        return 2;
    }
    
    InitializeSigScan(GetCurrentProcessId(), "KernelUtil.dll");
    
    /*psqlite3_key key = (psqlite3_key)((DWORD)hModule + 0x1);
    psqlite3_open open = (psqlite3_open)((DWORD)hModule + 0x1);
    psqlite3_exec exec = (psqlite3_exec)((DWORD)hModule + 0x1);
    psqlite3_key impl = (psqlite3_key)((DWORD)hModule + 0x1);
    psqlite3_key rekey = (psqlite3_key)((DWORD) hModule + 0x1);*/
    
    // cout<<sizeof(psqlite3_key)<<"test scan:"<<SigScan("##558BEC566B751011837D1010740D6817020000E8")<<endl;
    
    psqlite3_key akey = (psqlite3_key)(SigScan("##558BEC566B751011837D1010740D6817020000E8")); // ok
    psqlite3_open aopen = (psqlite3_open)(SigScan("##558BEC6A006A06FF750CFF7508E8E0130200")); // ok
    psqlite3_exec aexec = (psqlite3_exec)(SigScan("##558BEC8B45088B40505DC3")); // ok
    // psqlite3_key aimpl = (psqlite3_key)(SigScan("##558BECFF7508E8D608FFFF5985C0750D687E010000"));// key line 17
    psqlite3_key arekey = (psqlite3_key)(SigScan("##558BEC837D1010740D682F020000E8")); // ok
    
    /*cout<<hex;
    cout << (ull)akey << endl << (ull)aopen << endl << (ull)aexec << endl << (ull)aimpl << endl << (ull)arekey << endl << endl;
    cout << (ull)akey-(DWORD)hModule << endl << (ull)aopen-(DWORD)hModule << endl << (ull)aexec-(DWORD)hModule << endl << (ull)aimpl-(DWORD)hModule << endl << (ull)arekey-(DWORD)hModule << endl << endl;
    cout << (ull)akey-(DWORD)current_module << endl << (ull)aopen-(DWORD)current_module << endl << (ull)aexec-(DWORD)current_module << endl << (ull)aimpl-(DWORD)current_module << endl << (ull)arekey-(DWORD)current_module << endl << endl;
    cout << (ull)akey-(DWORD)current_module-(DWORD)hModule << endl << (ull)aopen-(DWORD)current_module-(DWORD)hModule << endl << (ull)aexec-(DWORD)current_module-(DWORD)hModule << endl << (ull)aimpl-(DWORD)current_module-(DWORD)hModule << endl << (ull)arekey-(DWORD)current_module-(DWORD)hModule << endl << endl;
    cout<<setbase(10);*/
    
    FinalizeSigScan();
    // cout<<"fined scan"<<endl;
    //原始Key
    BYTE pwdKey[16]={
        // PLACE YOUR KEY HERE
    };
    //拓展Key
    /*BYTE pwdKey1[272]={
    
    };*/
    int* pDB = NULL;
    int iRet = aopen("Msg3.0.db", &pDB);
    cout << "open iRet=" << iRet << endl;
    iRet = akey(pDB,(unsigned char *)pwdKey, 16);
    cout << "key iRet=" << iRet << endl;
    //iRet = aimpl(pDB, pwdKey1, 16*17);
    
    char select[]="SELECT * FROM sqlite_master WHERE type='table' ORDER BY name;";
    //char sql[] = "select from;";
    char* pErrmsg = NULL;
    printf("====EXEC=========\n");
    iRet = aexec(pDB, select, callback, NULL, &pErrmsg);
    cout << "exec iRet=" << iRet << endl;
    iRet = arekey(pDB, (unsigned char *)empty_key, 16);
    cout << "rekey iRet=" << iRet << endl;
    printf("====END=========\n");
    return 0;
}