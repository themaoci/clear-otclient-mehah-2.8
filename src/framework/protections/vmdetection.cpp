

#include <intrin.h>
#include <iostream>
#include <Windows.h>
#include <format>
#include <functional>
#include <future>
#include <map>

#include <Wbemidl.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#include <tchar.h>

#include "vmdetection.h"

VMDetection g_vmdetection;

void VMDetection::check() {
	if (known_dlls()) {
		executeDetection(11);
	}
	if (known_hostnames()) {
		executeDetection(12);
	}
	if (NumberOfProcessors()) {
		executeDetection(13);
	}
	if (memory_space()) {
		executeDetection(14);
	}
	if (accelerated_sleep()) {
		executeDetection(15);
	}
	if (cpuid_is_hypervisor()) {
		executeDetection(16);
	}
	if (take_time_cpuid_against_fyl2xp1()) {
		executeDetection(17);
	}
	if (check_highest_low_function_leaf()) {
		executeDetection(18);
	}
	if (check_invalid_leaf()) {
		executeDetection(19);
	}
	if (check_for_known_hypervisor()) {
		executeDetection(20);
	}
	m_wasRun = true;
}

bool VMDetection::known_dlls() 
{
	/* Some vars */
	HMODULE hDll;

	/* Array of strings of blacklisted dlls */
	CONST TCHAR* szDlls[] = {
		xorstr_("avghookx.dll"),	// AVG
		xorstr_("avghooka.dll"),	// AVG
		xorstr_("snxhk.dll"),		// Avast
		xorstr_("sbiedll.dll"),		// Sandboxie
		xorstr_("dbghelp.dll"),		// WindBG
		xorstr_("api_log.dll"),		// iDefense Lab
		xorstr_("dir_watch.dll"),	// iDefense Lab
		xorstr_("pstorec.dll"),		// SunBelt Sandbox
		xorstr_("vmcheck.dll"),		// Virtual PC
		xorstr_("wpespy.dll"),		// WPE Pro
		xorstr_("cmdvrt64.dll"),	// Comodo Container
		xorstr_("cmdvrt32.dll"),	// Comodo Container
	};

	WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
	for (int i = 0; i < dwlength; i++) {
		/* Check if process loaded modules contains the blacklisted dll */
		hDll = GetModuleHandle(szDlls[i]);
		if (hDll != NULL)
			return true;
	}
	return false;
}

/*
Check for hostnames associated with sandboxes
*/
bool VMDetection::known_hostnames() {

	/* Array of strings of hostnames seen in sandboxes */
	CONST TCHAR* szHostnames[] = {
		/* Checked for by Gootkit
		 * https://www.sentinelone.com/blog/gootkit-banking-trojan-deep-dive-anti-analysis-features/ */
		xorstr_("SANDBOX"),
		xorstr_("7SILVIA"),

		/* Checked for by ostap
		 * https://www.bromium.com/deobfuscating-ostap-trickbots-javascript-downloader/ */
		xorstr_("HANSPETER-PC"),
		xorstr_("JOHN-PC"),
		xorstr_("MUELLER-PC"),
		xorstr_("WIN7-TRAPS"),

		/* Checked for by Shifu (not including ones from above)
		 * https://www.mcafee.com/blogs/other-blogs/mcafee-labs/japanese-banking-trojan-shifu-combines-malware-tools */
		xorstr_("FORTINET"),

		/* Checked for by Emotet (not including ones from above)
		 * https://blog.trendmicro.com/trendlabs-security-intelligence/new-emotet-hijacks-windows-api-evades-sandbox-analysis/ */
		xorstr_("TEQUILABOOMBOOM"), /* VirusTotal Cuckoofork Sandbox */
	};
	TCHAR* NetBIOSHostName;
	TCHAR* DNSHostName;

	if (NULL == (NetBIOSHostName = get_netbios_hostname())) {
		return;
	}

	if (NULL == (DNSHostName = get_dns_hostname())) {
		free(NetBIOSHostName);
		return;
	}

	TCHAR msg[256];
	WORD dwlength = sizeof(szHostnames) / sizeof(szHostnames[0]);
	for (int i = 0; i < dwlength; i++) {

		/* Do a case-insensitive search for all entries in szHostnames */
		if (0 == _tcsicmp(szHostnames[i], NetBIOSHostName)) {
			return true;
		} else if (0 == _tcsicmp(szHostnames[i], DNSHostName)) {
			return true;
		}
	}

	free(NetBIOSHostName);
	free(DNSHostName);
}

/*
Number of Processors in VM
*/

bool VMDetection::NumberOfProcessors()
{
#if defined (_WIN64)
	PULONG ulNumberProcessors = (PULONG)(__readgsqword(0x60) + 0xB8);
#else
	PULONG ulNumberProcessors = (PULONG)(__readfsdword(0x30) + 0x64);
#endif

	if (*ulNumberProcessors < 2)
		return TRUE;
	else
		return FALSE;
}

/*
Check if the machine have enough memory space, usually VM get a small ammount,
one reason if because several VMs are running on the same servers so they can run
more tasks at the same time.
*/
bool VMDetection::memory_space()
{
	DWORDLONG ullMinRam = (1024LL * (1024LL * (1024LL * 1LL))); // 1GB
	MEMORYSTATUSEX statex = { 0 };

	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);

	return (statex.ullTotalPhys < ullMinRam) ? TRUE : FALSE;
}

/*
Sleep and check if time have been accelerated
*/
bool VMDetection::accelerated_sleep()
{
	DWORD dwStart = 0, dwEnd = 0, dwDiff = 0;
	DWORD dwMillisecondsToSleep = 60 * 1000;

	/* Retrieves the number of milliseconds that have elapsed since the system was started */
	dwStart = GetTickCount();

	/* Let's sleep 1 minute so Sandbox is interested to patch that */
	Sleep(dwMillisecondsToSleep);

	/* Do it again */
	dwEnd = GetTickCount();

	/* If the Sleep function was patched*/
	dwDiff = dwEnd - dwStart;
	if (dwDiff > dwMillisecondsToSleep - 1000) // substracted 1s just to be sure
		return FALSE;
	else
		return TRUE;
}

/*
The CPUID instruction is a processor supplementary instruction (its name derived from
CPU IDentification) for the x86 architecture allowing software to discover details of
the processor. By calling CPUID with EAX =1, The 31bit of ECX register if set will
reveal the precense of a hypervisor.
*/
bool VMDetection::cpuid_is_hypervisor()
{
	INT CPUInfo[4] = { -1 };

	/* Query hypervisor precense using CPUID (EAX=1), BIT 31 in ECX */
	__cpuid(CPUInfo, 1);
	if ((CPUInfo[2] >> 31) & 1)
		return TRUE;
	else
		return FALSE;
}

// resources [check https://secret.club/2020/01/12/battleye-hypervisor-detection.html] #Improvement Part
bool VMDetection::take_time_cpuid_against_fyl2xp1()
{
	constexpr auto measure_times = 5;
	auto positives = 0;
	auto negatives = 0;

	// run the internal VM check multiple times to get an average result
	for (auto i = measure_times; i != 0; --i)
		take_time() ? ++positives : ++negatives;

	// if there are more positive results than negative results, the
	// process is likely running inside a VM
	const bool decision = (positives >= negatives);

	return decision;
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html
bool VMDetection::check_invalid_leaf()
{
	constexpr unsigned int invalid_leaf = 0x04201337;
	constexpr unsigned int valid_leaf = 0x40000000;

	_cpuid_buffer_t InvalidLeafResponse = {};
	_cpuid_buffer_t ValidLeafResponse = {};

	__cpuid(reinterpret_cast<int32_t*>(&InvalidLeafResponse), invalid_leaf);
	__cpuid(reinterpret_cast<int32_t*>(&ValidLeafResponse), valid_leaf);

	if ((InvalidLeafResponse.EAX != ValidLeafResponse.EAX) ||
		(InvalidLeafResponse.EBX != ValidLeafResponse.EBX) ||
		(InvalidLeafResponse.ECX != ValidLeafResponse.ECX) ||
		(InvalidLeafResponse.EDX != ValidLeafResponse.EDX))
		return true;

	return false;
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html
bool VMDetection::check_highest_low_function_leaf()
{
	constexpr auto queryVendorIdMagic = 0x40000000;

	_cpuid_buffer_t regs = {};
	__cpuid(reinterpret_cast<int32_t*>(&regs), queryVendorIdMagic);

	_cpuid_buffer_t reserved_regs = {};
	__cpuid(reinterpret_cast<int32_t*>(&reserved_regs), 1);

	__cpuid(reinterpret_cast<int32_t*>(&reserved_regs), reserved_regs.EAX);

	if (reserved_regs.EAX != regs.EAX ||
		reserved_regs.EBX != regs.EBX ||
		reserved_regs.ECX != regs.ECX ||
		reserved_regs.EDX != regs.EDX)
		return true;

	return false;
}

// resouces https://kb.vmware.com/s/article/1009458
bool VMDetection::check_for_known_hypervisor()
{
	_cpuid_buffer_t cpuInfo = {};
	__cpuid(reinterpret_cast<int32_t*>(&cpuInfo), 1);

	if (!(cpuInfo.ECX & (1 << 31))) // check bit 31 of register ECX, which is “hypervisor present bit”
		return false;               // if not present return

	// we know hypervisor is present we can query the vendor id.
	constexpr auto queryVendorIdMagic = 0x40000000;
	__cpuid(reinterpret_cast<int32_t*>(&cpuInfo), queryVendorIdMagic);

	// construct string for our vendor name
	constexpr auto size = 13;
	const auto presentVendor = new char[size];
	memcpy(presentVendor + 0, &cpuInfo.EBX, 4);
	memcpy(presentVendor + 4, &cpuInfo.ECX, 4);
	memcpy(presentVendor + 8, &cpuInfo.EDX, 4);
	presentVendor[12] = '\0';

	// check against known vendor names
	const char* vendors[]{
		"KVMKVMKVM\0\0\0", // KVM 
		"Microsoft Hv",    // Microsoft Hyper-V or Windows Virtual PC */
		"VMwareVMware",    // VMware 
		"XenVMMXenVMM",    // Xen 
		"prl hyperv  ",    // Parallels
		"VBoxVBoxVBox"     // VirtualBox 
	};

	for (const auto& vendor : vendors) {
		if (!memcmp(vendor, presentVendor, size)) {
			//std::cout << "\tFound known hypervisor: " << presentVendor << std::endl;
			return true;
		}
	}

	//std::cout << "\tFound unknown hypervisor: " << presentVendor << std::endl;
	return false;
}