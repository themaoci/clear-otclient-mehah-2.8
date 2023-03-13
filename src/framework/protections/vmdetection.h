
#pragma once
#ifndef VMDETECTION_H
#define VMDETECTION_H

#include "xorstr.hpp"

class VMDetection
{
public:
    void check();
	bool wasRun() { return m_wasRun; }
private:
	struct _cpuid_buffer_t
	{
		uint32_t EAX;
		uint32_t EBX;
		uint32_t ECX;
		uint32_t EDX;
	};

	inline void executeDetection(int code = 0) {
		exit(code);
	}

	bool known_dlls();
	bool known_hostnames();
	bool NumberOfProcessors();
	bool memory_space();
	bool accelerated_sleep();
	bool cpuid_is_hypervisor();
	bool take_time();
	bool take_time_cpuid_against_fyl2xp1();
	bool check_invalid_leaf();
	bool check_highest_low_function_leaf();
	bool check_for_known_hypervisor();
	static TCHAR* get_netbios_hostname() {
		TCHAR* hostname;
		DWORD nSize = (MAX_COMPUTERNAME_LENGTH + 1);

		hostname = (TCHAR*)malloc(nSize * sizeof(TCHAR));
		if (!hostname) {
			return NULL;
		}
		if (0 == GetComputerName(hostname, &nSize)) {
			free(hostname);
			return NULL;
		}
		return hostname;
	}
	static TCHAR* get_dns_hostname() {
		TCHAR* hostname;
		DWORD nSize = 0;

		GetComputerNameEx(ComputerNameDnsHostname, NULL, &nSize);
		hostname = (TCHAR*)malloc((nSize + 1) * sizeof(TCHAR));
		if (!hostname) {
			return NULL;
		}
		if (0 == GetComputerNameEx(ComputerNameDnsHostname, hostname, &nSize)) {
			free(hostname);
			return NULL;
		}
		return hostname;
	}
	bool m_wasRun = false;
};

extern VMDetection g_vmdetection;

#endif