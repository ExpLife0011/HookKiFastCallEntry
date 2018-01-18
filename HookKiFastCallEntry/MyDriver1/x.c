#include <ntddk.h>

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

NTSTATUS
PsLookupProcessByProcessId(
	IN HANDLE ProcessId,
	OUT PEPROCESS *Process
);
__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

ULONG p_KiFastCallEntry = 0;								//HOOK的后面五个字节处

ULONG ServiceFunctionID;									//获取NtOpenProcess在SSDT表中的下标

ULONG O_NtOpenProcess;										//以前的NtOpenProcess的地址

ULONG DeviationOfName;										//找到当前系统版本的EPROCESS中ImageName的相对偏移量

UCHAR OldHeader[5];

UCHAR NewHeader[5] = { 0xE9,0x0,0x0,0x0,0x0 };				//我们用来替代的五个字节

NTSTATUS MyNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
);

typedef NTSTATUS(*MYNTOPENPROCESS)(
	OUT PHANDLE             ProcessHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId);					//定义一个指针函数，用于下面对O_NtOpenProcess进行强制转换


void FilterKiFastCallEntry()
{
	KdPrint(("%s", (char *)PsGetCurrentProcess() + DeviationOfName));
}

_declspec(naked) void MyKiFastCallEntry()
{
	_asm
	{
		pushad;
		pushfd;

		call	FilterKiFastCallEntry;

		popfd;
		popad;

		sub     esp, ecx;
		shr     ecx, 2;
		jmp		p_KiFastCallEntry;
	}
}

void PageProtectOff()//关闭页面保护
{
	__asm {
		cli
		mov  eax, cr0
		and  eax, not 10000h
		mov  cr0, eax
	}
}

void PageProtectOn()//打开页面保护
{
	__asm {
		mov  eax, cr0
		or eax, 10000h
		mov  cr0, eax
		sti
	}
}

void UnHookSsdt()
{
	PageProtectOff();
	KeServiceDescriptorTable.ServiceTableBase[ServiceFunctionID] = O_NtOpenProcess;//恢复ssdt中原来的函数地址
	PageProtectOn();
}

NTSTATUS ssdt_hook()
{
	UNICODE_STRING ServiceName = RTL_CONSTANT_STRING(L"NtOpenProcess");

	PVOID  ServiceFunction = MmGetSystemRoutineAddress(&ServiceName);

	for (UINT32 i = 0; TRUE; ++i)
	{
		if ((UINT32)ServiceFunction == KeServiceDescriptorTable.ServiceTableBase[i])
		{
			ServiceFunctionID = i;
			break;
		}
	}

	O_NtOpenProcess = KeServiceDescriptorTable.ServiceTableBase[ServiceFunctionID];//保存原来的函数地址

	PageProtectOff();

	KeServiceDescriptorTable.ServiceTableBase[ServiceFunctionID] = (UINT32)MyNtOpenProcess;

	PageProtectOn();

	return STATUS_SUCCESS;
}

ULONG SearchKiFastCallEntry(ULONG StartAddress)
{
	UCHAR * p = (UCHAR *)StartAddress;
	
	ULONG i;

	for (i = 0; i < 200; ++i)
	{
		if (*p == 0x2B &&
			*(p + 1) == 0xE1 &&
			*(p + 2) == 0xC1 &&
			*(p + 3) == 0xE9 &&
			*(p + 4) == 0x02)
			return (ULONG)p;
		--p;
	}

	return 0;
}

NTSTATUS MyNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
)
{
	ULONG u_KiFastCallEntry;

	ULONG pAddress = 0;

	__asm 
	{
		mov eax, [ebp + 4];						//栈回溯的方法获取KiFastCallEntry的地址
		mov u_KiFastCallEntry, eax;
	}

	pAddress = SearchKiFastCallEntry(u_KiFastCallEntry);

	if (pAddress != 0)
	{
		p_KiFastCallEntry = pAddress + 5;

		ULONG Offset = (ULONG)MyKiFastCallEntry - (pAddress + 5);

		PageProtectOff();

		memcpy((PVOID)OldHeader, (PVOID)pAddress, sizeof(OldHeader));

		memcpy((PVOID)(NewHeader + 1), (PVOID)&Offset, 4);

		memcpy((PVOID)pAddress, (PVOID)NewHeader, sizeof(NewHeader));

		PageProtectOn();
	}

	UnHookSsdt();

	return ((MYNTOPENPROCESS)O_NtOpenProcess)(
		ProcessHandle,//处理完自己的任务后，调用原来的函数，让其它进程正常工作
		DesiredAccess,
		ObjectAttributes,
		ClientId);
}

void GetDeviationOfName()
{
	UCHAR *p = (UCHAR *)PsGetCurrentProcess();

	DeviationOfName = 0;

	//因为调用我们的DriverEntry的一定是System进程，因此只需要获取当前进程对象，然后一个一个找是不是System就好，找到了即可获得名字的偏移量
	while (DeviationOfName < 0x300)
	{
		if (*p == 'S' && *(p + 1) == 'y' && *(p + 2) == 's' && *(p + 3) == 't' && *(p + 4) == 'e' && *(p + 5) == 'm')
			break;
		++DeviationOfName;
		++p;
	}
}

void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	//UnHookSsdt();

	KdPrint(("Driver Unload Success !"));

	if (p_KiFastCallEntry == 0)
	{
		KdPrint(("还没开始HOOK！"));
		return;
	}
	ULONG OldAddress = p_KiFastCallEntry - 5;

	PageProtectOff();

	memcpy((PVOID)OldAddress, OldHeader, sizeof(OldHeader));

	PageProtectOn();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegsiterPath)
{
	DbgPrint("This is My First Driver!");

	GetDeviationOfName();

	KdPrint(("The Deviation is %x", DeviationOfName));

	ssdt_hook();

	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}