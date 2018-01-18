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

ULONG p_KiFastCallEntry = 0;								//HOOK�ĺ�������ֽڴ�

ULONG ServiceFunctionID;									//��ȡNtOpenProcess��SSDT���е��±�

ULONG O_NtOpenProcess;										//��ǰ��NtOpenProcess�ĵ�ַ

ULONG DeviationOfName;										//�ҵ���ǰϵͳ�汾��EPROCESS��ImageName�����ƫ����

UCHAR OldHeader[5];

UCHAR NewHeader[5] = { 0xE9,0x0,0x0,0x0,0x0 };				//�����������������ֽ�

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
	IN PCLIENT_ID           ClientId);					//����һ��ָ�뺯�������������O_NtOpenProcess����ǿ��ת��


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

void PageProtectOff()//�ر�ҳ�汣��
{
	__asm {
		cli
		mov  eax, cr0
		and  eax, not 10000h
		mov  cr0, eax
	}
}

void PageProtectOn()//��ҳ�汣��
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
	KeServiceDescriptorTable.ServiceTableBase[ServiceFunctionID] = O_NtOpenProcess;//�ָ�ssdt��ԭ���ĺ�����ַ
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

	O_NtOpenProcess = KeServiceDescriptorTable.ServiceTableBase[ServiceFunctionID];//����ԭ���ĺ�����ַ

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
		mov eax, [ebp + 4];						//ջ���ݵķ�����ȡKiFastCallEntry�ĵ�ַ
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
		ProcessHandle,//�������Լ�������󣬵���ԭ���ĺ�����������������������
		DesiredAccess,
		ObjectAttributes,
		ClientId);
}

void GetDeviationOfName()
{
	UCHAR *p = (UCHAR *)PsGetCurrentProcess();

	DeviationOfName = 0;

	//��Ϊ�������ǵ�DriverEntry��һ����System���̣����ֻ��Ҫ��ȡ��ǰ���̶���Ȼ��һ��һ�����ǲ���System�ͺã��ҵ��˼��ɻ�����ֵ�ƫ����
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
		KdPrint(("��û��ʼHOOK��"));
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