#include <ntdll.h>

#define EventActivityIdControl  EtwEventActivityIdControl
#define EventEnabled            EtwEventEnabled
#define EventProviderEnabled    EtwEventProviderEnabled
#define EventRegister           EtwEventRegister
#define EventSetInformation     EtwEventSetInformation
#define EventUnregister         EtwEventUnregister
#define EventWrite              EtwEventWrite
#define EventWriteEndScenario   EtwEventWriteEndScenario
#define EventWriteEx            EtwEventWriteEx
#define EventWriteStartScenario EtwEventWriteStartScenario
#define EventWriteString        EtwEventWriteString
#define EventWriteTransfer      EtwEventWriteTransfer

#include <evntprov.h>
#include <evntrace.h>
#include <evntcons.h>

//////////////////////////////////////////////////////////////////////////
// Macros.
//////////////////////////////////////////////////////////////////////////

#define ALIGN_DOWN_BY(length, alignment) \
    ((ULONG_PTR)(length) & ~((ULONG_PTR)(alignment) - 1))

#define ALIGN_UP_BY(length, alignment) \
    (ALIGN_DOWN_BY(((ULONG_PTR)(length) + (alignment) - 1), alignment))

#define ALIGN_DOWN_POINTER_BY(address, alignment) \
    ((PVOID)((ULONG_PTR)(address) & ~((ULONG_PTR)(alignment) - 1)))

#define ALIGN_UP_POINTER_BY(address, alignment) \
    (ALIGN_DOWN_POINTER_BY(((ULONG_PTR)(address) + (alignment) - 1), alignment))

#define ALIGN_DOWN(length, type) \
    ALIGN_DOWN_BY(length, sizeof(type))

#define ALIGN_UP(length, type) \
    ALIGN_UP_BY(length, sizeof(type))

#define ALIGN_DOWN_POINTER(address, type) \
    ALIGN_DOWN_POINTER_BY(address, sizeof(type))

#define ALIGN_UP_POINTER(address, type) \
    ALIGN_UP_POINTER_BY(address, sizeof(type))

#define ETW_SESSION_HANDLE(WmiLoggerInformation) \
  ((USHORT)(((PWMI_LOGGER_INFORMATION)(WmiLoggerInformation))->Wnode.HistoricalContext))

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define EVENT_TRACE_CLOCK_RAW           0x00000000  // Use Raw timestamp
#define EVENT_TRACE_CLOCK_PERFCOUNTER   0x00000001  // Use HighPerfClock (Default)
#define EVENT_TRACE_CLOCK_SYSTEMTIME    0x00000002  // Use SystemTime
#define EVENT_TRACE_CLOCK_CPUCYCLE      0x00000003  // Use CPU cycle counter

#define SINGLE_LIST_ENTRY_FREE          ((PSINGLE_LIST_ENTRY)0)
#define SINGLE_LIST_ENTRY_MARKED        ((PSINGLE_LIST_ENTRY)1)


//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef enum _ETW_NOTIFICATION_TYPE
{
  EtwNotificationTypeNoReply = 1,
  EtwNotificationTypeLegacyEnable = 2,
  EtwNotificationTypeEnable = 3,
  EtwNotificationTypePrivateLogger = 4,
  EtwNotificationTypePerflib = 5,
  EtwNotificationTypeAudio = 6,
  EtwNotificationTypeSession = 7,
  EtwNotificationTypeReserved = 8,
  EtwNotificationTypeCredentialUI = 9,
  EtwNotificationTypeInProcSession = 10,
  EtwNotificationTypeMax = 11,
} ETW_NOTIFICATION_TYPE;

typedef enum _ETW_BUFFER_STATE
{
  EtwBufferStateFree = 0,
  EtwBufferStateGeneralLogging = 1,
  EtwBufferStateCSwitch = 2,
  EtwBufferStateFlush = 3,
  EtwBufferStatePendingCompression = 4,
  EtwBufferStateCompressed = 5,
  EtwBufferStatePlaceholder = 6,
  EtwBufferStateMaximum = 7,
} ETW_BUFFER_STATE;

typedef enum _ETW_FUNCTION_CODE
{
  EtwFunctionStartTrace = 1,
  EtwFunctionStopTrace = 2,
  EtwFunctionQueryTrace = 3,
  EtwFunctionUpdateTrace = 4,
  EtwFunctionFlushTrace = 5,
  EtwFunctionIncrementTraceFile = 6,

  EtwFunctionRealtimeConnect = 11,
  EtwFunctionWdiDispatchControl = 13,
  EtwFunctionRealtimeDisconnectConsumerByHandle = 14,
  EtwFunctionReceiveNotification = 16,
  EtwFunctionTraceEnableGuid = 17, // EtwTraceNotifyGuid
  EtwFunctionSendReplyDataBlock = 18,
  EtwFunctionReceiveReplyDataBlock = 19,
  EtwFunctionWdiUpdateSem = 20,
  EtwFunctionGetTraceGuidList = 21,
  EtwFunctionGetTraceGuidInfo = 22,
  EtwFunctionEnumerateTraceGuids = 23,
  // EtwFunction??? = 24,
  EtwFunctionQueryReferenceTime = 25,
  EtwFunctionTrackProviderBinary = 26,
  EtwFunctionAddNotificationEvent = 27,
  EtwFunctionUpdateDisallowList = 28,
  EtwFunctionUseDescriptorTypeUm = 31,
  EtwFunctionGetTraceGroupList = 32,
  EtwFunctionGetTraceGroupInfo = 33,
  EtwFunctionGetDisallowList = 34,
  EtwFunctionSetCompressionSettings = 35,
  EtwFunctionGetCompressionSettings = 36,
  EtwFunctionUpdatePeriodicCaptureState = 37,
  EtwFunctionGetPrivateSessionTraceHandle = 38,
  EtwFunctionRegisterPrivateSession = 39,
  EtwFunctionQuerySessionDemuxObject = 40,
  EtwFunctionSetProviderBinaryTracking = 41,
} ETW_FUNCTION_CODE;

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _WMI_LOGGER_INFORMATION
{
  WNODE_HEADER Wnode;
  ULONG BufferSize;
  ULONG MinimumBuffers;
  ULONG MaximumBuffers;
  ULONG MaximumFileSize;
  ULONG LogFileMode;
  ULONG FlushTimer;
  ULONG EnableFlags;
  union
  {
    LONG AgeLimit;
    LONG FlushThreshold;
  };
  ULONG Wow;
  LONG Padding_719;
  union
  {
    PVOID LogFileHandle;
    ULONGLONG LogFileHandle64;
  };
  union
  {
    ULONG NumberOfBuffers;
    ULONG InstanceCount;
  };
  union
  {
    ULONG FreeBuffers;
    ULONG InstanceId;
  };
  union
  {
    ULONG EventsLost;
    ULONG NumberOfProcessors;
  };
  ULONG BuffersWritten;
  union
  {
    ULONG LogBuffersLost;
    ULONG Flags;
  };
  ULONG RealTimeBuffersLost;
  union
  {
    PVOID LoggerThreadId;
    ULONGLONG LoggerThreadId64;
  };
  union
  {
    UNICODE_STRING LogFileName;
    STRING64 LogFileName64;
  };
  union
  {
    UNICODE_STRING LoggerName;
    STRING64 LoggerName64;
  };
  ULONG RealTimeConsumerCount;
  ULONG SpareUlong;
  union
  {
    union
    {
      PVOID LoggerExtension;
      ULONGLONG LoggerExtension64;
    };
  }  DUMMYUNIONNAME10;
} WMI_LOGGER_INFORMATION, *PWMI_LOGGER_INFORMATION;

typedef struct _ETWP_NOTIFICATION_HEADER
{
  ETW_NOTIFICATION_TYPE NotificationType;
  ULONG NotificationSize;
  LONG RefCount;
  UCHAR ReplyRequested;
  CHAR Padding_2083[3];
  union
  {
    ULONG ReplyIndex;
    ULONG Timeout;
  };
  union
  {
    ULONG ReplyCount;
    ULONG NotifyeeCount;
  };
  union
  {
    ULONGLONG ReplyHandle;
    PVOID ReplyObject;
    ULONG RegIndex;
  };
  ULONG TargetPID;
  ULONG SourcePID;
  GUID DestinationGuid;
  GUID SourceGuid;
} ETWP_NOTIFICATION_HEADER, *PETWP_NOTIFICATION_HEADER;

typedef struct _TRACE_ENABLE_CONTEXT
{
  USHORT LoggerId;
  UCHAR Level;
  UCHAR InternalFlag;
  ULONG EnableFlags;
} TRACE_ENABLE_CONTEXT, *PTRACE_ENABLE_CONTEXT;

typedef struct _ETW_ENABLE_NOTIFICATION_PACKET
{
  ETWP_NOTIFICATION_HEADER DataBlockHeader;
  TRACE_ENABLE_INFO EnableInfo;
  TRACE_ENABLE_CONTEXT LegacyEnableContext;
  ULONG LegacyProviderEnabled;
  ULONG FilterCount;
} ETW_ENABLE_NOTIFICATION_PACKET, *PETW_ENABLE_NOTIFICATION_PACKET;

typedef struct _ETW_REF_CLOCK
{
  LARGE_INTEGER StartTime;
  LARGE_INTEGER StartPerfClock;
} ETW_REF_CLOCK, *PETW_REF_CLOCK;

typedef struct _ETW_REALTIME_CONNECT_CONTEXT
{
  ULONG LoggerId;
  ULONG ReserveBufferSpaceSize;
  ULONGLONG ReserveBufferSpacePtr;
  ULONGLONG ReserveBufferSpaceBitMapPtr;
  ULONGLONG DisconnectEvent;
  ULONGLONG DataAvailableEvent;
  ULONGLONG BufferListHeadPtr;
  ULONGLONG BufferCountPtr;
  ULONGLONG EventsLostCountPtr;
  ULONGLONG BuffersLostCountPtr;
  ULONGLONG ConnectHandle;
  ETW_REF_CLOCK RealtimeReferenceTime;
} ETW_REALTIME_CONNECT_CONTEXT, *PETW_REALTIME_CONNECT_CONTEXT;

typedef struct _WMI_BUFFER_HEADER
{
  ULONG BufferSize;
  ULONG SavedOffset;
  volatile ULONG CurrentOffset;
  volatile LONG ReferenceCount;
  LARGE_INTEGER TimeStamp;
  LONGLONG SequenceNumber;
  union
  {
    struct
    {
      ULONGLONG ClockType : 3;
      ULONGLONG Frequency : 61;
    };
    SINGLE_LIST_ENTRY SlistEntry;
    struct _WMI_BUFFER_HEADER* NextBuffer;
  };
  ETW_BUFFER_CONTEXT ClientContext;
  ETW_BUFFER_STATE State;
  ULONG Offset;
  USHORT BufferFlag;
  USHORT BufferType;
  union
  {
    ULONG Padding1[4];
    ETW_REF_CLOCK ReferenceTime;
    LIST_ENTRY GlobalEntry;
    struct
    {
      PVOID Pointer0;
      PVOID Pointer1;
    };
  };
} WMI_BUFFER_HEADER, *PWMI_BUFFER_HEADER;

//////////////////////////////////////////////////////////////////////////
// Function type definitions.
//////////////////////////////////////////////////////////////////////////

typedef VOID (NTAPI * PLOGGER_CONNECT_CALLBACK)(
  _In_ ULONGLONG ConnectHandle
  );

//////////////////////////////////////////////////////////////////////////
// Variables.
//////////////////////////////////////////////////////////////////////////

//
// GUID:
//   {81ee4bad-e668-4fe3-b5a8-c4543a5742b7}
//

GUID ProviderGuid = {
  0x81ee4bad, 0xe668, 0x4fe3, { 0xb5, 0xa8, 0xc4, 0x54, 0x3a, 0x57, 0x42, 0xb7 }
};

WCHAR SessionName[] = L"EtwTestSession";

//////////////////////////////////////////////////////////////////////////
// Functions.
//////////////////////////////////////////////////////////////////////////

#pragma function(memset)      // error C2169: 'memset': intrinsic function, cannot be defined
extern "C"
void* __cdecl
memset(
  _Out_writes_bytes_all_(_Size) void*  _Dst,
  _In_                          int    _Val,
  _In_                          size_t _Size
  )
{
  unsigned char *_Ptr = (unsigned char*)_Dst;
  while (_Size-- > 0)
  {
    *_Ptr++ = _Val;
  }
  return _Dst;
}

NTSTATUS
LoggerWriteConsole(
  const char* Format,
  ...
  )
{
  using _vsnprintf_fn_t = int(__cdecl*)(
    char *buffer,
    size_t count,
    const char *format,
    va_list va
    );

  static _vsnprintf_fn_t _vsnprintf = nullptr;

  if (_vsnprintf == nullptr)
  {
    ANSI_STRING RoutineName;
    RtlInitAnsiString(&RoutineName, (PSTR)"_vsnprintf");

    UNICODE_STRING NtdllPath;
    RtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll");

    HANDLE NtdllHandle;
    LdrGetDllHandle(NULL, 0, &NtdllPath, &NtdllHandle);
    LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&_vsnprintf);
  }

  char Buffer[0x4000];

  va_list VaList;
  va_start(VaList, Format);
  int Length = _vsnprintf(Buffer, sizeof(Buffer), Format, VaList);
  va_end(VaList);

  IO_STATUS_BLOCK IoStatusBlock;
  return NtWriteFile(NtCurrentPeb()->ProcessParameters->StandardOutput,
                     NULL,
                     NULL,
                     NULL,
                     &IoStatusBlock,
                     Buffer,
                     Length,
                     NULL,
                     NULL);
}

NTSTATUS
NTAPI
LoggerInitialize(
  _Out_ PWMI_LOGGER_INFORMATION* WmiLoggerInformation,
  _In_ PWCHAR WmiSessionName
  )
{
  ULONG WmiLoggerSize = sizeof(WMI_LOGGER_INFORMATION) + 0x1000;
  PWMI_LOGGER_INFORMATION WmiLogger;

  WmiLogger = (PWMI_LOGGER_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), 0, WmiLoggerSize);
  RtlZeroMemory(WmiLogger, WmiLoggerSize);

  if (WmiLogger == NULL)
  {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  WmiLogger->Wnode.BufferSize = WmiLoggerSize;
  WmiLogger->Wnode.ClientContext = EVENT_TRACE_CLOCK_PERFCOUNTER;
  WmiLogger->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  WmiLogger->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  WmiLogger->LoggerName.Buffer = (PWCHAR)((ULONG_PTR)WmiLogger + sizeof(WMI_LOGGER_INFORMATION));
  WmiLogger->LoggerName.Length = 0;
  WmiLogger->LoggerName.MaximumLength = (USHORT)(WmiLoggerSize - sizeof(WMI_LOGGER_INFORMATION));
  RtlInitUnicodeString(&WmiLogger->LoggerName, WmiSessionName);

  *WmiLoggerInformation = WmiLogger;

  return STATUS_SUCCESS;
}

VOID
NTAPI
LoggerDestroy(
  _In_ PWMI_LOGGER_INFORMATION WmiLoggerInformation
  )
{
  RtlFreeHeap(RtlProcessHeap(), 0, WmiLoggerInformation);
}

NTSTATUS
NTAPI
LoggerStart(
  _In_ PWMI_LOGGER_INFORMATION WmiLoggerInformation
  )
{
  ULONG ReturnLength;
  return NtTraceControl(EtwFunctionStartTrace,
                        WmiLoggerInformation,
                        WmiLoggerInformation->Wnode.BufferSize,
                        WmiLoggerInformation,
                        WmiLoggerInformation->Wnode.BufferSize,
                        &ReturnLength);
}

NTSTATUS
NTAPI
LoggerStop(
  _In_ PWMI_LOGGER_INFORMATION WmiLoggerInformation
  )
{
  ULONG ReturnLength;
  return NtTraceControl(EtwFunctionStopTrace,
                        WmiLoggerInformation,
                        WmiLoggerInformation->Wnode.BufferSize,
                        WmiLoggerInformation,
                        WmiLoggerInformation->Wnode.BufferSize,
                        &ReturnLength);
}

NTSTATUS
NTAPI
LoggerEnable(
  _In_ PWMI_LOGGER_INFORMATION WmiLoggerInformation,
  _In_ PGUID ProviderGuid
  )
{
  ETW_ENABLE_NOTIFICATION_PACKET EtwNotificationPacket{};
  EtwNotificationPacket.DataBlockHeader.NotificationType = EtwNotificationTypeEnable;
  EtwNotificationPacket.DataBlockHeader.NotificationSize = sizeof(EtwNotificationPacket);
  EtwNotificationPacket.DataBlockHeader.RegIndex = 0xffffffff;
  EtwNotificationPacket.DataBlockHeader.SourcePID = (ULONG)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess;
  EtwNotificationPacket.DataBlockHeader.DestinationGuid = *ProviderGuid;
  EtwNotificationPacket.EnableInfo.IsEnabled = 1;
  EtwNotificationPacket.EnableInfo.LoggerId = ETW_SESSION_HANDLE(WmiLoggerInformation);

  ULONG ReturnLength;
  return NtTraceControl(EtwFunctionTraceEnableGuid,
                        &EtwNotificationPacket,
                        EtwNotificationPacket.DataBlockHeader.NotificationSize,
                        &EtwNotificationPacket,
                        sizeof(EtwNotificationPacket.DataBlockHeader),
                        &ReturnLength);
}

NTSTATUS
NTAPI
LoggerProcessBuffer(
  _In_ PWMI_BUFFER_HEADER WmiBufferHeader,
  _In_ PEVENT_RECORD_CALLBACK EventRecordCallback
  )
{
  //
  // EventHeader is located right after WmiBufferHeader.
  //

  PEVENT_HEADER EventHeader = (PEVENT_HEADER)(WmiBufferHeader + 1);

  //
  // Skip content of the "WmiBufferHeader".
  //

  ULONG CurrentOffset = sizeof(WMI_BUFFER_HEADER);

  while (CurrentOffset < WmiBufferHeader->Offset)
  {
    //
    // Process user data.
    //

    ULONGLONG UserData        = (ULONGLONG)(EventHeader + 1);
    ULONGLONG UserDataLength  = (ULONGLONG)(EventHeader)
                                + EventHeader->Size
                                - UserData;

    //
    // Process extended data (if present).
    //

    PEVENT_HEADER_EXTENDED_DATA_ITEM ExtendedData = NULL;
    USHORT ExtendedDataSize = 0;

    if (EventHeader->Flags & EVENT_HEADER_FLAG_EXTENDED_INFO)
    {
      ExtendedData     = (PEVENT_HEADER_EXTENDED_DATA_ITEM)((PUCHAR)(EventHeader) + sizeof(EVENT_HEADER));
      ExtendedDataSize = ExtendedData->Reserved1;

      //
      // Extended data are located before the user data.
      //

      UserData        += ExtendedDataSize;
      UserDataLength  -= ExtendedDataSize;
    }

    //
    // Build an EVENT_RECORD structure.
    //

    EVENT_RECORD EventRecord;
    EventRecord.EventHeader       = *EventHeader;
    EventRecord.BufferContext     = WmiBufferHeader->ClientContext;
    EventRecord.ExtendedDataCount = 0; // TODO
    EventRecord.UserDataLength    = (USHORT)(UserDataLength);
    EventRecord.ExtendedData      = ExtendedData;
    EventRecord.UserData          = (PVOID)(UserData);
    EventRecord.UserContext       = NULL;

    EventRecordCallback(&EventRecord);

    //
    // Advance pointer to the next event.
    // Note that pointer MUST be 8-byte aligned (64-bit pointer)
    // even on Wow64 & 32-bit systems.
    //

    ULONG EventSizeAligned = ALIGN_UP_BY(EventHeader->Size, 8);
    EventHeader   = (PEVENT_HEADER)((PUCHAR)(EventHeader) + EventSizeAligned);
    CurrentOffset += EventSizeAligned;
  }

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
LoggerConnect(
  _In_ PWMI_LOGGER_INFORMATION WmiLoggerInformation,
  _In_ PEVENT_RECORD_CALLBACK EventRecordCallback,
  _In_ PLOGGER_CONNECT_CALLBACK ConnectCallback
  )
{
  //
  // Size of a single per-CPU buffer (64kb).
  //

  SIZE_T SingleBufferSize = 64 * 1024;

  //
  // Allocate memory buffer (NumberOfProcessors * SingleBufferSize).
  //

  PVOID MemoryBuffer;
  SIZE_T MemoryBufferSize = SingleBufferSize * NtCurrentPeb()->NumberOfProcessors;
  NtAllocateVirtualMemory(NtCurrentProcess(), &MemoryBuffer, 0, &MemoryBufferSize, MEM_COMMIT, PAGE_READWRITE);

  //
  // Allocate bitmap buffer.
  //

  PVOID BitmapBuffer;
  SIZE_T BitmapBufferSize = MemoryBufferSize;
  NtAllocateVirtualMemory(NtCurrentProcess(), &BitmapBuffer, 0, &BitmapBufferSize, MEM_COMMIT, PAGE_READWRITE);

  RTL_BITMAP Bitmap;
  RtlInitializeBitMap(&Bitmap, (PULONG)BitmapBuffer, (ULONG)BitmapBufferSize);

  //
  // Create 2 events:
  //   - one that is fired when data is available
  //   - one that is fired when context is disconnected
  //

  HANDLE DisconnectEvent;
  NtCreateEvent(&DisconnectEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);

  HANDLE DataAvailableEvent;
  NtCreateEvent(&DataAvailableEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);

  ULONGLONG BufferCount = 0;
  ULONGLONG EventsLostCount = 0;
  ULONGLONG BuffersLostCount = 0;
  SINGLE_LIST_ENTRY BufferListHead = { 0 };

  //
  // Create ETW realtime-connect context structure.
  //

  ETW_REALTIME_CONNECT_CONTEXT RealtimeConnect = { 0 };
  RealtimeConnect.LoggerId                    = (ULONG)(ETW_SESSION_HANDLE(WmiLoggerInformation));
  RealtimeConnect.ReserveBufferSpaceSize      = (ULONG)(MemoryBufferSize);
  RealtimeConnect.ReserveBufferSpacePtr       = (ULONGLONG)(MemoryBuffer);
  RealtimeConnect.ReserveBufferSpaceBitMapPtr = (ULONGLONG)(Bitmap.Buffer);
  RealtimeConnect.DisconnectEvent             = (ULONGLONG)(DisconnectEvent);
  RealtimeConnect.DataAvailableEvent          = (ULONGLONG)(DataAvailableEvent);
  RealtimeConnect.BufferListHeadPtr           = (ULONGLONG)(&BufferListHead);
  RealtimeConnect.BufferCountPtr              = (ULONGLONG)(&BufferCount);
  RealtimeConnect.EventsLostCountPtr          = (ULONGLONG)(&EventsLostCount);
  RealtimeConnect.BuffersLostCountPtr         = (ULONGLONG)(&BuffersLostCount);

  //
  // Register this process as a realtime consumer.
  //

  NTSTATUS Status;
  ULONG ReturnLength;
  Status = NtTraceControl(EtwFunctionRealtimeConnect,
                          &RealtimeConnect,
                          sizeof(RealtimeConnect),
                          &RealtimeConnect,
                          sizeof(RealtimeConnect),
                          &ReturnLength);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  //
  // Notify that the consumer has successfully connected.
  //

  if (ConnectCallback)
  {
    ConnectCallback(RealtimeConnect.ConnectHandle);
  }

  HANDLE Events[] = {
    DisconnectEvent,
    DataAvailableEvent
  };

  for (;;)
  {
    //
    // Wait until data is available (or until disconnect).
    //

    Status = NtWaitForMultipleObjects(RTL_NUMBER_OF(Events), Events, WaitAny, FALSE, NULL);

    if (!NT_SUCCESS(Status) || Status == STATUS_WAIT_0)
    {
      //
      // If error occurred (or if the consumer has been disconnected)
      // break the loop.
      //

      break;
    }

    do
    {
      PSINGLE_LIST_ENTRY CurrentBuffer = NULL;
      PSINGLE_LIST_ENTRY NextBuffer = NULL;
      PSINGLE_LIST_ENTRY PrevBuffer = NULL;

      if (CurrentBuffer = BufferListHead.Next)
      {
        BufferListHead.Next = SINGLE_LIST_ENTRY_MARKED;

        //
        // Reverse the single-linked list.
        //

        do
        {
          NextBuffer = CurrentBuffer->Next;
          CurrentBuffer->Next = PrevBuffer;
          PrevBuffer = CurrentBuffer;
          CurrentBuffer = NextBuffer;
        } while (NextBuffer && NextBuffer != SINGLE_LIST_ENTRY_MARKED);

        //
        // Traverse the reversed list.
        //

        while (PrevBuffer)
        {
          PWMI_BUFFER_HEADER WmiBufferHeader = CONTAINING_RECORD(PrevBuffer, WMI_BUFFER_HEADER, SlistEntry);

          PrevBuffer = PrevBuffer->Next;
          InterlockedDecrement(&BufferCount);

          LoggerProcessBuffer(WmiBufferHeader, EventRecordCallback);
        }
      }
    } while (
      InterlockedCompareExchangePointer((volatile PVOID*)&BufferListHead.Next,
                                        SINGLE_LIST_ENTRY_FREE,
                                        SINGLE_LIST_ENTRY_MARKED) != SINGLE_LIST_ENTRY_MARKED
      );
  }

  //
  // Cleanup.
  //

  NtFreeVirtualMemory(NtCurrentProcess(), &BitmapBuffer, &BitmapBufferSize, MEM_FREE);
  NtFreeVirtualMemory(NtCurrentProcess(), &MemoryBuffer, &MemoryBufferSize, MEM_FREE);

  NtClose(DisconnectEvent);
  NtClose(DataAvailableEvent);

  return Status;
}

NTSTATUS
NTAPI
LoggerDisconnect(
  _In_ ULONGLONG ConnectHandle
  )
{
  ULONG ReturnLength;
  return NtTraceControl(EtwFunctionRealtimeDisconnectConsumerByHandle,
                        &ConnectHandle,
                        sizeof(ConnectHandle),
                        NULL,
                        0,
                        &ReturnLength);
}

ULONGLONG LoggerConnectHandle;

NTSTATUS
NTAPI
LoggerProducerThreadRoutine(
  _In_ PVOID ThreadParameter
  )
{
  PWMI_LOGGER_INFORMATION WmiLoggerInformation = (PWMI_LOGGER_INFORMATION)(ThreadParameter);

  //
  // Register ETW provider.
  //

  REGHANDLE ProviderHandle;
  EtwEventRegister(&ProviderGuid, NULL, NULL, &ProviderHandle);

  WCHAR Message[] = L"Message 0";

  //
  // Log some messages.
  //

  LoggerWriteConsole("Producing some messages       ...\n");
  for (int i = 0; i < 10; i++)
  {
    EtwEventWriteString(ProviderHandle, 0, 0, Message);
    Message[RTL_NUMBER_OF(Message) - 2] += 1;
  }

  EtwEventUnregister(ProviderHandle);

  LoggerWriteConsole("Waiting 2s before disconnect  ...\n");

  LARGE_INTEGER Delay;
  Delay.QuadPart = -10 * 1000 * 2000; // 2000ms
  NtDelayExecution(FALSE, &Delay);

  LoggerDisconnect(LoggerConnectHandle);

  return STATUS_SUCCESS;
}

VOID
NTAPI
LoggerEventRecordCallback(
  _In_ PEVENT_RECORD EventRecord
  )
{
  LoggerWriteConsole("Data: '%S'\n", EventRecord->UserData);
}

VOID
NTAPI
LoggerConnectCallback(
  _In_ ULONGLONG ConnectHandle
  )
{
  LoggerConnectHandle = ConnectHandle;
}

void NtMain()
{
  NTSTATUS Status;
  PWMI_LOGGER_INFORMATION WmiLoggerInformation;

  LoggerWriteConsole("Initializing logger           ...");
  Status = LoggerInitialize(&WmiLoggerInformation, SessionName);
  LoggerWriteConsole(" Status = 0x%08x\n", Status);

  if (!NT_SUCCESS(Status))
  {
    return;
  }

  LoggerWriteConsole("Destroying previous sessions  ...");
  Status = LoggerStop(WmiLoggerInformation);
  LoggerWriteConsole(" Status = 0x%08x\n", Status);

  LoggerWriteConsole("Creating new session          ...");
  Status = LoggerStart(WmiLoggerInformation);
  LoggerWriteConsole(" Status = 0x%08x\n", Status);

  if (!NT_SUCCESS(Status))
  {
    return;
  }

  LoggerWriteConsole("Enabling new session          ...");
  Status = LoggerEnable(WmiLoggerInformation, &ProviderGuid);
  LoggerWriteConsole(" Status = 0x%08x\n", Status);

  if (!NT_SUCCESS(Status))
  {
    return;
  }

  LoggerWriteConsole("Starting producer thread      ...\n");
  RtlCreateUserThread(NtCurrentProcess(),
                      NULL,
                      FALSE,
                      0,
                      0,
                      0,
                      &LoggerProducerThreadRoutine,
                      WmiLoggerInformation,
                      NULL,
                      NULL);

  LoggerWriteConsole("Connecting consumer           ...\n");
  Status = LoggerConnect(WmiLoggerInformation,
                         &LoggerEventRecordCallback,
                         &LoggerConnectCallback);

  if (!NT_SUCCESS(Status))
  {
    LoggerWriteConsole(" Status = 0x%08x\n", Status);
    return;
  }

  LoggerWriteConsole("Consumer disconnected         ...\n");

  LoggerWriteConsole("Destroying session            ...");
  Status = LoggerStop(WmiLoggerInformation);
  LoggerWriteConsole(" Status = 0x%08x\n", Status);

  LoggerWriteConsole("Destroying logger             ...\n");
  LoggerDestroy(WmiLoggerInformation);
}
