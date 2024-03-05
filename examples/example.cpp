#include "import_hunter.h"

NTSTATUS DriverEntry( PDRIVER_OBJECT objcet, PUNICODE_STRING registry )
{
    UNREFERENCED_PARAMETER( driver );
    UNREFERENCED_PARAMETER( registry );

    UNICODE_STRING ustr;
    CALL( RtlInitUnicodeString )( &ustr, L"Hello World!\n" );

    CALL( DbgPrintEx )( 0, 0, "%wZ\n", ustr );
    
    return STATUS_SUCCESS;
}
