#ifndef IMPORT_HUNTER_H
#define IMPORT_HUNTER_H

#include <ntddk.h>
#include <intrin.h>

#if defined(_MSC_VER)
#define IHUNTER_FORCEINLINE __forceinline
#elif defined(__GNUC__) && __GNUC__ > 3
#define IHUNTER_FORCEINLINE __attribute__((always_inline)) inline
#else
#define IHUNTER_FORCEINLINE inline
#endif

namespace import_hunter
{
    namespace detail
    {
        namespace std
        {
            template < class _Ty >
            struct remove_reference
            {
                using type = _Ty;
            };

            template < class _Ty >
            struct remove_reference< _Ty& >
            {
                using type = _Ty;
            };

            template <class _Ty>
            struct remove_reference< _Ty&& >
            {
                using type = _Ty;
            };

            template < class _Ty >
            using remove_reference_t = typename remove_reference< _Ty >::type;

            template < class _Ty >
            struct remove_const
            {
                using type = _Ty;
            };

            template < class _Ty >
            struct remove_const< const _Ty >
            {
                using type = _Ty;
            };

            template < class _Ty >
            using remove_const_t = typename remove_const< _Ty >::type;
        }

        typedef struct _IMAGE_DOS_HEADER
        {
            unsigned short e_magic;
            unsigned short e_cblp;
            unsigned short e_cp;
            unsigned short e_crlc;
            unsigned short e_cparhdr;
            unsigned short e_minalloc;
            unsigned short e_maxalloc; 
            unsigned short e_ss;
            unsigned short e_sp;
            unsigned short e_csum;
            unsigned short e_ip;
            unsigned short e_cs;
            unsigned short e_lfarlc;
            unsigned short e_ovno;
            unsigned short e_res[ 4 ];
            unsigned short e_oemid;
            unsigned short e_oeminfo;
            unsigned short e_res2[ 10 ];
            int e_lfanew;
        } IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;
            
            
        typedef struct _IMAGE_FILE_HEADER
        {
            unsigned short Machine;
            unsigned short NumberOfSections;
            unsigned int TimeDateStamp;
            unsigned int PointerToSymbolTable;
            unsigned int NumberOfSymbols;
            unsigned short SizeOfOptionalHeader;
            unsigned short Characteristics;
        } IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;
            
        typedef struct _IMAGE_DATA_DIRECTORY
        {
            unsigned int VirtualAddress;
            unsigned int Size;
        } IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;
            
        typedef struct _IMAGE_OPTIONAL_HEADER64
        {
            unsigned short Magic;
            unsigned char MajorLinkerVersion;
            unsigned char MinorLinkerVersion;
            unsigned int SizeOfCode;
            unsigned int SizeOfInitializedData;
            unsigned int SizeOfUninitializedData;
            unsigned int AddressOfEntryPoint;
            unsigned int BaseOfCode;
            unsigned long long ImageBase;
            unsigned int SectionAlignment;
            unsigned int FileAlignment;
            unsigned short MajorOperatingSystemVersion;
            unsigned short MinorOperatingSystemVersion;
            unsigned short MajorImageVersion;
            unsigned short MinorImageVersion;
            unsigned short MajorSubsystemVersion;
            unsigned short MinorSubsystemVersion;
            unsigned int Win32VersionValue;
            unsigned int SizeOfImage;
            unsigned int SizeOfHeaders;
            unsigned int CheckSum;
            unsigned short Subsystem;
            unsigned short DllCharacteristics;
            unsigned long long SizeOfStackReserve;
            unsigned long long SizeOfStackCommit;
            unsigned long long SizeOfHeapReserve;
            unsigned long long SizeOfHeapCommit;
            unsigned int LoaderFlags;
            unsigned int NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[ 16 ];
        } IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;
            
        typedef struct _IMAGE_NT_HEADERS64
        {
            unsigned int Signature;
            IMAGE_FILE_HEADER FileHeader;
            IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        } IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

        typedef struct _IMAGE_EXPORT_DIRECTORY
        {
            unsigned int Characteristics;
            unsigned int TimeDateStamp;
            unsigned short MajorVersion;
            unsigned short MinorVersion;
            unsigned int Name;
            unsigned int Base;
            unsigned int NumberOfFunctions;
            unsigned int NumberOfNames;
            unsigned int AddressOfFunctions;
            unsigned int AddressOfNames;
            unsigned int AddressOfNameOrdinals;
        } IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;
    }

    template < typename Type, Type Value >
    struct force_cx
    {
        constexpr static auto value = Value;
    };

    template< typename T >
    T IHUNTER_FORCEINLINE constexpr get_kernel_base( )
    {
        const auto idtbase =
            *reinterpret_cast< uint64_t* >( __readgsqword( 0x18 ) + 0x38 );

        const auto descriptor_0 =
            *reinterpret_cast< uint64_t* >( idtbase );

        const auto descriptor_1 =
            *reinterpret_cast< uint64_t* >( idtbase + 8 );

        const auto isr_base =
            ( ( descriptor_0 >> 32 ) & 0xFFFF0000 ) + ( descriptor_0 & 0xFFFF ) + ( descriptor_1 << 32 );
        
        auto align_base = isr_base & 0xFFFFFFFFFFFFF000;

        for ( ; ; align_base -= 0x1000 )
        {
            for ( auto* search_base = reinterpret_cast< uint8_t* >( align_base );
                search_base < reinterpret_cast< uint8_t* >( align_base ) + 0xFF9; search_base++ )
            {
                if ( search_base[ 0 ] == 0x48 &&
                    search_base[ 1 ] == 0x8D &&
                    search_base[ 2 ] == 0x1D &&
                    search_base[ 6 ] == 0xFF )
                {
                    const auto relative_offset =
                        *reinterpret_cast< int* >( &search_base[ 3 ] );
                    
                    const auto address =
                        reinterpret_cast< uint64_t >( search_base + relative_offset + 7 );

                    if ( ( address & 0xFFF ) == 0 )
                    {
                        if ( *reinterpret_cast< uint16_t* >( address ) != 0x5A4D )
                        {
                            continue;
                        }
                        return address;
                    }
                }
            }
        }
        return 0;
    }

    // make it unique
    template < typename T, typename Char >
    IHUNTER_FORCEINLINE constexpr T hash( const Char* str )
    {
        T val = 0x1CAF4EB71B3ULL;

        for ( size_t i = 0; str[ i ]; i++ )
        {
            T c = str[ i ];

            val ^= static_cast< T >( c );
            val ^= ( c * c ) << ( ( i + 1 ) % 8 );
            val ^= 0xCBF29CE484222325ULL;
            val *= i + 1;
        }
        return val;
    }

#define HASH(str) \
    (import_hunter::force_cx<uint64_t, import_hunter::hash<uint64_t, std::remove_const_t<std::remove_reference_t<decltype(*(str))>>>((str))>::value)

#define HASH_RTS(str) \
    (import_hunter::hash<uint64_t, std::remove_const_t<std::remove_reference_t<decltype(*(str))>>>((str)))
    
    template< typename T >
    IHUNTER_FORCEINLINE T find_kernel_export( uint64_t export_hash )
    {
        const auto kernel_base = get_kernel_base<uintptr_t>( );

        const auto dos_header = reinterpret_cast< detail::PIMAGE_DOS_HEADER >( kernel_base );
        const auto nt_headers = reinterpret_cast< detail::PIMAGE_NT_HEADERS64 >( kernel_base + dos_header->e_lfanew );

        const auto export_dir = reinterpret_cast< detail::PIMAGE_EXPORT_DIRECTORY >( kernel_base +
            nt_headers->OptionalHeader.DataDirectory[ 0 ].VirtualAddress );

        const auto address_of_functions =
            reinterpret_cast< DWORD* >( kernel_base + export_dir->AddressOfFunctions );

        const auto address_of_names =
            reinterpret_cast< DWORD* >( kernel_base + export_dir->AddressOfNames );

        const auto address_of_names_ordinals =
            reinterpret_cast< WORD* >( kernel_base + export_dir->AddressOfNameOrdinals );

        for ( uint32_t i = 0; i < export_dir->NumberOfNames; ++i )
        {
            const auto export_entry_name = ( char* )( kernel_base + address_of_names[ i ] );
            const auto export_entry_hash = HASH_RTS( export_entry_name );

            if ( export_hash == export_entry_hash )
            {
                return reinterpret_cast< ULONG64 >( kernel_base + address_of_functions[ address_of_names_ordinals[ i ] ] );
            }
        }
        return 0ULL;
    }
}

#define CALL(function) \
    ((decltype(&function))(import_hunter::find_kernel_export<ULONG64>(HASH(#function))))

#endif
