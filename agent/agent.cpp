#include "agent.h"


void on_load()
{
    __android_log_print(ANDROID_LOG_INFO, "agent", "agent started");
    __android_log_print(ANDROID_LOG_DEBUG, "agent", "hooking function '%s' at %x using relocs of type %u",
        SYMBOL_TO_HOOK, ORIGINAL_FUNCTION, RELOC_TYPE_TO_HOOK);
    int ret = dl_iterate_phdr(relocationTableHook, nullptr);
    __android_log_print(ANDROID_LOG_INFO, "agent", "agent finished: %d", ret);
}

int myOpen(const char* pathname, int flags, ...)
{
    int result;
    bool ignoreMode = true;
    mode_t mode = 0;
    const char* pathnameOrNull = (nullptr == pathname) ? "nullptr" : pathname;
    if (flags & O_CREAT || flags & O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (ignoreMode) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "myOpen called with: %s, %d", pathnameOrNull, flags);
        result = open(pathname, flags);
        __android_log_print(ANDROID_LOG_INFO, "agent", "myOpen result: %d", result);
    } else {
        __android_log_print(ANDROID_LOG_INFO, "agent", "myOpen called with: %s, %d, %d", pathnameOrNull, flags, mode);
        result = open(pathname, flags, mode);
        __android_log_print(ANDROID_LOG_INFO, "agent", "myOpen result: %d", result);
    }
    return result;
}

int relocationTableHook(dl_phdr_info* info, size_t size, void* data)
{
    if (nullptr == info->dlpi_name) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "skipping null so");
        return 0;
    }

    __android_log_print(ANDROID_LOG_INFO, "agent", "looking at so: %s at %x", info->dlpi_name, info->dlpi_addr);
    ElfW(Addr) dynSegment = 0;
    for (uint16_t i = 0; i < info->dlpi_phnum; i++) {
        if (PT_DYNAMIC == info->dlpi_phdr[i].p_type) {
            dynSegment = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
        }
    }

    if (0 == dynSegment) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "no PT_DYNAMIC segment found");
        return 0;
    }
    __android_log_print(ANDROID_LOG_DEBUG, "agent", "dynamic segment is at %x", dynSegment);
    ElfW(Dyn)* dynSection = (ElfW(Dyn)*)dynSegment;

    char* stringTable = nullptr;
    ElfW(Sym)* symbolTable = nullptr;
    /*nbucket = 0;
    nchain = 0;
    nbucket = 0;
    chain = 0;*/
    rel_t* pltRelTable = nullptr;
    rel_t* relTable = nullptr;
    uint8_t* androidRelTable = nullptr;
    ElfW(Xword) numOfPltRelEntries = 0;
    ElfW(Xword) numOfRelEntries = 0;
    ElfW(Xword) androidRelTableSize = 0;
    for (ElfW(Xword) i = 0; dynSection[i].d_tag != DT_NULL; i++) {
        switch(dynSection[i].d_tag) {
            case DT_STRTAB:
                stringTable = (char*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
                break;
            case DT_SYMTAB:
                symbolTable = (ElfW(Sym)*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
                break;
            case DT_JMPREL:
                pltRelTable = (rel_t*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                numOfPltRelEntries = dynSection[i].d_un.d_val / sizeof(rel_t);
                break;
            /*case DT_HASH:
                symbolTable = (ElfW(Sym)*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
                break;*/
#if defined(USE_RELA)
            case DT_PLTREL:
                if (dynSection[i].d_un.d_val != DT_RELA) {
                    __android_log_print(ANDROID_LOG_ERROR, "agent", "DT_PLTREL invalid value: %x", dynSection[i].d_un.d_val);
                }
                break;
            case DT_RELA:
                relTable = (rel_t*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
                break;
            case DT_RELASZ:
                numOfRelEntries = dynSection[i].d_un.d_val / sizeof(rel_t);
                break;
            case DT_ANDROID_RELA:
                androidRelTable = (uint8_t*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
                break;
            case DT_ANDROID_RELASZ:
                androidRelTableSize = dynSection[i].d_un.d_val;
                break;
#else // defined(USE_RELA)
            case DT_PLTREL:
                if (dynSection[i].d_un.d_val != DT_REL) {
                    __android_log_print(ANDROID_LOG_ERROR, "agent", "DT_PLTREL invalid value: %x", dynSection[i].d_un.d_val);
                }
                break;
            case DT_REL:
                relTable = (rel_t*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
                break;
            case DT_RELSZ:
                numOfRelEntries = dynSection[i].d_un.d_val / sizeof(rel_t);
                break;
            case DT_ANDROID_REL:
                androidRelTable = (uint8_t*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
                break;
            case DT_ANDROID_RELSZ:
                androidRelTableSize = dynSection[i].d_un.d_val;
                break;
#endif // defined(USE_RELA)
        }
    }
    __android_log_print(ANDROID_LOG_DEBUG, "agent", "stringTable: %x, symbolTable: %x, relTable: %x, androidRel: %x, pltRel: %x, numOfRelEntries: %u, androidRelSz: %u, numOfPltRelEntries: %u",
        (ElfW(Addr))stringTable, (ElfW(Addr))symbolTable, (ElfW(Addr))relTable, (ElfW(Addr))androidRelTable, (ElfW(Addr))pltRelTable, (ElfW(Addr))numOfRelEntries, (ElfW(Addr))androidRelTableSize, (ElfW(Addr))numOfPltRelEntries
    );
    if (nullptr == stringTable || nullptr == symbolTable) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "could not find stringTable and symbolTable in dynamic section");
        return 0;
    }
    if ((0 == numOfRelEntries || nullptr == relTable) && (0 == androidRelTableSize || nullptr == androidRelTable) && (0 == numOfPltRelEntries || nullptr == pltRelTable)) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "could not find relocation table");
        return 0;
    }

    /*if (relTable != nullptr) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "iterating rel table");
        size_t plainReplacements = iterRelTable(plain_reloc_iterator(relTable, numOfRelEntries), info->dlpi_addr, symbolTable, stringTable);
        if (plainReplacements < 0) {
            __android_log_print(ANDROID_LOG_ERROR, "agent", "error while iterating plain rel table: %d", plainReplacements);
            return 0;
        } else if (plainReplacements > 0) {
            __android_log_print(ANDROID_LOG_INFO, "agent", "SUCCESSFULLY MADE %u REPLACEMENTS", plainReplacements);
        }
    }

    if (androidRelTable != nullptr) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "iterating packed rel table");
        // check signature
        if (androidRelTableSize > 3 && androidRelTable[0] == 'A' && androidRelTable[1] == 'P' && androidRelTable[2] == 'S' && androidRelTable[3] == '2') {
            androidRelTable += 4;
            androidRelTableSize -= 4;
            size_t packedReplacements = iterRelTable(packed_reloc_iterator(
                sleb128_decoder(androidRelTable, androidRelTableSize)), info->dlpi_addr, symbolTable, stringTable);
            if (packedReplacements < 0) {
                __android_log_print(ANDROID_LOG_ERROR, "agent", "error while iterating packed rel table: %d", packedReplacements);
                return 0;
            } else if (packedReplacements > 0) {
                __android_log_print(ANDROID_LOG_INFO, "agent", "SUCCESSFULLY MADE %u REPLACEMENTS", packedReplacements);
            }
        } else {
            __android_log_print(ANDROID_LOG_ERROR, "agent", "packed rel table is invalid");
        }
    }*/

    if (pltRelTable != nullptr) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "iterating plt rel table");
        size_t pltReplacements = iterRelTable(plain_reloc_iterator(pltRelTable, numOfPltRelEntries), info->dlpi_addr, symbolTable, stringTable);
        if (pltReplacements < 0) {
            __android_log_print(ANDROID_LOG_ERROR, "agent", "error while iterating plt rel table: %d", pltReplacements);
            return 0;
        } else if (pltReplacements > 0) {
            __android_log_print(ANDROID_LOG_INFO, "agent", "SUCCESSFULLY MADE %u REPLACEMENTS", pltReplacements);
        }
    }

    return 0;
}


(ElfW(Addr)) align((ElfW(Addr)) addr, pagesize) {
    pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize)
    (x & ~(PAGESIZE-1))
}
