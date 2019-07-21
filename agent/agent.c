#include <android/log.h>
#include <link.h>
#include <string.h>

// ELFW macro copied from http://androidxref.com/5.0.0_r2/xref/bionic/linker/linker.h
#if defined(__LP64__)
#define ELFW(what) ELF64_ ## what
#else
#define ELFW(what) ELF32_ ## what
#endif

const char* SYMBOL_TO_HOOK = "open";
const ElfW(Addr) RELOC_TYPE_TO_HOOK = R_ARM_JUMP_SLOT;


int relocationTableHook(struct dl_phdr_info* info, size_t size, void* data);
void on_load(void) __attribute__((constructor));

void on_load(void)
{
    __android_log_print(ANDROID_LOG_INFO, "agent", "agent started");
    int ret = dl_iterate_phdr(relocationTableHook, NULL);
    __android_log_print(ANDROID_LOG_INFO, "agent", "agent finished: %d", ret);
}

int relocationTableHook(struct dl_phdr_info* info, size_t size, void* data)
{
    if (NULL == info->dlpi_name) {
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

    char* stringTable = 0;
    ElfW(Sym)* symbolTable = 0;
    ElfW(Rel)* relTable = 0;
    ElfW(Rela)* relaTable = 0;
    ElfW(Xword) numOfRelEntries = 0;
    ElfW(Xword) numOfRelaEntries = 0;
    for (ElfW(Xword) i = 0; dynSection[i].d_tag != DT_NULL; i++) {
        if (DT_STRTAB == dynSection[i].d_tag) {
            stringTable = (char*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
        } else if (DT_SYMTAB == dynSection[i].d_tag) {
            symbolTable = (ElfW(Sym)*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
        } else if (DT_RELA == dynSection[i].d_tag) {
            relaTable = (ElfW(Rela)*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
        } else if (DT_RELASZ == dynSection[i].d_tag) {
            numOfRelaEntries = dynSection[i].d_un.d_val / sizeof(ElfW(Rela));
        } else if (DT_REL == dynSection[i].d_tag) {
            relTable = (ElfW(Rel)*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
        } else if (DT_RELSZ == dynSection[i].d_tag) {
            numOfRelEntries = dynSection[i].d_un.d_val / sizeof(ElfW(Rel));
        }
    }
    __android_log_print(ANDROID_LOG_DEBUG, "agent", "stringTable: %x, symbolTable: %x, relTable: %x, relaTable: %x, numOfRelEntries: %u, numOfRelaEntries: %u",
        (ElfW(Addr))stringTable, (ElfW(Addr))symbolTable, (ElfW(Addr))relTable, (ElfW(Addr))relaTable, (ElfW(Addr))numOfRelEntries, (ElfW(Addr))numOfRelaEntries
    );
    if (0 == stringTable || 0 == symbolTable) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "could not find stringTable and symbolTable in dynamic section");
        return 0;
    }
    if ((0 == numOfRelEntries || 0 == relTable) && (0 == numOfRelaEntries || 0 == relaTable)) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "could not find relocation table");
        return 0;
    }
    if (relTable != 0) {
        for (ElfW(Xword) i = 0; i < numOfRelEntries; i++) {
            ElfW(Addr) relType = ELFW(R_TYPE)(relTable[i].r_info);
            ElfW(Sym)* symbol = &symbolTable[ELFW(R_SYM)(relTable[i].r_info)];
            if (symbol->st_name != 0) {
                char* symbolName = &stringTable[symbol->st_name];
                __android_log_print(ANDROID_LOG_DEBUG, "agent", "found reloc for %s", symbolName);
                if (0 == strcmp(symbolName, SYMBOL_TO_HOOK)) {  // RELOC_TYPE_TO_HOOK == relType &&
                    ElfW(Addr) addressToPatch = info->dlpi_addr + relTable[i].r_offset;
                    ElfW(Addr) symValue = symbol->st_value;
                    ElfW(Addr) symSize = symbol->st_size;
                    unsigned char symBind = ELFW(ST_BIND)(symbol->st_info);
                    unsigned char symType = ELFW(ST_TYPE)(symbol->st_info);
                    __android_log_print(ANDROID_LOG_DEBUG, "agent", "expected: %u", RELOC_TYPE_TO_HOOK);
                    __android_log_print(ANDROID_LOG_INFO, "agent",
                        "found relocation of type %u for %s at %x (value is %x). (symbol: value %x, size %x, bind %c, type %c)",
                        relType, symbolName, addressToPatch, *((ElfW(Addr)*)(addressToPatch)), symValue, symSize, symBind, symType
                    );
                }
            }
        }
    }
    return 0;
}
