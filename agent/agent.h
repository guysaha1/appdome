#include <string_view>

#include <fcntl.h>

#include <bionic/linker_reloc_iterators.h>
#include <bionic/linker_sleb128.h>
#include <bionic/linker_relocs.h>


using namespace std::literals;

const auto SYMBOL_TO_HOOK = "open"sv;
const ElfW(Addr) RELOC_TYPE_TO_HOOK = R_GENERIC_JUMP_SLOT;
const ElfW(Addr) ORIGINAL_FUNCTION = &open;
const ElfW(Addr) REPLACEMENT_FUNCTION = &myOpen;
std::array<std::string_view, 2> MODULES_TO_IGNORE{"/libagent.so"sv, "/linker"sv};


void on_load() __attribute__((constructor));
int relocationTableHook(struct dl_phdr_info* info, size_t size, void* data);
int myOpen(const char* pathname, int flags, ...);
template <typename RelocIter> size_t iterRelTable(RelocIter&& relIter, ElfW(Addr) loadBias, ElfW(Sym)* symbolTable, char* stringTable);


template <typename RelocIter>
size_t iterRelTable(RelocIter&& relIter, ElfW(Addr) loadBias, ElfW(Sym)* symbolTable, char* stringTable)
{
    size_t replacements = 0;
    for (size_t idx = 0; relIter.has_next(); ++idx) {
        const auto rel = relIter.next();
        if (nullptr == rel) {
          return -1 - replacements;
        }

        ElfW(Word) relType = ELFW(R_TYPE)(rel->r_info);
        ElfW(Word) symIndex = ELFW(R_SYM)(rel->r_info);
        if (0 == symIndex) {
            __android_log_print(ANDROID_LOG_DEBUG, "agent", "skipping relocation without symbol (type=%u)", relType);
            continue;
        }

        ElfW(Addr) addressToPatch = static_cast<ElfW(Addr)>(rel->r_offset + loadBias);
        ElfW(Sym)* symbol = &symbolTable[symIndex];

        if (0 == symbol->st_name) {
            __android_log_print(ANDROID_LOG_DEBUG, "agent", "skipping relocation with nameless symbol (type=%u, addr=%x)", relType, addressToPatch);
        } else {
            if (RELOC_TYPE_TO_HOOK == relType && SYMBOL_TO_HOOK == symbolName) {
                char* symbolName = &stringTable[symbol->st_name];
                ElfW(Addr) symValue = symbol->st_value;
                ElfW(Addr) symSize = symbol->st_size;
                unsigned char symBind = ELFW(ST_BIND)(symbol->st_info);
                unsigned char symType = ELFW(ST_TYPE)(symbol->st_info);
                ElfW(Addr) originalValue = *((ElfW(Addr)*)(addressToPatch));
                __android_log_print(ANDROID_LOG_DEBUG, "agent",
                    "found relocation of type %u for %s at %x (value is %x). (symbol: value %x, size %x, bind %hhx, type %hhx)",
                    relType, symbolName, addressToPatch, originalValue, symValue, symSize, symBind, symType
                );
                if (originalValue != ORIGINAL_FUNCTION) {
                    __android_log_print(ANDROID_LOG_ERROR, "agent", "unexpected original value at reloc offset: %x", originalValue);
                    continue;
                }
                *((ElfW(Addr)*)(addressToPatch)) = REPLACEMENT_FUNCTION;
                replacements += 1;
            }
        }
    }
    return replacements;
}
