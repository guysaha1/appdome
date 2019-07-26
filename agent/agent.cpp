#include "agent.h"

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#include <android/log.h>

#include <bionic/linker_relocs.h>


#if defined(USE_RELA)
constexpr auto DT_PLTREL_VALUE = DT_RELA;
#else // defined(USE_RELA)
constexpr auto DT_PLTREL_VALUE = DT_REL;
#endif // defined(USE_RELA)

const std::vector<std::string_view> MODULES_TO_IGNORE{ "/libagent.so", "/linker" };


extern "C" int myOpen(const char* pathname, int flags, ...)
{
    int result;
    bool ignoreMode = true;
    mode_t mode = 0;
    const char* pathnameOrNull = (nullptr == pathname) ? "nullptr" : pathname;
    if (flags & O_CREAT || flags & O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
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


void on_load()
{
    __android_log_print(ANDROID_LOG_INFO, "agent", "agent started");
    long pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize < 1) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "invalid pagesize: %ld, errno: %d", pagesize, errno);
        return;
    }
    HookInfo hookInfo{ "open", R_GENERIC_JUMP_SLOT, reinterpret_cast<ElfW(Addr)>(&myOpen), reinterpret_cast<ElfW(Addr)>(&open), pagesize };
    __android_log_print(ANDROID_LOG_DEBUG, "agent", "hooking function '%s' at %x using relocs of type %u",
        hookInfo.symbol.data(), hookInfo.original, hookInfo.relocType);
    int ret = dl_iterate_phdr(relocationTableHook, &hookInfo);
    __android_log_print(ANDROID_LOG_INFO, "agent", "agent finished: %d", ret);
}

int relocationTableHook(dl_phdr_info* info, size_t size, void* data)
{
    const HookInfo* hookInfo = reinterpret_cast<const HookInfo*>(data);
    RelocTableHook relocTableHook{ info };
    if (relocTableHook.shouldIgnoreModule(MODULES_TO_IGNORE)) {
        return 0;
    }

    if (!relocTableHook.parseDynamicSection()) {
        return 0;
    }

    size_t hooksPerformed = relocTableHook.performHook(hookInfo);
    __android_log_print(ANDROID_LOG_INFO, "agent", "%u hooks performed", hooksPerformed);
    return 0;
}


RelocTableHook::RelocTableHook(const dl_phdr_info* moduleInfo)
    : m_moduleName{}, m_loadBias{ moduleInfo->dlpi_addr }, m_phdrInfo{ moduleInfo },
        m_stringTable{}, m_symbolTable{ nullptr }, m_pltRel{ nullptr }, m_numOfPltRelEntries{ 0 }
{
    if (nullptr != moduleInfo->dlpi_name) {
        m_moduleName = { moduleInfo->dlpi_name };
        __android_log_print(ANDROID_LOG_INFO, "agent", "looking at module %s", m_moduleName.data());
    }
}

bool RelocTableHook::shouldIgnoreModule(const std::vector<std::string_view>& modulesToIgnore)
{
    if (m_moduleName.empty()) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "ignoring nameless module");
        return true;
    }
    for (const auto& moduleToIgnore : modulesToIgnore) {
        if (m_moduleName.size() >= moduleToIgnore.size()
                && m_moduleName.substr(m_moduleName.size() - moduleToIgnore.size()) == moduleToIgnore) {
            __android_log_print(ANDROID_LOG_INFO, "agent", "ignoring module %s", m_moduleName.data());
            return true;
        }
    }
    return false;
}

bool RelocTableHook::parseDynamicSection()
{
    ElfW(Addr) dynSegment = 0;
    for (uint16_t i = 0; i < m_phdrInfo->dlpi_phnum; i++) {
        const auto* programHeader = &m_phdrInfo->dlpi_phdr[i];
        if (PT_DYNAMIC == programHeader->p_type) {
            dynSegment = m_loadBias + programHeader->p_vaddr;
        }
    }

    if (0 == dynSegment) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "no PT_DYNAMIC segment found");
        return false;
    }
    __android_log_print(ANDROID_LOG_DEBUG, "agent", "dynamic segment is at %x", dynSegment);
    ElfW(Dyn)* dynSection = reinterpret_cast<ElfW(Dyn)*>(dynSegment);

    for (ElfW(Xword) i = 0; dynSection[i].d_tag != DT_NULL; i++) {
        switch(dynSection[i].d_tag) {
            case DT_STRTAB:
                m_stringTable = reinterpret_cast<char*>(m_loadBias + dynSection[i].d_un.d_ptr);
                break;
            case DT_SYMTAB:
                m_symbolTable = reinterpret_cast<ElfW(Sym)*>(m_loadBias + dynSection[i].d_un.d_ptr);
                break;
            case DT_JMPREL:
                m_pltRel = reinterpret_cast<rel_t*>(m_loadBias + dynSection[i].d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                m_numOfPltRelEntries = dynSection[i].d_un.d_val / sizeof(rel_t);
                break;
            /*case DT_HASH:
                break;*/
            case DT_PLTREL:
                if (dynSection[i].d_un.d_val != DT_PLTREL_VALUE) {
                    __android_log_print(ANDROID_LOG_ERROR, "agent", "DT_PLTREL invalid value: %x", dynSection[i].d_un.d_val);
                }
                break;
        }
    }
    __android_log_print(ANDROID_LOG_DEBUG, "agent", "stringTable: %x, symbolTable: %x, pltRel: %x, numOfPltRelEntries: %llu",
        reinterpret_cast<ElfW(Addr)>(m_stringTable), reinterpret_cast<ElfW(Addr)>(m_symbolTable), reinterpret_cast<ElfW(Addr)>(m_pltRel), m_numOfPltRelEntries
    );
    if (nullptr == m_stringTable || nullptr == m_symbolTable) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "could not find stringTable and symbolTable in dynamic section");
        return false;
    }
    if (0 == m_numOfPltRelEntries || nullptr == m_pltRel) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "could not find pltRel table");
        return false;
    }

    return true;
}

size_t RelocTableHook::performHook(const HookInfo* hookInfo)
{
    size_t replacements = 0;
    for (ElfW(Xword) i = 0; i < m_numOfPltRelEntries; ++i) {
        const auto* rel = &m_pltRel[i];

        ElfW(Word) relType = ELFW(R_TYPE)(rel->r_info);
        ElfW(Word) symIndex = ELFW(R_SYM)(rel->r_info);
        if (0 == symIndex) {
            __android_log_print(ANDROID_LOG_DEBUG, "agent", "skipping relocation without symbol (type=%u)", relType);
            continue;
        }

        ElfW(Addr) addressToPatch = static_cast<ElfW(Addr)>(rel->r_offset + m_loadBias);
        const auto* symbol = &m_symbolTable[symIndex];

        if (0 == symbol->st_name) {
            __android_log_print(ANDROID_LOG_DEBUG, "agent", "skipping relocation with nameless symbol (type=%u, addr=%x)", relType, addressToPatch);
            continue;
        }
        const std::string_view symbolName{&m_stringTable[symbol->st_name]};

        if (hookInfo->relocType == relType && hookInfo->symbol == symbolName) {
            __android_log_print(ANDROID_LOG_INFO, "agent", "found relocation of type %u for %s at %x", relType, symbolName.data(), addressToPatch);
            ElfW(Addr) originalValue = *reinterpret_cast<ElfW(Addr)*>(addressToPatch);
            if (originalValue != hookInfo->original) {
                __android_log_print(ANDROID_LOG_ERROR, "agent", "unexpected original value to hook: %x", originalValue);
                continue;
            }
            if (!changeProtection(addressToPatch, hookInfo->pagesize, sizeof(ElfW(Addr)), PROT_READ | PROT_WRITE)) {
                continue;
            }
            *reinterpret_cast<ElfW(Addr)*>(addressToPatch) = hookInfo->hook;
            changeProtection(addressToPatch, hookInfo->pagesize, sizeof(ElfW(Addr)), PROT_READ | PROT_EXEC);
            __android_log_print(ANDROID_LOG_INFO, "agent", "performed hook!");
            replacements += 1;
        }
    }
    return replacements;
}


ElfW(Addr) align(ElfW(Addr) addr, long pagesize) {
    return addr & ~(pagesize - 1);
}

bool changeProtection(ElfW(Addr) addr, long pagesize, size_t len, int protection) {
    const auto aligned = align(addr, pagesize);
    size_t totalLen = addr - aligned + len;
    int ret = mprotect(reinterpret_cast<void*>(addr), totalLen, PROT_READ | PROT_WRITE);
    if (0 != ret) {
        __android_log_print(ANDROID_LOG_ERROR, "agent", "mprotect failed on addr %x with prot %d: %d. errno: %d", aligned, protection, ret, errno);
        return false;
    }
    return true;
}
