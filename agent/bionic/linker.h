#include <link.h>

// copied from http://androidxref.com/9.0.0_r3/xref/bionic/linker/linker.h
#if defined(__LP64__)
#define ELFW(what) ELF64_ ## what
#else
#define ELFW(what) ELF32_ ## what
#endif

// copied from http://androidxref.com/9.0.0_r3/xref/bionic/linker/linker_common_types.h
// Android uses RELA for aarch64 and x86_64. mips64 still uses REL.
#if defined(__aarch64__) || defined(__x86_64__)
#define USE_RELA 1
#endif

// copied from http://androidxref.com/9.0.0_r3/xref/bionic/linker/linker_reloc_iterators.h
#if defined(USE_RELA)
  typedef ElfW(Rela) rel_t;
#else
  typedef ElfW(Rel) rel_t;
#endif

// copied from http://androidxref.com/9.0.0_r3/xref/bionic/libc/private/bionic_macros.h
#if !defined(DISALLOW_COPY_AND_ASSIGN)
// DISALLOW_COPY_AND_ASSIGN disallows the copy and operator= functions.
// It goes in the private: declarations in a class.
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&) = delete;      \
  void operator=(const TypeName&) = delete
#endif  // !defined(DISALLOW_COPY_AND_ASSIGN)
