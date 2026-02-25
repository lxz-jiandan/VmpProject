/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef _UAPI_LINUX_ELF_H
#define _UAPI_LINUX_ELF_H

// 说明：
// 本文件是 ELF ABI 常量/结构定义汇总，主要用于解析与校验，不承载业务逻辑。
// 这里保留与 Linux UAPI 对齐的命名，便于与系统资料互相对照。

// Basic types
// 与 Linux UAPI 对齐的基础整数类型别名。
typedef signed char __s8;
typedef unsigned char __u8;
typedef signed short __s16;
typedef unsigned short __u16;
typedef signed int __s32;
typedef unsigned int __u32;
typedef signed long long __s64;
typedef unsigned long long __u64;

// ELF machine types (from elf-em.h)
// e_machine 常量：标识目标 CPU 架构。
#define EM_NONE 0
#define EM_M32 1
#define EM_SPARC 2
#define EM_386 3
#define EM_68K 4
#define EM_88K 5
#define EM_486 6
#define EM_860 7
#define EM_MIPS 8
#define EM_MIPS_RS3_LE 10
#define EM_MIPS_RS4_BE 10
#define EM_PARISC 15
#define EM_SPARC32PLUS 18
#define EM_PPC 20
#define EM_PPC64 21
#define EM_SPU 23
#define EM_ARM 40
#define EM_SH 42
#define EM_SPARCV9 43
#define EM_H8_300 46
#define EM_IA_64 50
#define EM_X86_64 62
#define EM_S390 22
#define EM_CRIS 76
#define EM_M32R 88
#define EM_MN10300 89
#define EM_OPENRISC 92
#define EM_ARCOMPACT 93
#define EM_XTENSA 94
#define EM_BLACKFIN 106
#define EM_UNICORE 110
#define EM_ALTERA_NIOS2 113
#define EM_TI_C6000 140
#define EM_HEXAGON 164
#define EM_NDS32 167
#define EM_AARCH64 183
#define EM_TILEPRO 188
#define EM_MICROBLAZE 189
#define EM_TILEGX 191
#define EM_ARCV2 195
#define EM_RISCV 243
#define EM_BPF 247
#define EM_CSKY 252
#define EM_FRV 0x5441
#define EM_ALPHA 0x9026
#define EM_CYGNUS_M32R 0x9041
#define EM_S390_OLD 0xA390
#define EM_CYGNUS_MN10300 0xbeef

// DT_GNU_HASH definition
// GNU Hash 动态标记（用于符号快速查找）。
#define DT_GNU_HASH 0x6ffffef5

// PT_GNU_* definitions
// GNU 扩展 Program Header 类型。
#define PT_GNU_RELRO 0x6474e552
// 32/64 位 ELF 基础地址与偏移类型。
typedef __u32 Elf32_Addr;
typedef __u16 Elf32_Half;
typedef __u32 Elf32_Off;
typedef __s32 Elf32_Sword;
typedef __u32 Elf32_Word;
typedef __u64 Elf64_Addr;
typedef __u16 Elf64_Half;
typedef __s16 Elf64_SHalf;
typedef __u64 Elf64_Off;
typedef __s32 Elf64_Sword;
typedef __u32 Elf64_Word;
typedef __u64 Elf64_Xword;
typedef __s64 Elf64_Sxword;
// Program Header 类型定义。
// p_type 取值：段加载与解释行为。
#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_SHLIB 5
#define PT_PHDR 6
#define PT_TLS 7
#define PT_LOOS 0x60000000
#define PT_HIOS 0x6fffffff
#define PT_LOPROC 0x70000000
#define PT_HIPROC 0x7fffffff
#define PT_GNU_EH_FRAME 0x6474e550
#define PT_GNU_STACK (PT_LOOS + 0x474e551)
#define PN_XNUM 0xffff
// ELF 文件类型定义。
// e_type 取值：可重定位、可执行、共享库等。
#define ET_NONE 0
#define ET_REL 1
#define ET_EXEC 2
#define ET_DYN 3
#define ET_CORE 4
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff
// Dynamic Table 的常用 tag 定义。
// d_tag 取值：描述动态链接器所需元信息。
#define DT_NULL 0
#define DT_NEEDED 1
#define DT_PLTRELSZ 2
#define DT_PLTGOT 3
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
#define DT_STRSZ 10
#define DT_SYMENT 11
#define DT_INIT 12
#define DT_FINI 13
#define DT_SONAME 14
#define DT_RPATH 15
#define DT_SYMBOLIC 16
#define DT_REL 17
#define DT_RELSZ 18
#define DT_RELENT 19
#define DT_PLTREL 20
#define DT_DEBUG 21
#define DT_TEXTREL 22
#define DT_JMPREL 23
#define DT_ENCODING 32
#define OLD_DT_LOOS 0x60000000
#define DT_LOOS 0x6000000d
#define DT_HIOS 0x6ffff000
#define DT_VALRNGLO 0x6ffffd00
#define DT_VALRNGHI 0x6ffffdff
#define DT_ADDRRNGLO 0x6ffffe00
#define DT_ADDRRNGHI 0x6ffffeff
#define DT_VERSYM 0x6ffffff0
#define DT_RELACOUNT 0x6ffffff9
#define DT_RELCOUNT 0x6ffffffa
#define DT_FLAGS_1 0x6ffffffb
#define DT_VERDEF 0x6ffffffc
#define DT_VERDEFNUM 0x6ffffffd
#define DT_VERNEED 0x6ffffffe
#define DT_VERNEEDNUM 0x6fffffff
#define OLD_DT_HIOS 0x6fffffff
#define DT_LOPROC 0x70000000
#define DT_HIPROC 0x7fffffff
// 符号绑定/类型定义。
// st_info 的 bind/type 编码规则。
#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STB_WEAK 2
#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4
#define STT_COMMON 5
#define STT_TLS 6
#define ELF_ST_BIND(x) ((x) >> 4)
#define ELF_ST_TYPE(x) (((unsigned int) x) & 0xf)
#define ELF32_ST_BIND(x) ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x) ELF_ST_TYPE(x)
#define ELF64_ST_BIND(x) ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x) ELF_ST_TYPE(x)
// 动态段条目结构（32 位）。
// Elf32_Dyn: d_tag + d_un(d_val/d_ptr)。
typedef struct dynamic {
  // 动态标签（DT_*）。
  Elf32_Sword d_tag;
  // 动态标签对应的值或地址。
  union {
    // 数值型参数（例如大小、计数）。
    Elf32_Sword d_val;
    // 指针型参数（例如表地址）。
    Elf32_Addr d_ptr;
  } d_un;
} Elf32_Dyn;
// 动态段条目结构（64 位）。
typedef struct {
  // 动态标签（DT_*）。
  Elf64_Sxword d_tag;
  // 动态标签对应的值或地址。
  union {
    // 数值型参数（例如大小、计数）。
    Elf64_Xword d_val;
    // 指针型参数（例如表地址）。
    Elf64_Addr d_ptr;
  } d_un;
} Elf64_Dyn;
#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)
#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)
// REL 重定位结构（无 addend）。
// 运行时由目标地址与符号信息共同决定最终值。
typedef struct elf32_rel {
  // 重定位目标地址（相对装载基址）。
  Elf32_Addr r_offset;
  // 符号索引 + 重定位类型打包值。
  Elf32_Word r_info;
} Elf32_Rel;
typedef struct elf64_rel {
  // 重定位目标地址（相对装载基址）。
  Elf64_Addr r_offset;
  // 符号索引 + 重定位类型打包值。
  Elf64_Xword r_info;
} Elf64_Rel;
// RELA 重定位结构（带 addend）。
typedef struct elf32_rela {
  // 重定位目标地址（相对装载基址）。
  Elf32_Addr r_offset;
  // 符号索引 + 重定位类型打包值。
  Elf32_Word r_info;
  // 显式加数。
  Elf32_Sword r_addend;
} Elf32_Rela;
typedef struct elf64_rela {
  // 重定位目标地址（相对装载基址）。
  Elf64_Addr r_offset;
  // 符号索引 + 重定位类型打包值。
  Elf64_Xword r_info;
  // 显式加数。
  Elf64_Sxword r_addend;
} Elf64_Rela;
// 符号表项结构（32 位）。
// st_name/st_value/st_size 等字段用于符号解析。
typedef struct elf32_sym {
  // 符号名在字符串表中的偏移。
  Elf32_Word st_name;
  // 符号值（地址或绝对值）。
  Elf32_Addr st_value;
  // 符号大小（字节）。
  Elf32_Word st_size;
  // 绑定 + 类型打包字段。
  unsigned char st_info;
  // 可见性与保留位。
  unsigned char st_other;
  // 所在节索引（SHN_*）。
  Elf32_Half st_shndx;
} Elf32_Sym;
// 符号表项结构（64 位）。
typedef struct elf64_sym {
  // 符号名在字符串表中的偏移。
  Elf64_Word st_name;
  // 绑定 + 类型打包字段。
  unsigned char st_info;
  // 可见性与保留位。
  unsigned char st_other;
  // 所在节索引（SHN_*）。
  Elf64_Half st_shndx;
  // 符号值（地址或绝对值）。
  Elf64_Addr st_value;
  // 符号大小（字节）。
  Elf64_Xword st_size;
} Elf64_Sym;
// ELF 头 e_ident 数组长度。
// e_ident 固定 16 字节。
#define EI_NIDENT 16
// ELF Header 结构（32 位）。
typedef struct elf32_hdr {
  // ELF 固定标识区（魔数、位宽、字节序等）。
  unsigned char e_ident[EI_NIDENT];
  // 文件类型（ET_*）。
  Elf32_Half e_type;
  // 目标架构（EM_*）。
  Elf32_Half e_machine;
  // ELF 版本。
  Elf32_Word e_version;
  // 入口虚拟地址。
  Elf32_Addr e_entry;
  // 程序头表文件偏移。
  Elf32_Off e_phoff;
  // 节头表文件偏移。
  Elf32_Off e_shoff;
  // 架构相关标志。
  Elf32_Word e_flags;
  // ELF 头大小。
  Elf32_Half e_ehsize;
  // 程序头单项大小。
  Elf32_Half e_phentsize;
  // 程序头项数量。
  Elf32_Half e_phnum;
  // 节头单项大小。
  Elf32_Half e_shentsize;
  // 节头项数量。
  Elf32_Half e_shnum;
  // 节名字符串表节索引。
  Elf32_Half e_shstrndx;
} Elf32_Ehdr;
// ELF Header 结构（64 位）。
typedef struct elf64_hdr {
  // ELF 固定标识区（魔数、位宽、字节序等）。
  unsigned char e_ident[EI_NIDENT];
  // 文件类型（ET_*）。
  Elf64_Half e_type;
  // 目标架构（EM_*）。
  Elf64_Half e_machine;
  // ELF 版本。
  Elf64_Word e_version;
  // 入口虚拟地址。
  Elf64_Addr e_entry;
  // 程序头表文件偏移。
  Elf64_Off e_phoff;
  // 节头表文件偏移。
  Elf64_Off e_shoff;
  // 架构相关标志。
  Elf64_Word e_flags;
  // ELF 头大小。
  Elf64_Half e_ehsize;
  // 程序头单项大小。
  Elf64_Half e_phentsize;
  // 程序头项数量。
  Elf64_Half e_phnum;
  // 节头单项大小。
  Elf64_Half e_shentsize;
  // 节头项数量。
  Elf64_Half e_shnum;
  // 节名字符串表节索引。
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;
// Segment 权限位定义（R/W/X）。
// Program Header 的 p_flags 位定义。
#define PF_R 0x4
#define PF_W 0x2
#define PF_X 0x1
// Program Header 结构（32 位）。
typedef struct elf32_phdr {
  // 段类型（PT_*）。
  Elf32_Word p_type;
  // 段在文件中的偏移。
  Elf32_Off p_offset;
  // 段虚拟地址。
  Elf32_Addr p_vaddr;
  // 段物理地址（多数平台可忽略）。
  Elf32_Addr p_paddr;
  // 文件中该段字节数。
  Elf32_Word p_filesz;
  // 内存中该段字节数。
  Elf32_Word p_memsz;
  // 段权限标志（PF_*）。
  Elf32_Word p_flags;
  // 段对齐约束。
  Elf32_Word p_align;
} Elf32_Phdr;
// Program Header 结构（64 位）。
typedef struct elf64_phdr {
  // 段类型（PT_*）。
  Elf64_Word p_type;
  // 段权限标志（PF_*）。
  Elf64_Word p_flags;
  // 段在文件中的偏移。
  Elf64_Off p_offset;
  // 段虚拟地址。
  Elf64_Addr p_vaddr;
  // 段物理地址（多数平台可忽略）。
  Elf64_Addr p_paddr;
  // 文件中该段字节数。
  Elf64_Xword p_filesz;
  // 内存中该段字节数。
  Elf64_Xword p_memsz;
  // 段对齐约束。
  Elf64_Xword p_align;
} Elf64_Phdr;
// Section 类型定义。
// sh_type 常量：描述 section 内容种类。
#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_HASH 5
#define SHT_GNU_HASH 0x6ffffff6
#define SHT_DYNAMIC 6
#define SHT_NOTE 7
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHT_SHLIB 10
#define SHT_DYNSYM 11
#define SHT_NUM 12
#define SHT_LOPROC 0x70000000
#define SHT_HIPROC 0x7fffffff
#define SHT_LOUSER 0x80000000
#define SHT_HIUSER 0xffffffff
// Section 标志位定义。
// sh_flags 常量：描述 section 属性。
#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4
#define SHF_RELA_LIVEPATCH 0x00100000
#define SHF_RO_AFTER_INIT 0x00200000
#define SHF_MASKPROC 0xf0000000
#define SHN_UNDEF 0
#define SHN_LORESERVE 0xff00
#define SHN_LOPROC 0xff00
#define SHN_HIPROC 0xff1f
#define SHN_LIVEPATCH 0xff20
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2
#define SHN_HIRESERVE 0xffff
// Section Header 结构（32 位）。
typedef struct elf32_shdr {
  // 节名在节名字符串表中的偏移。
  Elf32_Word sh_name;
  // 节类型（SHT_*）。
  Elf32_Word sh_type;
  // 节标志（SHF_*）。
  Elf32_Word sh_flags;
  // 节运行时地址。
  Elf32_Addr sh_addr;
  // 节在文件中的偏移。
  Elf32_Off sh_offset;
  // 节大小（字节）。
  Elf32_Word sh_size;
  // 关联索引（依类型解释）。
  Elf32_Word sh_link;
  // 附加信息（依类型解释）。
  Elf32_Word sh_info;
  // 地址对齐要求。
  Elf32_Word sh_addralign;
  // 固定项大小（表类节使用）。
  Elf32_Word sh_entsize;
} Elf32_Shdr;
// Section Header 结构（64 位）。
typedef struct elf64_shdr {
  // 节名在节名字符串表中的偏移。
  Elf64_Word sh_name;
  // 节类型（SHT_*）。
  Elf64_Word sh_type;
  // 节标志（SHF_*）。
  Elf64_Xword sh_flags;
  // 节运行时地址。
  Elf64_Addr sh_addr;
  // 节在文件中的偏移。
  Elf64_Off sh_offset;
  // 节大小（字节）。
  Elf64_Xword sh_size;
  // 关联索引（依类型解释）。
  Elf64_Word sh_link;
  // 附加信息（依类型解释）。
  Elf64_Word sh_info;
  // 地址对齐要求。
  Elf64_Xword sh_addralign;
  // 固定项大小（表类节使用）。
  Elf64_Xword sh_entsize;
} Elf64_Shdr;
// ELF 魔数与 e_ident 索引定义。
// e_ident 各字段索引与标准魔数定义。
#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define EI_OSABI 7
#define EI_PAD 8
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFMAG "\177ELF"
#define SELFMAG 4
#define ELFCLASSNONE 0
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFCLASSNUM 3
#define ELFDATANONE 0
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2
#define EV_NONE 0
#define EV_CURRENT 1
#define EV_NUM 2
// OSABI 定义。
// e_ident[EI_OSABI] 常量。
#define ELFOSABI_NONE 0
#define ELFOSABI_LINUX 3
#ifndef ELF_OSABI
#define ELF_OSABI ELFOSABI_NONE
#endif
// Note 段常见类型定义（核心转储与平台扩展）。
// n_type 常量：用于 core dump/平台特性记录。
#define NT_PRSTATUS 1
#define NT_PRFPREG 2
#define NT_PRPSINFO 3
#define NT_TASKSTRUCT 4
#define NT_AUXV 6
#define NT_SIGINFO 0x53494749
#define NT_FILE 0x46494c45
#define NT_PRXFPREG 0x46e62b7f
// PowerPC 扩展 note 类型。
#define NT_PPC_VMX 0x100
#define NT_PPC_SPE 0x101
#define NT_PPC_VSX 0x102
#define NT_PPC_TAR 0x103
#define NT_PPC_PPR 0x104
#define NT_PPC_DSCR 0x105
#define NT_PPC_EBB 0x106
#define NT_PPC_PMU 0x107
#define NT_PPC_TM_CGPR 0x108
#define NT_PPC_TM_CFPR 0x109
#define NT_PPC_TM_CVMX 0x10a
#define NT_PPC_TM_CVSX 0x10b
#define NT_PPC_TM_SPR 0x10c
#define NT_PPC_TM_CTAR 0x10d
#define NT_PPC_TM_CPPR 0x10e
#define NT_PPC_TM_CDSCR 0x10f
#define NT_PPC_PKEY 0x110
// x86(32) 扩展 note 类型。
#define NT_386_TLS 0x200
#define NT_386_IOPERM 0x201
#define NT_X86_XSTATE 0x202
// s390 扩展 note 类型。
#define NT_S390_HIGH_GPRS 0x300
#define NT_S390_TIMER 0x301
#define NT_S390_TODCMP 0x302
#define NT_S390_TODPREG 0x303
#define NT_S390_CTRS 0x304
#define NT_S390_PREFIX 0x305
#define NT_S390_LAST_BREAK 0x306
#define NT_S390_SYSTEM_CALL 0x307
#define NT_S390_TDB 0x308
#define NT_S390_VXRS_LOW 0x309
#define NT_S390_VXRS_HIGH 0x30a
#define NT_S390_GS_CB 0x30b
#define NT_S390_GS_BC 0x30c
#define NT_S390_RI_CB 0x30d
// ARM/AArch64 扩展 note 类型。
#define NT_ARM_VFP 0x400
#define NT_ARM_TLS 0x401
#define NT_ARM_HW_BREAK 0x402
#define NT_ARM_HW_WATCH 0x403
#define NT_ARM_SYSTEM_CALL 0x404
#define NT_ARM_SVE 0x405
#define NT_ARM_PAC_MASK 0x406
#define NT_ARM_PACA_KEYS 0x407
#define NT_ARM_PACG_KEYS 0x408
#define NT_ARC_V2 0x600
#define NT_VMCOREDD 0x700
// MIPS 扩展 note 类型。
#define NT_MIPS_DSP 0x800
#define NT_MIPS_FP_MODE 0x801
#define NT_MIPS_MSA 0x802
// NOTE 头结构（32 位）。
typedef struct elf32_note {
  // name 字段长度（字节，含结尾零时依实现而定）。
  Elf32_Word n_namesz;
  // desc 字段长度（字节）。
  Elf32_Word n_descsz;
  // note 类型（NT_*）。
  Elf32_Word n_type;
} Elf32_Nhdr;
// NOTE 头结构（64 位）。
typedef struct elf64_note {
  // name 字段长度（字节，含结尾零时依实现而定）。
  Elf64_Word n_namesz;
  // desc 字段长度（字节）。
  Elf64_Word n_descsz;
  // note 类型（NT_*）。
  Elf64_Word n_type;
} Elf64_Nhdr;
#endif
