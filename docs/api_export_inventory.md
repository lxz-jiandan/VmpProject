# API 导出清单（可编辑）

说明：
- 本文件按模块与头文件导出当前可见 API 声明，供你直接改设计。
- 你可直接在本文件修改、增删、重命名 API；我将按你的版本做结构重构。
- 本清单聚焦‘类型声明 + 函数签名’，已过滤大部分字段声明。
- 若你只想设计核心导出函数，请优先编辑：`docs/api_core_exports.md`。

## VmEngine/runtime

### VmEngine/app/src/main/cpp/zAssestManager.h
- `class zAssetManager {`
- `static jobject getCurrentApplicationContext(JNIEnv* env);`
- `static bool loadAssetDataByFileName(JNIEnv* env, const char* assetFileName, std::vector<uint8_t>& dataOut);`
- `static bool loadAssetDataByFileName(JNIEnv* env, jobject context, const char* assetFileName, std::vector<uint8_t>& dataOut);`
- `static bool extractAssetToFile(JNIEnv* env, const char* assetFileName, std::string& outPath);`
- `static bool extractAssetToFile(JNIEnv* env, jobject context, const char* assetFileName, std::string& outPath);`
- `static bool getCurrentFilesDirPath(JNIEnv* env, std::string& outPath);`
- `static bool jstringToString(JNIEnv* env, jstring str, std::string& out);`
- `static bool writeAll(int fd, const void* data, size_t size);`
- `static bool getFilesDirPath(JNIEnv* env, jobject context, std::string& outPath);`
- `static AAssetManager* getAssetManagerFromContext(JNIEnv* env, jobject context);`

### VmEngine/app/src/main/cpp/zElfTakeoverDynsym.h
- `bool zElfRecoverTakeoverEntriesFromPatchedSo( const std::string& so_path, std::vector<zTakeoverSymbolEntry>& out_entries );`

### VmEngine/app/src/main/cpp/zEmbeddedPayload.h
- `enum class zEmbeddedPayloadReadStatus {`
- `class zEmbeddedPayload {`
- `static bool readEmbeddedPayloadFromHostSo( const std::string& host_so_path, std::vector<uint8_t>& out_payload, zEmbeddedPayloadReadStatus* out_status );`
- `static uint32_t crc32(const uint8_t* data, size_t size);`

### VmEngine/app/src/main/cpp/zFileBytes.h
- `namespace zFileBytes {`
- `bool readFileBytes(const std::string& path, std::vector<uint8_t>& out);`
- `bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data);`

### VmEngine/app/src/main/cpp/zFunction.h
- `struct VMRegSlot;`
- `class zType;`
- `class FunctionStructType;`
- `class zTypeManager;`
- `class zFunction : public zFunctionData {`
- `bool loadUnencodedText(const char* text, size_t len);`
- `bool loadEncodedData(const uint8_t* data, uint64_t len, uint64_t* externalInitArray = nullptr);`
- `bool empty() const;`
- `const std::vector<uint64_t>& branchAddrs() const;`
- `uint64_t functionAddress() const;`
- `void setFunctionAddress(uint64_t functionAddress);`
- `void setTypePool(std::unique_ptr<zTypeManager> pool);`
- `void releaseTypeResources();`
- `static std::string trimCopy(const std::string& value);`
- `static bool parseArrayValues32(const std::string& line, std::vector<uint32_t>& values);`
- `static bool parseArrayValues64(const std::string& line, std::vector<uint64_t>& values);`
- `static bool parseScalarUint32(const std::string& line, uint32_t& value);`
- `static bool parseScalarUint64(const std::string& line, uint64_t& value);`
- `bool parseFromStream(std::istream& in);`

### VmEngine/app/src/main/cpp/zFunctionData.h
- `class zFunctionData {`
- `bool validate(std::string* error = nullptr) const;`
- `bool serializeEncoded(std::vector<uint8_t>& out, std::string* error = nullptr) const;`
- `static bool deserializeEncoded(const uint8_t* data, size_t len, zFunctionData& out, std::string* error = nullptr);`
- `bool encodedEquals(const zFunctionData& other, std::string* error = nullptr) const;`

### VmEngine/app/src/main/cpp/zLinker.h
- `struct soinfo {`
- `class zLinker {`
- `zLinker();`
- `bool LoadLibrary(const char* path);`
- `soinfo* GetSoinfo(const char* name);`
- `bool OpenElf(const char* path);`
- `bool ReadElf();`
- `void CloseElf();`
- `bool ReadElfHeader();`
- `bool VerifyElfHeader();`
- `bool ReadProgramHeaders();`
- `bool ReserveAddressSpace();`
- `bool LoadSegments();`
- `bool FindPhdr();`
- `bool ProtectSegments();`
- `bool CheckPhdr(ElfW(Addr) loaded) const;`
- `size_t PhdrTableGetLoadSize(ElfW(Addr)* minVaddr) const;`
- `soinfo* GetOrCreateSoinfo(const char* name);`
- `bool UpdateSoinfo(soinfo* si) const;`
- `bool PrelinkImage(soinfo* si);`
- `bool ParseDynamic(soinfo* si);`
- `void ApplyRelaSections(soinfo* si) const;`
- `bool LinkImage(soinfo* si);`
- `bool RelocateImage(soinfo* si);`
- `bool ProcessRelaRelocation(soinfo* si, const ElfW(Rela)* rela);`
- `ElfW(Addr) FindSymbolAddress(const char* name, soinfo* si);`
- `ElfW(Sym)* GnuLookup(uint32_t hash, const char* name, soinfo* si) const;`
- `ElfW(Sym)* ElfLookup(unsigned hash, const char* name, soinfo* si) const;`
- `uint32_t GnuHash(const char* name) const;`
- `unsigned ElfHash(const char* name) const;`

### VmEngine/app/src/main/cpp/zLog.h
- `void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...);`

### VmEngine/app/src/main/cpp/zPatchBay.h
- `struct zPatchBayHeader {`
- `struct zPatchBayImage {`
- `extern "C" const zPatchBayHeader* vm_get_patch_bay_header();`

### VmEngine/app/src/main/cpp/zPipelineConfig.h
- (未识别到函数/类型声明)

### VmEngine/app/src/main/cpp/zSoBinBundle.h
- `struct zSoBinEntry {`
- `class zSoBinBundleReader {`
- `static bool readFromExpandedSo( const std::string& so_path, std::vector<zSoBinEntry>& out_entries, std::vector<uint64_t>& out_shared_branch_addrs );`

### VmEngine/app/src/main/cpp/zSymbolTakeover.h
- `struct zTakeoverSymbolEntry {`
- `bool zSymbolTakeoverInit( const char* primary_so_name, const zTakeoverSymbolEntry* entries, size_t entry_count );`
- `void zSymbolTakeoverClear();`
- `extern "C" int vm_takeover_dispatch_by_id(int a, int b, uint32_t symbol_id);`

### VmEngine/app/src/main/cpp/zTypeManager.h
- `enum TypeKind : uint32_t {`
- `enum TypeTag : uint32_t {`
- `class zType {`
- `virtual ~zType() = default;`
- `class FunctionStructType : public zType {`
- `class PointerType : public zType {`
- `class ArrayType : public zType {`
- `class CallType : public zType {`
- `class IntegerWidthType : public zType {`
- `class zTypeManager {`
- `zTypeManager();`
- `zType* createInt8(bool isSigned = true);`
- `zType* createInt16(bool isSigned = true);`
- `zType* createInt32(bool isSigned = true);`
- `zType* createInt64(bool isSigned = true);`
- `zType* createFloat32();`
- `zType* createFloat64();`
- `zType* createPointer();`
- `zType* createIntegerWidth(uint32_t bitWidth);`
- `FunctionStructType* createFunctionStruct(bool hasReturn, uint32_t paramCount);`
- `PointerType* createPointerType(zType* pointeeType);`
- `ArrayType* createArrayType(uint32_t elementCount, zType* elementType, uint32_t kind);`
- `CallType* createCallType(bool hasReturn, zType* returnType, uint32_t paramCount);`
- `zType* createFromCode(uint32_t code);`
- `void freeType(zType* type);`
- `void freeTypeList(zType** types, uint32_t count);`
- `static uint32_t getTypeSize(zType* type);`
- `static uint32_t getTypeAlignment(zType* type);`
- `static void calcStructAlignment(zType* type);`
- `zType* allocType();`
- `FunctionStructType* allocFunctionStructType();`
- `PointerType* allocPointerType();`
- `ArrayType* allocArrayType();`
- `CallType* allocCallType();`

### VmEngine/app/src/main/cpp/zVmEngine.h
- `struct VMRegSlot {`
- `struct RegManager {`
- `struct zParams {`
- `zParams() = default;`
- `struct VMContext {`
- `RegManager* allocRegManager(uint32_t count);`
- `void freeRegManager(RegManager* mgr);`
- `class zVmEngine {`
- `static zVmEngine& getInstance();`
- `uint64_t execute( void* retBuffer, uint32_t registerCount, VMRegSlot* registers, uint32_t typeCount, zType** types, uint32_t instCount, uint32_t* instructions, uint32_t branchCount, uint32_t* branches, uint32_t branchAddrCount, uint64_t* ext_list );`
- `uint64_t execute( void* retBuffer, const char* soName, uint64_t funAddr, const zParams& params );`
- `bool cacheFunction(std::unique_ptr<zFunction> function);`
- `bool LoadLibrary(const char* path);`
- `soinfo* GetSoinfo(const char* name);`
- `void setSharedBranchAddrs(const char* soName, std::vector<uint64_t> branchAddrs);`
- `void clearSharedBranchAddrs(const char* soName);`
- `void clearCache();`
- `zVmEngine();`
- `zVmEngine(const zVmEngine&) = delete;`
- `zVmEngine& operator=(const zVmEngine&) = delete;`
- `zVmEngine(zVmEngine&&) = delete;`
- `zVmEngine& operator=(zVmEngine&&) = delete;`
- `uint64_t executeState( zFunction* function, VMRegSlot* registers, void* retBuffer, const char* soName );`
- `void destroyFunction(zFunction* function);`
- `void dispatch(VMContext* ctx);`

### VmEngine/app/src/main/cpp/zVmInitCore.h
- `bool runVmInitCore(JNIEnv* env);`

### VmEngine/app/src/main/cpp/zVmOpcodes.h
- `enum Opcode : uint32_t {`
- `enum VMConditionCode : uint32_t {`
- `enum BinaryOp : uint32_t {`
- `enum UnaryOp : uint32_t {`
- `enum CompareOp : uint32_t {`
- `enum ConvertOp : uint32_t {`
- `namespace vm {`
- `typedef void (*OpcodeHandler)(VMContext* ctx);`
- `void op_end(VMContext* ctx);`
- `void op_binary(VMContext* ctx);`
- `void op_type_convert(VMContext* ctx);`
- `void op_load_const(VMContext* ctx);`
- `void op_store_const(VMContext* ctx);`
- `void op_get_element(VMContext* ctx);`
- `void op_alloc_return(VMContext* ctx);`
- `void op_store(VMContext* ctx);`
- `void op_load_const64(VMContext* ctx);`
- `void op_nop(VMContext* ctx);`
- `void op_copy(VMContext* ctx);`
- `void op_get_field(VMContext* ctx);`
- `void op_cmp(VMContext* ctx);`
- `void op_set_field(VMContext* ctx);`
- `void op_restore_reg(VMContext* ctx);`
- `void op_call(VMContext* ctx);`
- `void op_return(VMContext* ctx);`
- `void op_branch(VMContext* ctx);`
- `void op_branch_if(VMContext* ctx);`
- `void op_branch_if_cc(VMContext* ctx);`
- `void op_set_return_pc(VMContext* ctx);`
- `void op_bl(VMContext* ctx);`
- `void op_adrp(VMContext* ctx);`
- `void op_alloc_memory(VMContext* ctx);`
- `void op_mov(VMContext* ctx);`
- `void op_load_imm(VMContext* ctx);`
- `void op_dynamic_cast(VMContext* ctx);`
- `void op_unary(VMContext* ctx);`
- `void op_phi(VMContext* ctx);`
- `void op_select(VMContext* ctx);`
- `void op_memcpy(VMContext* ctx);`
- `void op_memset(VMContext* ctx);`
- `void op_strlen(VMContext* ctx);`
- `void op_fetch_next(VMContext* ctx);`
- `void op_call_indirect(VMContext* ctx);`
- `void op_switch(VMContext* ctx);`
- `void op_get_ptr(VMContext* ctx);`
- `void op_bitcast(VMContext* ctx);`
- `void op_sign_extend(VMContext* ctx);`
- `void op_zero_extend(VMContext* ctx);`
- `void op_truncate(VMContext* ctx);`
- `void op_float_extend(VMContext* ctx);`
- `void op_float_truncate(VMContext* ctx);`
- `void op_int_to_float(VMContext* ctx);`
- `void op_array_elem(VMContext* ctx);`
- `void op_float_to_int(VMContext* ctx);`
- `void op_read(VMContext* ctx);`
- `void op_write(VMContext* ctx);`
- `void op_lea(VMContext* ctx);`
- `void op_atomic_add(VMContext* ctx);`
- `void op_atomic_sub(VMContext* ctx);`
- `void op_atomic_xchg(VMContext* ctx);`
- `void op_atomic_cas(VMContext* ctx);`
- `void op_fence(VMContext* ctx);`
- `void op_unreachable(VMContext* ctx);`
- `void op_alloc_vsp(VMContext* ctx);`
- `void op_binary_imm(VMContext* ctx);`
- `void op_unknown(VMContext* ctx);`
- `void initOpcodeTable();`
- `uint64_t execBinaryOp(uint32_t op, uint64_t lhs, uint64_t rhs, zType* type);`
- `uint64_t execUnaryOp(uint32_t op, uint64_t src, zType* type);`
- `uint64_t execCompareOp(uint32_t op, uint64_t lhs, uint64_t rhs, zType* type);`
- `uint64_t execTypeConvert(uint32_t op, uint64_t src, zType* srcType, zType* dstType);`
- `const char* getOpcodeName(uint32_t opcode);`
- `void copyValue(VMRegSlot* src, zType* type, VMRegSlot* dst);`
- `void readValue(VMRegSlot* addrSlot, zType* type, VMRegSlot* dst);`
- `void writeValue(VMRegSlot* addrSlot, zType* type, VMRegSlot* valueSlot);`
- `void setVmModuleBase(uint64_t base);`

## VmProtect/L0-foundation

### VmProtect/modules/foundation/core/zIoUtils.h
- `namespace vmp {`
- `bool fileExists(const std::string& path);`
- `bool ensureDirectory(const std::string& path);`
- `bool readFileBytes(const char* path, std::vector<uint8_t>& out);`
- `bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data);`

### VmProtect/modules/foundation/core/zLog.h
- `void zLogPrint(int level, const char* tag, const char* file_name, const char* function_name, int line_num, const char* format, ...);`

## VmProtect/L0-base

### VmProtect/modules/base/core/base/bitcodec.h
- `namespace vmp::base::bitcodec {`
- `class BitWriter6 {`
- `void write6(uint32_t value);`
- `void writeExtU32(uint32_t value);`
- `class BitReader6 {`
- `BitReader6(const uint8_t* data, size_t len);`
- `bool read6(uint32_t* out);`
- `bool readExtU32(uint32_t* out);`
- `void writeU64AsU32Pair(BitWriter6* writer, uint64_t value);`
- `bool readU64FromU32Pair(BitReader6* reader, uint64_t* out);`

### VmProtect/modules/base/core/base/bytes.h
- `namespace vmp::base::bytes {`
- `bool validateRegionAllowEmpty(uint32_t header_size, uint32_t total_size, uint32_t off, uint32_t cap, const char* name, std::string* error);`
- `bool validateUsedRegion(uint32_t header_size, uint32_t total_size, uint32_t off, uint32_t cap, uint32_t used, const char* name, std::string* error);`
- `bool writeRegionPadded(std::vector<uint8_t>* bytes, uint64_t base_off, uint32_t off, uint32_t cap, const std::vector<uint8_t>& payload, std::string* error);`

### VmProtect/modules/base/core/base/checksum.h
- `namespace vmp::base::checksum {`
- `uint32_t crc32IeeeInit();`
- `uint32_t crc32IeeeUpdate(uint32_t crc, const uint8_t* data, size_t size);`
- `uint32_t crc32IeeeFinal(uint32_t crc);`
- `uint32_t crc32Ieee(const uint8_t* data, size_t size);`
- `uint32_t crc32Ieee(const std::vector<uint8_t>& data);`

### VmProtect/modules/base/core/base/codec.h
- `namespace vmp::base::codec {`
- `bool readU32Le(const std::vector<uint8_t>& bytes, size_t offset, uint32_t* out);`
- `bool writeU32Le(std::vector<uint8_t>* bytes, size_t offset, uint32_t value);`
- `void appendU32Le(std::vector<uint8_t>* out, uint32_t value);`
- `bool readU64Le(const std::vector<uint8_t>& bytes, size_t offset, uint64_t* out);`
- `bool writeU64Le(std::vector<uint8_t>* bytes, size_t offset, uint64_t value);`
- `void appendU64Le(std::vector<uint8_t>* out, uint64_t value);`
- `void appendU32LeArray(std::vector<uint8_t>* out, const uint32_t* values, size_t count);`
- `void appendU64LeArray(std::vector<uint8_t>* out, const uint64_t* values, size_t count);`
- `bool readU32LeAdvance(const std::vector<uint8_t>& bytes, size_t* cursor, uint32_t* out);`
- `bool readU64LeAdvance(const std::vector<uint8_t>& bytes, size_t* cursor, uint64_t* out);`
- `void appendStringU32Le(std::vector<uint8_t>* out, const std::string& value);`
- `bool readStringU32LeAdvance(const std::vector<uint8_t>& bytes, size_t* cursor, std::string* out);`

### VmProtect/modules/base/core/base/hash.h
- `namespace vmp::base::hash {`
- `uint32_t elfSysvHash(const char* name);`
- `uint32_t elfGnuHash(const char* name);`
- `uint32_t chooseBucketCount(uint32_t nchain);`

### VmProtect/modules/base/core/base/io.h
- `namespace vmp::base::io {`
- `bool fileExists(const std::string& path);`
- `bool ensureDirectory(const std::string& path);`
- `bool readFileBytes(const char* path, std::vector<uint8_t>* out);`
- `bool writeFileBytes(const std::string& path, const std::vector<uint8_t>& data);`

## VmProtect/L1-elfkit-core

### VmProtect/modules/elfkit/core/zElfTypes.h
- (未识别到函数/类型声明)

### VmProtect/modules/elfkit/core/zElf.h
- `class zElf {`
- `enum LINK_VIEW {`
- `zElf();`
- `zElf(const char* elf_file_name);`
- `void parseElfHead();`
- `void parseProgramHeaderTable();`
- `void parseSectionTable();`
- `void parseDynamicTable();`
- `bool loadElfFile(const char* elf_path);`
- `void printLayout();`
- `bool relocateAndExpandPht(int extra_entries, const char* output_path);`
- `Elf64_Addr findSymbolOffsetByDynamic(const char* symbol_name);`
- `Elf64_Addr findSymbolOffsetBySection(const char* symbol_name);`
- `Elf64_Addr findSymbolOffset(const char* symbol_name);`
- `char* getSymbolFileAddress(const char* symbol_name);`
- `Elf64_Sym* findSymbolInfo(const char* symbol_name);`
- `bool buildFunctionList();`
- `zFunction* getFunction(const char* function_name);`
- `const std::vector<zFunction>& getFunctionList() const;`
- `bool addFunctionFromSymbol(const char* symbol_name, Elf64_Xword symbol_size);`
- `zFunction* findFunctionInList(const char* function_name);`

### VmProtect/modules/elfkit/core/zFunction.h
- `class zFunction : public zFunctionData {`
- `enum class DumpMode {`
- `explicit zFunction(const zFunctionData& data);`
- `const std::string& name() const;`
- `Elf64_Addr offset() const;`
- `size_t size() const;`
- `const uint8_t* data() const;`
- `bool empty() const;`
- `zFunction& analyzeAssembly();`
- `const std::vector<zInst>& assemblyList() const;`
- `bool dump(const char* file_path, DumpMode mode) const;`
- `bool prepareTranslation(std::string* error = nullptr) const;`
- `const std::string& lastTranslationError() const;`
- `const std::vector<uint64_t>& sharedBranchAddrs() const;`
- `bool remapBlToSharedBranchAddrs(const std::vector<uint64_t>& shared_branch_addrs);`
- `void ensureAsmReady() const;`
- `void ensureUnencodedReady() const;`
- `void setUnencodedCache( uint32_t register_count, std::vector<uint32_t> reg_id_list, uint32_t type_count, std::vector<uint32_t> type_tags, uint32_t init_value_count, std::map<uint64_t, std::vector<uint32_t>> inst_by_address, std::map<uint64_t, std::string> asm_by_address, uint32_t inst_count, uint32_t branch_count, std::vector<uint32_t> branch_words, std::vector<uint64_t> branch_addr_words ) const;`
- `void rebuildAsmListFromUnencoded() const;`

### VmProtect/modules/elfkit/core/zFunctionData.h
- `class zFunctionData {`
- `bool validate(std::string* error = nullptr) const;`
- `bool serializeEncoded(std::vector<uint8_t>& out, std::string* error = nullptr) const;`
- `static bool deserializeEncoded(const uint8_t* data, size_t len, zFunctionData& out, std::string* error = nullptr);`
- `bool encodedEquals(const zFunctionData& other, std::string* error = nullptr) const;`

### VmProtect/modules/elfkit/core/zInst.h
- `class zInst {`
- `zInst() = default;`
- `zInst(uint64_t address, std::vector<uint8_t> raw_bytes, uint32_t instruction_length, std::string asm_type, std::string disasm_text);`
- `uint64_t address() const;`
- `const std::vector<uint8_t>& rawBytes() const;`
- `uint32_t instructionLength() const;`
- `const std::string& asmType() const;`
- `const std::string& disasmText() const;`

### VmProtect/modules/elfkit/core/zSoBinBundle.h
- `struct zSoBinPayload {`
- `class zSoBinBundleWriter {`
- `static bool writeExpandedSo( const char* input_so_path, const char* output_so_path, const std::vector<zSoBinPayload>& payloads, const std::vector<uint64_t>& shared_branch_addrs );`

## VmProtect/L1-elfkit-public

### VmProtect/modules/elfkit/core/zElfAbi.h
- (未识别到函数/类型声明)

### VmProtect/modules/elfkit/api/zElfKit.h
- `namespace vmp::elfkit {`
- `enum class DumpMode {`
- `class FunctionView {`
- `FunctionView() = default;`
- `bool valid() const;`
- `const std::string& name() const;`
- `uint64_t offset() const;`
- `size_t size() const;`
- `const uint8_t* data() const;`
- `bool prepareTranslation(std::string* error = nullptr) const;`
- `bool dump(const char* file_path, DumpMode mode) const;`
- `const std::vector<uint64_t>& sharedBranchAddrs() const;`
- `bool remapBlToSharedBranchAddrs(const std::vector<uint64_t>& shared_branch_addrs) const;`
- `explicit FunctionView(void* impl_ptr);`
- `class ElfImage {`
- `explicit ElfImage(const char* elf_path);`
- `ElfImage(const ElfImage&) = delete;`
- `ElfImage& operator=(const ElfImage&) = delete;`
- `ElfImage(ElfImage&& other) noexcept;`
- `ElfImage& operator=(ElfImage&& other) noexcept;`
- `bool loaded() const;`
- `FunctionView findFunction(const std::string& symbol_name);`
- `class Impl;`

### VmProtect/modules/elfkit/api/zPatchbayApi.h
- `class zDynamicSection;`
- `class zSectionTableElement;`
- `class zStrTabSection;`
- `class zSymbolSection;`
- `namespace vmp::elfkit {`
- `struct PatchSymbolInfo {`
- `struct PatchDynamicExportInfo {`
- `struct PatchRequiredSections {`
- `class PatchElfImage {`
- `explicit PatchElfImage(const char* elf_path);`
- `PatchElfImage(const PatchElfImage&) = delete;`
- `PatchElfImage& operator=(const PatchElfImage&) = delete;`
- `PatchElfImage(PatchElfImage&& other) noexcept;`
- `PatchElfImage& operator=(PatchElfImage&& other) noexcept;`
- `bool loaded() const;`
- `bool validate(std::string* error = nullptr) const;`
- `bool resolveSymbol(const char* symbol_name, PatchSymbolInfo* out_info) const;`
- `bool collectDefinedDynamicExports(std::vector<std::string>* out_exports, std::string* error) const;`
- `bool collectDefinedDynamicExportInfos(std::vector<PatchDynamicExportInfo>* out_exports, std::string* error) const;`
- `bool queryRequiredSections(PatchRequiredSections* out, std::string* error) const;`
- `class Impl;`

## VmProtect/L2-patchbay-elf-model

### VmProtect/modules/elfkit/patchbay_model/elf.h
- (未识别到函数/类型声明)

### VmProtect/modules/elfkit/patchbay_model/PatchElf.h
- `class PatchElf;`
- `class PatchElf {`
- `PatchElf();`
- `explicit PatchElf(const char* elf_file_name);`
- `bool loadElfFile(const char* elf_path);`
- `void printLayout();`
- `bool relocateAndExpandPht(int extra_entries, const char* output_path);`
- `bool reconstruct();`
- `bool save(const char* output_path);`
- `bool isLoaded() const;`
- `size_t fileImageSize() const;`
- `const uint8_t* fileImageData() const;`
- `bool validate(std::string* error = nullptr) const;`
- `zElfHeader& headerModel();`
- `zElfProgramHeaderTable& programHeaderModel();`
- `zElfSectionHeaderTable& sectionHeaderModel();`
- `const zElfHeader& headerModel() const;`
- `const zElfProgramHeaderTable& programHeaderModel() const;`
- `const zElfSectionHeaderTable& sectionHeaderModel() const;`
- `zProgramTableElement* getProgramHeader(size_t idx);`
- `const zProgramTableElement* getProgramHeader(size_t idx) const;`
- `zProgramTableElement* findFirstProgramHeader(Elf64_Word type);`
- `const zProgramTableElement* findFirstProgramHeader(Elf64_Word type) const;`
- `zSectionTableElement* getSection(size_t idx);`
- `const zSectionTableElement* getSection(size_t idx) const;`
- `zSectionTableElement* findSectionByName(const std::string& section_name);`
- `const zSectionTableElement* findSectionByName(const std::string& section_name) const;`
- `bool addProgramHeader(const zProgramTableElement& ph, size_t* out_index = nullptr);`
- `bool addSectionSimple(const std::string& name, Elf64_Word type, Elf64_Xword flags, Elf64_Xword addralign, const std::vector<uint8_t>& payload, size_t* out_index = nullptr);`
- `bool addSectionPaddingByName(const std::string& section_name, size_t pad_size);`
- `bool addSectionPaddingByIndex(size_t idx, size_t pad_size);`
- `bool addZeroFillToSegment(size_t idx, Elf64_Xword extra_memsz);`
- `bool addSegment(Elf64_Word type, const std::string& flags_text, size_t* out_index = nullptr);`
- `bool addSection(const std::string& name, size_t load_segment_idx, size_t* out_index = nullptr);`
- `bool addSection(const std::string& name, size_t* out_index = nullptr);`
- `int getFirstLoadSegment() const;`
- `int getLastLoadSegment() const;`
- `bool relocate(const std::string& output_path);`
- `bool backup();`
- `struct PendingBlob {`
- `bool reconstructionImpl();`
- `bool vaddrToFileOffset(Elf64_Addr vaddr, Elf64_Off* off) const;`
- `Elf64_Addr fileOffsetToVaddr(Elf64_Off off) const;`
- `uint64_t currentMaxFileEnd() const;`
- `uint64_t currentMaxLoadVaddrEnd() const;`

### VmProtect/modules/elfkit/patchbay_model/elf_header.h
- `class zElfHeader {`
- `bool fromRaw(const uint8_t* data, size_t size);`
- `bool isElf64AArch64() const;`

### VmProtect/modules/elfkit/patchbay_model/elf_loader.h
- `class PatchElf;`
- `namespace zElfLoader {`
- `bool loadFileAndParse(PatchElf* elf, const char* elf_path);`

### VmProtect/modules/elfkit/patchbay_model/program_table.h
- `class zElfProgramHeaderTable {`
- `void fromRaw(const Elf64_Phdr* raw, size_t count);`
- `int findFirstByType(Elf64_Word type) const;`

### VmProtect/modules/elfkit/patchbay_model/section_table.h
- `class zElfSectionHeaderTable {`
- `bool fromRaw(const uint8_t* file_data, size_t file_size, const Elf64_Shdr* section_headers, size_t section_count, uint16_t shstrndx);`
- `int findByName(const std::string& section_name) const;`
- `zSectionTableElement* get(size_t idx);`
- `const zSectionTableElement* get(size_t idx) const;`

### VmProtect/modules/elfkit/patchbay_model/elf_utils.h
- `class PatchElf;`
- `class zProgramTableElement;`
- `class zSectionTableElement;`
- `uint64_t inferRuntimePageSizeFromPhdrs( const std::vector<zProgramTableElement>& phs);`
- `bool load_segment_matches_section_flags( const zProgramTableElement& ph, const zSectionTableElement& section);`
- `bool isDynamicPointerTag(Elf64_Sxword tag);`
- `bool collectDynamicTags( const PatchElf& elf, std::unordered_map<int64_t, uint64_t>* tags, std::string* error);`
- `bool read_dynamic_entries_from_phdr( const PatchElf& elf, std::vector<Elf64_Dyn>* out_entries, Elf64_Off* out_off, Elf64_Xword* out_size, bool* out_has_pt_dynamic, std::string* error);`

### VmProtect/modules/elfkit/patchbay_model/zElfValidator.h
- `class PatchElf;`
- `class zElfValidator {`
- `static bool validateBasic(const PatchElf& elf, std::string* error);`
- `static bool validateProgramSegmentLayout(const PatchElf& elf, std::string* error);`
- `static bool validateSectionSegmentMapping(const PatchElf& elf, std::string* error);`
- `static bool validateSymbolResolution(const PatchElf& elf, std::string* error);`
- `static bool validatePltGotRelocations(const PatchElf& elf, std::string* error);`
- `static bool validateReparseConsistency(const PatchElf& elf, std::string* error);`
- `static bool validateAll(const PatchElf& elf, std::string* error);`

### VmProtect/modules/elfkit/patchbay_model/program_entry.h
- `class zProgramTableElement {`
- `static zProgramTableElement fromPhdr(const Elf64_Phdr& phdr);`
- `Elf64_Phdr toPhdr() const;`
- `bool containsVaddr(Elf64_Addr addr) const;`
- `bool containsFileOffset(Elf64_Off off) const;`
- `bool validateMemFileRelation() const;`
- `uint64_t fileEnd() const;`
- `uint64_t vaddrEnd() const;`

### VmProtect/modules/elfkit/patchbay_model/section_entry.h
- `class zSectionTableElement {`
- `virtual ~zSectionTableElement() = default;`
- `virtual void parseFromBytes(const uint8_t* data, size_t data_size);`
- `virtual std::vector<uint8_t> toByteArray() const;`
- `virtual void syncHeader();`
- `Elf64_Shdr toShdr() const;`
- `const std::string& sectionName() const;`
- `Elf64_Word sectionType() const;`
- `Elf64_Xword sectionFlags() const;`
- `void fromShdr(const Elf64_Shdr& shdr);`
- `class zStrTabSection : public zSectionTableElement {`
- `uint32_t addString(const std::string& value);`
- `const char* getStringAt(uint32_t off) const;`
- `class zSymbolSection : public zSectionTableElement {`
- `void parseFromBytes(const uint8_t* data, size_t data_size) override;`
- `void syncHeader() override;`
- `size_t symbolCount() const;`
- `class zDynamicSection : public zSectionTableElement {`
- `size_t entryCount() const;`
- `class zRelocationSection : public zSectionTableElement {`
- `size_t relocationCount() const;`

## VmProtect/L2-patchbay-domain

### VmProtect/modules/patchbay/domain/patchbayAliasTables.h
- `struct AliasTableBuildResult {`
- `bool buildPatchbayAliasTables(const vmp::elfkit::PatchElfImage& elf, const vmp::elfkit::PatchRequiredSections& required, const std::vector<AliasPair>& alias_pairs, AliasTableBuildResult* out, std::string* error);`

### VmProtect/modules/patchbay/foundation/patchbayCrc.h
- `uint64_t bitmaskForCountU32(uint32_t count);`
- `bool computePatchbayCrcFromFile(const std::vector<uint8_t>& file_bytes, uint64_t patchbay_off, const PatchBayHeader& hdr, uint32_t* out_crc, std::string* error);`

### VmProtect/modules/patchbay/patchbay_entry.h
- `bool vmprotectIsPatchbayCommand(const char* cmd);`
- `int vmprotectPatchbayEntry(int argc, char* argv[]);`

### VmProtect/modules/patchbay/patchbay_export.h
- `bool exportAliasSymbolsPatchbay(const char* input_path, const char* output_path, const std::vector<AliasPair>& alias_pairs, bool allow_validate_fail, std::string* error);`

### VmProtect/modules/patchbay/format/patchbayHash.h
- `uint32_t elfSysvHash(const char* name);`
- `uint32_t chooseBucketCount(uint32_t nchain);`
- `uint32_t elfGnuHash(const char* name);`

### VmProtect/modules/patchbay/patchbay_io.h
- `bool loadFileBytes(const char* path, std::vector<uint8_t>* out);`
- `bool saveFileBytes(const char* path, const std::vector<uint8_t>& bytes);`

### VmProtect/modules/patchbay/format/patchbayLayout.h
- `bool validateElfTablesForAndroid(const std::vector<uint8_t>& file_bytes, std::string* error);`

### VmProtect/modules/patchbay/patchbay_patch_apply.h
- `bool applyPatchbayAliasPayload(const vmp::elfkit::PatchRequiredSections& required, const char* input_path, const char* output_path, const std::vector<uint8_t>& new_dynsym_bytes, const std::vector<uint8_t>& new_dynstr, const std::vector<uint8_t>& new_versym, const std::vector<uint8_t>& new_gnu_hash, const std::vector<uint8_t>& new_sysv_hash, uint32_t slot_used_hint, bool allow_validate_fail, bool* handled, std::string* error);`

### VmProtect/modules/patchbay/domain/patchbayRules.h
- `bool isFunOrJavaSymbol(const std::string& name);`
- `bool isTakeoverSlotModeImpl(const char* impl_name);`
- `bool validateVmengineExportNamingRules(const std::vector<std::string>& input_exports, std::string* error);`

### VmProtect/modules/patchbay/domain/patchbayTypes.h
- `struct AliasPair {`
- `struct PatchBayHeader {`

## VmProtect/L3-pipeline

### VmProtect/modules/pipeline/core/zPipelineCli.h
- `namespace vmp {`
- `void deduplicateKeepOrder(std::vector<std::string>& values);`
- `bool parseCommandLine(int argc, char* argv[], CliOverrides& cli, std::string& error);`
- `void printUsage();`

### VmProtect/modules/pipeline/core/pipeline/zPipelineCoverage.h
- `namespace vmp {`
- `bool buildCoverageBoard(const std::vector<std::string>& function_names, const std::vector<elfkit::FunctionView>& functions, CoverageBoard& board);`
- `bool writeCoverageReport(const std::string& report_path, const CoverageBoard& board);`

### VmProtect/modules/pipeline/core/pipeline/zPipelineExport.h
- `namespace vmp {`
- `bool collectFunctions(elfkit::ElfImage& elf, const std::vector<std::string>& function_names, std::vector<elfkit::FunctionView>& functions);`
- `bool exportProtectedPackage(const VmProtectConfig& config, const std::vector<std::string>& function_names, const std::vector<elfkit::FunctionView>& functions);`

### VmProtect/modules/pipeline/core/pipeline/zPipelinePatch.h
- `namespace vmp {`
- `bool embedExpandedSoIntoHost(const std::string& host_so, const std::string& payload_so, const std::string& final_so);`
- `bool runPatchbayExportFromDonor(const std::string& input_so, const std::string& output_so, const std::string& donor_so, const std::string& impl_symbol, bool patch_all_exports, bool allow_validate_fail);`

### VmProtect/modules/pipeline/core/pipeline/zPipelineTypes.h
- `namespace vmp {`
- `struct VmProtectConfig {`
- `struct CliOverrides {`
- `struct FunctionCoverageRow {`
- `struct CoverageBoard {`






