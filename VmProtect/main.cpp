#include <cinttypes>
#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "zElf.h"
#include "zFunction.h"
#include "zLog.h"
#include "zSoBinBundle.h"

namespace {

// 读取二进制文件到内存，供后续组装 payload 写入 expand so。
bool readFileBytes(const char* path, std::vector<uint8_t>& out) {
    out.clear();
    if (!path || path[0] == '\0') {
        return false;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        return false;
    }
    in.seekg(0, std::ios::beg);

    out.resize(static_cast<size_t>(size));
    if (!out.empty()) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    }
    return static_cast<bool>(in);
}

// 导出统一的共享 branch_addr_list.txt，供三条回归路线复用。
bool writeSharedBranchAddrList(const char* file_path, const std::vector<uint64_t>& branch_addrs) {
    if (file_path == nullptr || file_path[0] == '\0') {
        return false;
    }

    std::ofstream out(file_path, std::ios::trunc);
    if (!out) {
        return false;
    }

    out << "static const uint64_t branch_addr_count = " << branch_addrs.size() << ";\n";
    if (branch_addrs.empty()) {
        out << "uint64_t branch_addr_list[1] = {};\n";
        return static_cast<bool>(out);
    }

    out << "uint64_t branch_addr_list[] = { ";
    for (size_t i = 0; i < branch_addrs.size(); ++i) {
        if (i > 0) {
            out << ", ";
        }
        out << "0x" << std::hex << branch_addrs[i] << std::dec;
    }
    out << " };\n";
    return static_cast<bool>(out);
}

// 把函数局部 branch 地址并入全局表，并保持“首次出现顺序”稳定。
void appendUniqueBranchAddrs(
    const std::vector<uint64_t>& local_addrs,
    std::unordered_set<uint64_t>& seen_addrs,
    std::vector<uint64_t>& out_shared
) {
    for (uint64_t addr : local_addrs) {
        if (seen_addrs.insert(addr).second) {
            out_shared.push_back(addr);
        }
    }
}

} // namespace

int main(int argc, char* argv[]) {
    // 输入 so 与输出产物路径（本地调试约定）。
    const char* so_path = "D:\\work\\2026\\0217_vmp_project\\VmpProject\\VmProtect\\libdemo.so";
    const char* expanded_so_path = "libdemo_expand.so";
    const char* shared_branch_file = "branch_addr_list.txt";

    zElf elf(so_path);

    // 支持命令行自定义函数列表；未传参时导出当前完整回归集。
    std::vector<std::string> function_names;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] && argv[i][0] != '\0') {
            function_names.emplace_back(argv[i]);
        }
    }
    if (function_names.empty()) {
        function_names = {
            "fun_for",
            "fun_add",
            "fun_for_add",
            "fun_if_sub",
            "fun_countdown_muladd",
            "fun_loop_call_mix",
            "fun_call_chain",
            "fun_branch_call",
            "fun_cpp_make_string",
            "fun_cpp_string_len",
            "fun_cpp_vector_sum",
            "fun_cpp_virtual_mix",
            "fun_global_data_mix",
            "fun_static_local_table",
            "fun_global_struct_acc",
            "fun_class_static_member",
            "fun_multi_branch_path",
            "fun_switch_dispatch",
            "fun_bitmask_branch",
            "fun_global_table_rw",
            "fun_global_mutable_state",
        };
    }

    std::vector<zFunction*> functions;
    functions.reserve(function_names.size());
    for (const std::string& function_name : function_names) {
        zFunction* function = elf.getfunction(function_name.c_str());
        if (!function) {
            LOGE("获取 zFunction 失败: %s", function_name.c_str());
            return 1;
        }

        LOGI("找到函数 %s 在偏移: 0x%llx",
             function->name().c_str(),
             static_cast<unsigned long long>(function->offset()));
        functions.push_back(function);
    }

    // 第一阶段：收集全局共享 branch_addr_list（顺序稳定：按函数顺序 + 首次出现顺序）。
    std::vector<uint64_t> shared_branch_addrs;
    std::unordered_set<uint64_t> seen_addrs;
    for (zFunction* function : functions) {
        appendUniqueBranchAddrs(function->sharedBranchAddrs(), seen_addrs, shared_branch_addrs);
    }

    if (!writeSharedBranchAddrList(shared_branch_file, shared_branch_addrs)) {
        LOGE("写入共享分支地址文件失败: %s", shared_branch_file);
        return 1;
    }

    std::vector<zSoBinPayload> payloads;
    payloads.reserve(functions.size());

    // 第二阶段：统一 remap OP_BL 索引后导出 txt/bin，再收集 bin 载荷。
    for (size_t i = 0; i < functions.size(); ++i) {
        zFunction* function = functions[i];
        const std::string& function_name = function_names[i];

        if (!function->remapBlToSharedBranchAddrs(shared_branch_addrs)) {
            LOGE("重映射 OP_BL 到共享分支表失败: %s", function_name.c_str());
            return 1;
        }

        const std::string txt_name = function_name + ".txt";
        const std::string bin_name = function_name + ".bin";

        if (!function->dump(txt_name.c_str(), zFunction::DumpMode::UNENCODED)) {
            LOGE("导出未编码文本失败: %s", txt_name.c_str());
            return 1;
        }
        if (!function->dump(bin_name.c_str(), zFunction::DumpMode::ENCODED)) {
            LOGE("导出编码二进制失败: %s", bin_name.c_str());
            return 1;
        }

        zSoBinPayload payload;
        payload.fun_addr = static_cast<uint64_t>(function->offset());
        if (!readFileBytes(bin_name.c_str(), payload.encoded_bytes) || payload.encoded_bytes.empty()) {
            LOGE("读取编码二进制失败: %s", bin_name.c_str());
            return 1;
        }
        payloads.push_back(std::move(payload));
    }

    // 第三阶段：生成带多 payload + 共享 branch_addr_list 的扩展 so。
    if (!zSoBinBundleWriter::writeExpandedSo(
            so_path,
            expanded_so_path,
            payloads,
            shared_branch_addrs)) {
        LOGE("生成扩展 so 失败: %s", expanded_so_path);
        return 1;
    }

    LOGI("导出完成: payload_count=%u shared_branch_addr_count=%u",
         static_cast<unsigned int>(payloads.size()),
         static_cast<unsigned int>(shared_branch_addrs.size()));
    return 0;
}
