# ARM64 Translation Coverage Board

| Metric | Value |
| --- | ---: |
| Total instructions | 780 |
| Supported instructions | 780 |
| Unsupported instructions | 0 |

## Per Function

| Function | Total | Supported | Unsupported | Translation OK | Translation Error |
| --- | ---: | ---: | ---: | --- | --- |
| fun_for | 26 | 26 | 0 | yes | - |
| fun_add | 8 | 8 | 0 | yes | - |
| fun_for_add | 34 | 34 | 0 | yes | - |
| fun_if_sub | 21 | 21 | 0 | yes | - |
| fun_countdown_muladd | 24 | 24 | 0 | yes | - |
| fun_loop_call_mix | 39 | 39 | 0 | yes | - |
| fun_call_chain | 25 | 25 | 0 | yes | - |
| fun_branch_call | 31 | 31 | 0 | yes | - |
| fun_cpp_make_string | 81 | 81 | 0 | yes | - |
| fun_cpp_string_len | 31 | 31 | 0 | yes | - |
| fun_cpp_vector_sum | 71 | 71 | 0 | yes | - |
| fun_cpp_virtual_mix | 56 | 56 | 0 | yes | - |
| fun_global_data_mix | 26 | 26 | 0 | yes | - |
| fun_static_local_table | 48 | 48 | 0 | yes | - |
| fun_global_struct_acc | 36 | 36 | 0 | yes | - |
| fun_class_static_member | 19 | 19 | 0 | yes | - |
| fun_multi_branch_path | 66 | 66 | 0 | yes | - |
| fun_switch_dispatch | 55 | 55 | 0 | yes | - |
| fun_bitmask_branch | 34 | 34 | 0 | yes | - |
| fun_global_table_rw | 22 | 22 | 0 | yes | - |
| fun_global_mutable_state | 27 | 27 | 0 | yes | - |

## Unsupported Instructions

| Instruction | Count |
| --- | ---: |

## Supported Instructions

| Instruction | Count |
| --- | ---: |
| ldr(634) | 177 |
| str(1182) | 122 |
| b(51) | 110 |
| add(22) | 103 |
| bl(95) | 49 |
| sub(1211) | 44 |
| subs(1210) | 38 |
| ldur(710) | 25 |
| ret(887) | 21 |
| adrp(24) | 17 |
| stur(1188) | 17 |
| orr(774) | 11 |
| ldp(629) | 9 |
| stp(1180) | 9 |
| mrs(752) | 7 |
| movz(750) | 6 |
| ldrsw(638) | 3 |
| and(32) | 2 |
| strb(1181) | 2 |
| tbz(1250) | 2 |
| blr(96) | 1 |
| csel(284) | 1 |
| ldrb(633) | 1 |
| ldurb(709) | 1 |
| tbnz(1247) | 1 |
| ubfm(1281) | 1 |

