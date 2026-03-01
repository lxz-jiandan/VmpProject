# ARM64 Translation Coverage Board

| Metric | Value |
| --- | ---: |
| Total instructions | 337 |
| Supported instructions | 337 |
| Unsupported instructions | 0 |

## Per Function

| Function | Total | Supported | Unsupported | Translation OK | Translation Error |
| --- | ---: | ---: | ---: | --- | --- |
| fun_cpp_make_string | 81 | 81 | 0 | yes | - |
| fun_div_mod_chain | 51 | 51 | 0 | yes | - |
| fun_cpp_vector_sum | 71 | 71 | 0 | yes | - |
| fun_static_local_table | 48 | 48 | 0 | yes | - |
| fun_csinc_path | 13 | 13 | 0 | yes | - |
| fun_ext_insn_mix | 20 | 20 | 0 | yes | - |
| fun_ret_bool_mix2 | 53 | 53 | 0 | yes | - |

## Unsupported Instructions

| Instruction | Count |
| --- | ---: |

## Supported Instructions

| Instruction | Count |
| --- | ---: |
| ldr(634) | 69 |
| str(1182) | 51 |
| b(51) | 42 |
| add(22) | 38 |
| bl(95) | 26 |
| sub(1211) | 22 |
| subs(1210) | 16 |
| orr(774) | 8 |
| ret(887) | 7 |
| ldur(710) | 6 |
| stur(1188) | 6 |
| movz(750) | 5 |
| strb(1181) | 5 |
| and(32) | 4 |
| csinc(285) | 4 |
| ldrb(633) | 4 |
| mrs(752) | 4 |
| ubfm(1281) | 4 |
| adrp(24) | 2 |
| ldp(629) | 2 |
| ldrsw(638) | 2 |
| madd(731) | 2 |
| sbfm(939) | 2 |
| stp(1180) | 2 |
| tbnz(1247) | 2 |
| adds(18) | 1 |
| tbz(1250) | 1 |

