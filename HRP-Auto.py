#模块导入 需要自行安装openai tenacity
import idautils
import ida_funcs
import idc
import json
import idaapi
from collections import deque, defaultdict
from openai import OpenAI
from idautils import XrefsTo
import math
from datetime import datetime
from ida_funcs import get_func, get_func_name
from collections import deque
import random
from tenacity import (
    retry,
    wait_exponential,
    stop_after_attempt,
    retry_if_exception_type
)
import openai
import concurrent.futures
import math
import time

try:
    import ida_hexrays
    HAVE_HEXRAYS = True
except ImportError:
    HAVE_HEXRAYS = False

#全局存储代码片段，用以在html生成调用
global_code_dict = defaultdict(lambda: {"pseudo_code": [], "assembly": []})

#危险函数列表，通过IDA控件选择检测类型后通过DANGER_CATEGORIES进行筛选去重赋予到DANGER_FUNCTIONS
DANGER_FUNCTIONS = []

#危险函数总字典
DANGER_CATEGORIES = {
    # 内存操作不当导致的缓冲区溢出或内存破坏
    "buffer_overflow": [
        "fgets",    # 缓冲区大小参数错误时溢出
        "gets",     # 无边界检查输入
        "read",     # 未校验读取长度
        "strncpy",  # 截断导致内容丢失或溢出
        "strcpy",   # 无长度检查的字符串复制
        "memcpy",   # 缺少边界检查的内存复制
        "strcat",   # 无长度控制的字符串拼接
        "sprintf",  # 格式化输出长度不可控
        "vsprintf", # 变参版本sprintf
        "snprintf", # 长度参数错误时仍可能溢出
        "recv",     # 网络数据长度未校验
        "recvfrom", # 同recv
        "strtok"    # 非线程安全的内存操作
    ],
    
    # 直接/间接执行系统命令
    "command_injection": [
        "system",   # 直接执行shell命令
        "popen",    # 管道方式执行命令
        "execl",    # 执行外部程序
        "dlopen"    # 加载动态库(可能执行初始化代码)
    ],
    
    # 用户可控的格式化字符串
    "format_string": [
        "sprintf",  # 格式化字符串输出
        "vsprintf", # 变参版本sprintf
        "printf",   # 直接输出格式化字符串
        "syslog",   # 系统日志接口
        "scanf",    # 格式化字符串输入
        "snprintf"  # 参数可控时仍存在风险
    ],
    
    # 路径处理不当导致越权访问
    "directory_traversal": [
        "dlopen",   # 加载非预期路径的动态库
        "chmod",    # 权限配置可能被路径利用
        "access",   # 存在目录穿越漏洞
    ],
    
    # 资源使用存在时间差漏洞
    "race_condition": [
        "access",   # 检查与使用之间的TOCTOU
        "vfork",    # 进程复制时的竞态窗口
        "strtok"    # 多线程使用时状态冲突
    ]
}

#危险函数解释字典，用以传递LLM进行提示分析
DANGER_FUNCTIONS_DOC = {
    "fgets": {
        "作用": "从文件流中读取字符串",
        "参数解析": [
            ("char *str", "存储读取内容的缓冲区地址"),
            ("int n", "最多读取的字符数(通常为缓冲区长度)"),
            ("FILE *stream", "要读取的文件流指针")
        ],
        "风险说明": "IoT设备常受限内存，若n值大于缓冲区实际长度可能引发溢出"
    },

    "system": {
        "作用": "执行操作系统命令",
        "参数解析": [
            ("const char *command", "要执行的shell命令字符串")
        ],
        "风险说明": "IoT设备常以高权限运行，命令注入可直接控制设备"
    },

    "gets": {
        "作用": "从标准输入读取字符串",
        "参数解析": [
            ("char *str", "目标缓冲区地址")
        ],
        "风险说明": "无长度限制的输入可能造成缓冲区溢出（已从C11标准移除）"
    },

    "read": {
        "作用": "从文件描述符读取数据",
        "参数解析": [
            ("int fd", "文件描述符"),
            ("void *buf", "数据存储缓冲区"),
            ("size_t count", "最大读取字节数")
        ],
        "风险说明": "IoT设备可能未校验count与缓冲区实际大小的匹配性"
    },

    "popen": {
        "作用": "创建管道执行命令",
        "参数解析": [
            ("const char *command", "要执行的shell命令"),
            ("const char *type", "管道类型：'r'读取或'w'写入")
        ],
        "风险说明": "与system相同存在命令注入风险，且可能泄露执行结果"
    },

    "strncpy": {
        "作用": "有限长度的字符串拷贝",
        "参数解析": [
            ("char *dest", "目标缓冲区地址"),
            ("const char *src", "源字符串地址"), 
            ("size_t n", "最大拷贝字节数")
        ],
        "风险说明": "IoT设备常处理定长协议，n设置错误可能导致未终止字符串"
    },

    "strcpy": {
        "作用": "字符串拷贝",
        "参数解析": [
            ("char *dest", "目标缓冲区地址"),
            ("const char *src", "源字符串地址")
        ],
        "风险说明": "源字符串长度超过目标缓冲区时必然溢出"
    },

    "memcpy": {
        "作用": "内存数据块复制",
        "参数解析": [
            ("void *dest", "目标地址"),
            ("const void *src", "源地址"),
            ("size_t n", "复制的字节数")
        ],
        "风险说明": "IoT设备常直接操作硬件寄存器，n值错误可能覆盖关键内存"
    },

    "strcat": {
        "作用": "字符串拼接",
        "参数解析": [
            ("char *dest", "目标缓冲区地址"),
            ("const char *src", "源字符串地址")
        ],
        "风险说明": "IoT设备处理长URL或路径时易造成缓冲区越界"
    },

    "sprintf": {
        "作用": "格式化字符串写入缓冲区",
        "参数解析": [
            ("char *str", "目标缓冲区地址"),
            ("const char *format", "格式化字符串"),
            ("...", "可变参数列表")
        ],
        "风险说明": "当format参数被攻击者控制时，可泄露内存或修改数据"
    },

    "vsprintf": {
        "作用": "变参版本的sprintf",
        "参数解析": [
            ("char *str", "目标缓冲区地址"),
            ("const char *format", "格式化字符串"),
            ("va_list ap", "参数列表")
        ],
        "风险说明": "与sprintf风险相同，在IoT日志模块中常见此函数"
    },

    "scanf": {
        "作用": "格式化输入解析",
        "参数解析": [
            ("const char *format", "格式控制字符串"),
            ("...", "接收输入的变量地址")
        ],
        "风险说明": "IoT设备配置接口若使用%s等格式符可能引发溢出"
    },

    "snprintf": {
        "作用": "带长度限制的格式化写入",
        "参数解析": [
            ("char *str", "目标缓冲区地址"),
            ("size_t size", "缓冲区大小"),
            ("const char *format", "格式化字符串"),
            ("...", "可变参数列表")
        ],
        "风险说明": "若size参数使用sizeof(buf)但buf是指针而非数组时计算错误"
    },

    "recv": {
        "作用": "从套接字接收数据",
        "参数解析": [
            ("int sockfd", "套接字描述符"),
            ("void *buf", "接收缓冲区"),
            ("size_t len", "缓冲区长度"),
            ("int flags", "接收标志如MSG_WAITALL")
        ],
        "风险说明": "IoT设备处理网络协议时，未校验len与协议定义的长度是否匹配"
    },

    "recvfrom": {
        "作用": "接收数据并获取来源地址",
        "参数解析": [
            ("int sockfd", "套接字描述符"),
            ("void *buf", "接收缓冲区"),
            ("size_t len", "缓冲区长度"),
            ("int flags", "接收标志"),
            ("struct sockaddr *src_addr", "来源地址存储"),
            ("socklen_t *addrlen", "地址结构长度")
        ],
        "风险说明": "同时存在recv的风险和地址结构处理不当的风险"
    },

    "strtok": {
        "作用": "字符串分割",
        "参数解析": [
            ("char *str", "待分割字符串（首次调用需指定，后续可NULL）"),
            ("const char *delim", "分隔符集合")
        ],
        "风险说明": "IoT多线程服务中使用可能导致内存状态不一致"
    },

    "printf": {
        "作用": "格式化输出到标准输出",
        "参数解析": [
            ("const char *format", "格式化字符串"),
            ("...", "可变参数列表")
        ],
        "风险说明": "当format来自不可信源时，可泄露寄存器/栈数据（在ARM架构IoT设备中常见）"
    },

    "syslog": {
        "作用": "写入系统日志",
        "参数解析": [
            ("int priority", "日志优先级如LOG_ERR"),
            ("const char *format", "格式化字符串"),
            ("...", "可变参数列表")
        ],
        "风险说明": "IoT设备日志模块常直接传递用户输入给format参数"
    },

    "dlopen": {
        "作用": "动态加载共享库",
        "参数解析": [
            ("const char *filename", "库文件路径（NULL表示主程序）"),
            ("int mode", "加载模式：RTLD_LAZY/RTLD_NOW等")
        ],
        "风险说明": "加载恶意so文件可能导致提权，IoT设备固件更新机制需特别注意"
    },

    "chmod": {
        "作用": "修改文件权限",
        "参数解析": [
            ("const char *path", "文件路径"),
            ("mode_t mode", "权限位（如0644）")
        ],
        "风险说明": "IoT设备需严格权限控制，错误设置777权限可能暴露敏感文件"
    },

    "access": {
        "作用": "检查文件访问权限",
        "参数解析": [
            ("const char *pathname", "文件路径"),
            ("int mode", "检查模式：F_OK/R_OK/W_OK/X_OK")
        ],
        "风险说明": "TOCTOU竞态条件可能被利用修改设备固件验证结果"
    },

    "execl": {
        "作用": "执行新程序",
        "参数解析": [
            ("const char *path", "可执行文件路径"),
            ("const char *arg", "参数列表（以NULL结尾）"),
            ("...", "可变参数列表")
        ],
        "风险说明": "IoT设备若通过此函数调用不可信路径程序，可能导致持久化攻击"
    },

    "vfork": {
        "作用": "创建子进程（已过时）",
        "参数解析": [],
        "风险说明": "共享地址空间特性易导致内存损坏，IoT实时系统可能仍在使用"
    }
}

# 定义分析结果存储类
class AnalysisResult:
    # 初始化方法，创建存储结构
    def __init__(self):
        # 存储原始输出内容的列表（控制台输出）
        self.raw_output = []
        # 结构化数据存储字典
        self.structured_data = {
            # 预定义的危险函数集合（需外部定义DANGER_FUNCTIONS）
            "danger_functions": DANGER_FUNCTIONS,
            # 使用默认字典存储危险调用链，键为危险函数名，值为调用链列表
            "danger_chains": defaultdict(list),
            # 统计分析数据
            "statistics": {
                "total_danger": 0,       # 总危险计数（初始化后未在类中更新）
                "unique_paths": 0,       # 唯一调用路径计数
            }
        }
    
    # 添加结构化调用链数据的方法
    def add_structured_chain(self, danger_name, caller_ea, path, code_snippets):
        # 构建调用链条目
        chain_entry = {
            "caller_address": hex(caller_ea),  # 调用者地址转十六进制
            # 构建完整的调用链
            "call_chain": [{
                "name": name,                   # 函数名
                "address": hex(ea),             # 地址转十六进制
                "pseudo_code": code_snippets[i][0],  # 对应位置的伪代码
                "assembly": code_snippets[i][1]       # 对应位置的汇编代码
            } for i, (name, ea) in enumerate(path)]  # 遍历路径中的每个节点
        }
        # 将调用链添加到对应危险函数的列表中
        self.structured_data["danger_chains"][danger_name].append(chain_entry)
        # 增加唯一路径计数
        self.structured_data["statistics"]["unique_paths"] += 1
    
    # 添加原始输出内容的方法
    def add_output(self, content):
        # 将内容追加到原始输出列表
        self.raw_output.append(content)
        # 同步打印到控制台
        print(content)
    
    #存储代码片段
    def add_code_snippet(self, ea, code):
        if ea not in self.structured_data["code_snippets"]:
            self.structured_data["code_snippets"][hex(ea)] = code
            self.structured_data["statistics"]["called_functions"] += 1
    
    # 获取组合输出结果的接口方法
    def get_combined_output(self):
        return {
            # 将原始输出列表连接为字符串
            "console_output": "\n".join(self.raw_output),
            # 返回完整的结构化数据
            "analysis_data": self.structured_data
        }

#获取汇编代码和伪代码
def print_pseudo_code(ea, result_collector):
    code = []
    if HAVE_HEXRAYS:
        try:
            f = ida_funcs.get_func(ea)
            pcode = ida_hexrays.decompile(f)
            if pcode:
                code_content = "伪代码：\n" + str(pcode)
                result_collector.add_output(code_content)
                code.append(code_content)
                return "\n".join(code)
        except Exception as e:
            error_msg = f"伪代码生成失败：{str(e)}"
            result_collector.add_output(error_msg)
            code.append(error_msg)
    
    disasm = ["反汇编代码："]
    for line in idautils.FuncItems(ea):
        line_content = f"0x{line:08X}: {idc.GetDisasm(line)}"
        disasm.append(line_content)
        result_collector.add_output(line_content)
    return "\n".join(disasm)


#污染链追踪函数，通过限制总路径数和最大子节点数实现早停避免路径爆炸的情况
#（缺点：可能存在无法全路径覆盖的情况，但是这样也是无可奈何的比较LLM的开销也是分析成本，尽可能限制在每个危险函数包含数百条路径是比较合理的）
def get_full_call_chains(target_func_ea, max_depth, 
                        max_children_per_node=50,  
                        max_total_chains=500,    
                        enable_random_sampling=True): 
    """
    - target_func_ea 危险函数起始地址
    - max_depth 最大路径溯源深度
    - max_children_per_node: 单个函数节点最大展开的调用者数量（剪枝阈值）
    - max_total_chains: 允许的最大总路径数量（防内存溢出）
    - enable_random_sampling: 当子节点超限时启用随机采样代替直接截断
    """
    target_func = get_func(target_func_ea)
    if not target_func:
        print(f"Error: Invalid target function at {hex(target_func_ea)}")
        return []

    # 初始化数据结构（保持原有结构不变）
    func_cache = set(idautils.Functions())
    xref_cache = defaultdict(list)
    valid_chains = []
    visited = set()
    
    # 调试计数器
    search_counter = 0
    
    # 使用双端队列实现BFS
    queue = deque()

    # 初始化目标函数的调用者（保持不变）
    initial_callers = []
    for xref in XrefsTo(target_func_ea):
        if xref.type in (0,1,2,3,4,5,16,17,18,19,20,21):
            caller_ea = xref.frm
            caller_func = get_func(caller_ea)
            if caller_func and caller_func.start_ea in func_cache:
                initial_callers.append( (caller_ea, caller_func.start_ea) )

    if not initial_callers:
        print(f"No callers found for target function {hex(target_func_ea)}")
        return []

    # 将初始调用者加入队列（保持不变）
    for insn_ea, func_ea in initial_callers:
        chain = [(insn_ea, func_ea)]
        path_signature = (func_ea, tuple([func_ea]))
        if path_signature not in visited:
            visited.add(path_signature)
            queue.append( (chain, 1) )

    # 主循环处理（添加剪枝逻辑）
    while queue:
        # 新增：提前终止条件
        if len(valid_chains) >= max_total_chains:
            print(f"WARNING: 达到最大路径数量限制 {max_total_chains}，提前终止搜索")
            break
            
        current_chain, current_depth = queue.popleft()
        search_counter += 1
        
        # 调试输出（保持原有逻辑）
        if search_counter % 1000 == 0:
            print(f"Processing #{search_counter} | Depth:{current_depth} | Queue:{len(queue)} | TotalChains:{len(valid_chains)}")

        # 终止条件：达到最大深度（保持不变）
        if current_depth >= max_depth:
            valid_chains.append(current_chain)
            continue

        # 获取当前函数（保持不变）
        last_func_ea = current_chain[-1][1]
        
        # 动态加载交叉引用（保持不变）
        if last_func_ea not in xref_cache:
            xrefs = []
            for xref in XrefsTo(last_func_ea):
                if xref.type in (0,1,2,3,4,5,16,17,18,19,20,21):
                    xrefs.append(xref.frm)
            xref_cache[last_func_ea] = xrefs

        # 收集有效调用者（保持不变）
        new_callers = []
        for caller_insn_ea in xref_cache[last_func_ea]:
            caller_func = get_func(caller_insn_ea)
            if not caller_func or caller_func.start_ea not in func_cache:
                continue
                
            caller_func_ea = caller_func.start_ea
            
            # 环路检测（保持不变）
            chain_funcs = {func_ea for _, func_ea in current_chain}
            if caller_func_ea in chain_funcs:
                continue
                
            new_callers.append( (caller_insn_ea, caller_func_ea) )

        # ============== 新增剪枝逻辑 ==============
        if len(new_callers) > max_children_per_node:
            print(f"剪枝：函数 {hex(last_func_ea)} 有 {len(new_callers)} 个调用者，超过阈值 {max_children_per_node}")
            
            if enable_random_sampling:
                # 随机采样策略（保持多样性）
                new_callers = random.sample(new_callers, max_children_per_node)
            else:
                # 简单截断策略（保证确定性）
                new_callers = new_callers[:max_children_per_node]
        # ============== 剪枝结束 ==============

        # 记录有效路径（保持不变）
        if not new_callers:
            valid_chains.append(current_chain)
        else:
            for caller in new_callers:
                new_chain = current_chain + [caller]
                new_func_ea = caller[1]
                
                func_sequence = tuple([x[1] for x in new_chain])
                path_signature = (new_func_ea, func_sequence)
                
                if path_signature not in visited:
                    visited.add(path_signature)
                    queue.append( (new_chain, current_depth + 1) )

    # 路径后处理（保持不变）
    final_chains = []
    for chain in valid_chains:
        reversed_chain = list(reversed(chain))
        final_chain = reversed_chain + [(target_func_ea, target_func_ea)]
        final_chains.append(final_chain)
        
        if len(final_chains) % 100 == 0:
            print(f"Found chain #{len(final_chains)}: {' -> '.join([hex(x[1]) for x in final_chain])}")

    print(f"Search complete. Total chains: {len(final_chains)}")
    return final_chains


def analyze_danger_calls(params, debug):
    result = AnalysisResult()
    result.add_output("【IDA Pro 智能分析系统】")
    
    # 初始化完整数据结构
    full_analysis_data = {
        "danger_functions": DANGER_FUNCTIONS,
        "call_chains": defaultdict(list),
        "statistics": {
            "total_danger": 0,
            "unique_paths": 0
        }
    }

    # 收集危险函数
    danger_map = defaultdict(list)
    for func_ea in idautils.Functions():
        name = ida_funcs.get_func_name(func_ea)
        if name in DANGER_FUNCTIONS:
            danger_map[name].append(func_ea)
            full_analysis_data["statistics"]["total_danger"] += 1

    if not danger_map:
        result.add_output("警告：未发现危险函数")
        return full_analysis_data

    # 处理每个危险函数
    for danger_name, addresses in danger_map.items():
        result.add_output(f"\n▌ 追踪 {danger_name} 调用路径...")
        
        for danger_ea in addresses:
            # 获取完整调用链
            chains = get_full_call_chains(danger_ea, max_total_chains=params['limit_chains_length'], max_depth=params['max_depth'])
            
            # 处理每个调用链
            for chain in chains:
                code_snippets = []
                raw_path = []
                readable_chain = []
                
                # 遍历调用链每个节点
                for call_insn_ea, func_ea in chain:
                    # 获取函数信息
                    func_name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:08X}"
                    raw_path.append((func_name, call_insn_ea))
                    readable_chain.append(f"{func_name}({hex(call_insn_ea)})")
                    
                    # 生成伪代码
                    pseudo_code = []
                    try:
                        f = ida_funcs.get_func(func_ea)
                        if HAVE_HEXRAYS:
                            pcode = ida_hexrays.decompile(f)
                            if pcode:
                                pseudo_code = str(pcode).splitlines()
                    except Exception as e:
                        pseudo_code = [f"反编译失败：{str(e)}"]
                    
                    # 生成汇编代码
                    asm_code = []
                    for ins in idautils.FuncItems(func_ea):
                        asm = idc.GetDisasm(ins)
                        asm_code.append(f"{hex(ins)}: {asm}")
                    
                    # 存储代码片段
                    code_snippets.append((
                        "\n".join(pseudo_code),
                        "\n".join(asm_code)
                    ))

                    # 将 pseudo_code 和 assembly 存储到全局字典中
                    # 检查并避免存储重复的代码片段
                    pseudo_code_str = "\n".join(pseudo_code)
                    asm_code_str = "\n".join(asm_code)
                    
                    if pseudo_code_str not in global_code_dict[func_name]["pseudo_code"]:
                        global_code_dict[func_name]["pseudo_code"].append(pseudo_code_str)
                    
                    if asm_code_str not in global_code_dict[func_name]["assembly"]:
                        global_code_dict[func_name]["assembly"].append(asm_code_str)

                # 记录结构化数据
                chain_entry = {
                    "caller_address": hex(chain[-1][1]),
                    "call_chain": [{
                        "name": name,
                        "address": hex(func_ea),
                        "pseudo_code": code_snippets[i][0],
                        "assembly": code_snippets[i][1]
                    } for i, (name, func_ea) in enumerate(raw_path)]
                }

                full_analysis_data["call_chains"][danger_name].append(chain_entry)
                full_analysis_data["statistics"]["unique_paths"] += 1

    # 生成统计信息
    result.add_output("\n" + "="*80)
    result.add_output("漏洞调用路径分析报告")
    result.add_output("="*80)
    
    # 输出详细路径信息
    for danger in full_analysis_data["call_chains"]:
        result.add_output(f"\n🔴 危险函数：{danger}")
        
        # 聚合相同路径
        chain_counter = defaultdict(list)
        for entry in full_analysis_data["call_chains"][danger]:
            chain_str = " → ".join([f"{node['name']}({node['address']})" 
                                  for node in entry["call_chain"]])
            chain_counter[chain_str].append(entry["caller_address"])
        
        # 输出格式化路径
        for chain_idx, (chain, addrs) in enumerate(chain_counter.items(), 1):
            result.add_output(f"[路径{chain_idx:02d}] {chain}")
            for addr in addrs:
                result.add_output(f"    ↳ 调用入口地址: {addr}")

    # 执行LLM分析
    json_report = batch_analyze_with_llm(full_analysis_data, debug, params)
    return json_report




# 重试装饰器（必须放在所有函数之前）
@retry(
    wait=wait_exponential(multiplier=1, min=4, max=60),
    stop=stop_after_attempt(5),
    retry=(retry_if_exception_type(openai.RateLimitError) | 
          retry_if_exception_type(openai.APITimeoutError)),
    before_sleep=lambda _: print("触发重试机制，等待API恢复...")
)
def analyze_with_llm(debug, params, analysis_data, console_output):
    """原始LLM调用逻辑完全保留"""
    client = openai.OpenAI(api_key=params['api_key'])
    
    try:
        response = client.chat.completions.create(
            model=params['llm_model'],
            messages=[
                {"role": "system", "content": "你是一个全球顶尖的二进制安全分析专家"},
                {"role": "user", "content": console_output}
            ],
            temperature=params['temperature'],
            max_tokens=params['max_output_tokens']
        )
        return response.choices[0].message.content
    except Exception as e:
        if debug:
            print(f"LLM API Error: {str(e)}")
        return f"分析失败：{str(e)}"

def batch_analyze_with_llm(full_data, debug, params):
    BATCH_SIZE = params['batch_size']
    json_report = {
        "danger_functions": full_data["danger_functions"],
        "analysis": [],
        "statistics": full_data["statistics"]
    }

    # 全局异步控制器（新增部分）
    global async_controller
    async_controller = {
        "should_stop": False,
        "futures": [],
        "executor": None
    }

    # 并发控制参数
    MAX_WORKERS = 10
    REQUEST_INTERVAL = 5
    last_request_time = time.time()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            async_controller["executor"] = executor  # 记录执行器
            futures = []
            
            # 遍历所有危险函数
            for danger_func in full_data["call_chains"]:
                # 添加中止检查点（新增）
                if async_controller["should_stop"]:
                    print("[中止] 危险函数遍历已停止")
                    break
                    
                danger_chains = full_data["call_chains"][danger_func]

                # 原始批处理循环
                for batch_idx in range(0, len(danger_chains), BATCH_SIZE):
                    # 添加中止检查点（新增）
                    if async_controller["should_stop"]:
                        print(f"[中止] 停止处理批次 {batch_idx}")
                        break
                    
                    batch = danger_chains[batch_idx : batch_idx+BATCH_SIZE]
                    batch_context = []
                    
                    # 处理每个调用链条目（完整保留原始代码）
                    for chain_entry in batch:
                        chain_nodes = []
                        call_path = []  # 完整调用路径
                        code_snippets = []  # 各节点代码片段
                        
                        # 生成调用路径标识
                        path_identifier = " → ".join(
                            [f"{node['name']}@{node['address']}" 
                             for node in chain_entry["call_chain"]]
                        )
                        call_path.append(path_identifier)
                        
                        # 处理调用链每个节点
                        for node in chain_entry["call_chain"]:
                            # 代码智能分段处理
                            pseudo_lines = node["pseudo_code"].split('\n')
                            asm_lines = node["assembly"].split('\n')
                            
                            # 生成带上下文标记的代码
                            code_context = {
                                "func_name": node["name"],
                                "address": node["address"],
                                "pseudo_code": "\n".join([
                                    f"/* {node['name']} 伪代码片段 */",
                                    *pseudo_lines
                                ]),
                                "asm_code": "\n".join([
                                    f"; {node['name']} 汇编片段",
                                    *asm_lines
                                ]),
                                "key_marks": {
                                    "buffer_ops": [
                                        line for line in pseudo_lines 
                                        if any(kw in line for kw in full_data["danger_functions"])
                                    ], 
                                    "danger_calls": [
                                        line for line in asm_lines
                                        if "call" in line
                                    ]
                                }
                            }
                            chain_nodes.append(code_context)
                            code_snippets.append({
                                "address": node["address"],
                                "pseudo": code_context["pseudo_code"],
                                "asm": code_context["asm_code"]
                            })
                        
                        # 构建调用链条目
                        batch_entry = {
                            "chain_id": f"{danger_func}_chain_{len(batch_context)+1}",
                            "nodes": chain_nodes,
                            "call_path": call_path,
                            "code_snippets": code_snippets,
                            "risk_factors": {
                                "buffer_operations": sum(1 for n in chain_nodes if n["key_marks"]["buffer_ops"]),
                                "dangerous_calls": sum(1 for n in chain_nodes if n["key_marks"]["danger_calls"])
                            },
                            "path_analysis": {
                                "depth": len(chain_entry["call_chain"]),
                                "entry_point": chain_entry["call_chain"][0]["address"],
                                "exit_point": chain_entry["call_chain"][-1]["address"]
                            }
                        }
                        batch_context.append(batch_entry)

                    # 构建LLM请求数据（完整保留原始结构）
                    llm_request_data = {
                        "metadata": {
                            "danger_function": danger_func,
                            "current_call_paths": [
                                {
                                    "path": chain["call_path"][0],
                                    "depth": chain["path_analysis"]["depth"],
                                    "entry": chain["path_analysis"]["entry_point"],
                                    "exit": chain["path_analysis"]["exit_point"]
                                } for chain in batch_context
                            ],
                            "batch_info": {
                                "current": (batch_idx // BATCH_SIZE) + 1,
                                "total": math.ceil(len(danger_chains)/BATCH_SIZE),
                                "chain_count": len(batch_context)
                            }
                        },
                        "chains": batch_context
                    }

                    # 生成原始提示词（完整保留模板）
                    llm_prompt = f"""二进制安全分析请求 - {danger_func}

=== 分析目标 ===
1. 追踪{danger_func}的参数传播路径
2. 验证缓冲区操作安全性
3. 识别未过滤的危险数据流
4. 重点分析{danger_func}在当前可能引起的危害

=== 调用链上下文 ===
共有 {len(batch_context)} 条调用链需要分析"""

                    for chain in batch_context:
                        llm_prompt += f"""
                        
▌ 调用链 {chain['chain_id']} 
• 完整路径：{chain['call_path'][0]}
• 深度：{chain['path_analysis']['depth']} 层
• 入口：{chain['path_analysis']['entry_point']}
• 出口：{chain['path_analysis']['exit_point']}
[风险系数：{chain['risk_factors']['buffer_operations']} 缓冲区操作 / {chain['risk_factors']['dangerous_calls']} 危险调用]"""

                        for node in chain["nodes"]:
                            llm_prompt += f"""
                            
▸ 函数 {node['func_name']} ({node['address']})
[伪代码片段]
{node['pseudo_code']}

[汇编片段] 
{node['asm_code']}"""

                    llm_prompt += f"""

=== 分析要求 ===
* 必须结合调用路径上下文进行分析
* 对路径中的每个节点执行以下检查：
  1. 参数传递是否经过过滤
  2. 缓冲区大小是否被正确校验
  3. 是否存在危险函数组合风险
* 对跨函数数据流进行追踪分析"""

                    # 速率控制核心逻辑（完整保留）
                    current_time = time.time()
                    elapsed = current_time - last_request_time
                    if elapsed < REQUEST_INTERVAL:
                        sleep_time = REQUEST_INTERVAL - elapsed
                        time.sleep(sleep_time)
                    
                    # 提交异步任务（添加future记录）
                    future = executor.submit(
                        _async_llm_analysis,
                        danger_func,
                        batch_context.copy(),
                        llm_request_data.copy(),
                        llm_prompt,
                        debug,
                        params
                    )
                    futures.append(future)
                    async_controller["futures"].append(future)  # 记录future
                    last_request_time = time.time()

            # 结果收集（完整保留+中止检查）
            for future in concurrent.futures.as_completed(futures):
                if async_controller["should_stop"]:
                    print("[中止] 停止结果收集")
                    break
                
                try:
                    result = future.result()
                    json_report["analysis"].append(result)
                except Exception as e:
                    if debug:
                        print(f"异步处理异常: {str(e)}")
                    json_report["analysis"].append({
                        "target_function": "ERROR",
                        "llm_response": "用户中止" if async_controller["should_stop"] else f"处理失败: {str(e)}"
                    })

    finally:
        # 资源清理（新增部分）
        if async_controller["executor"]:
            async_controller["executor"].shutdown(wait=False)
        for future in async_controller["futures"]:
            future.cancel()
        print("[资源] 线程池已关闭")

    return json_report

# 新增全局中止函数（需在IDA脚本中止时调用）
def abort_llm_processing():
    global async_controller
    if async_controller:
        print("\n[紧急中止] 正在停止所有LLM处理...")
        async_controller["should_stop"] = True
        
        # 取消所有任务
        for future in async_controller.get("futures", []):
            future.cancel()
            print(f"[中止] 任务 {future} 已取消")
            
        # 立即关闭线程池
        if async_controller.get("executor"):
            async_controller["executor"].shutdown(wait=False)
            print("[中止] 线程池已强制关闭")

def _async_llm_analysis(danger_func, batch_context, llm_request_data, llm_prompt, debug, params):
    """添加中断检查点"""
    if async_controller["should_stop"]:
        return {
            "target_function": danger_func,
            "llm_response": "任务已中止",
            "batch_metadata": llm_request_data["metadata"]
        }
    
    """异步处理包装函数（完整异常处理）"""
    try:
        llm_response = analyze_with_llm(
            debug,
            params,
            analysis_data=llm_request_data,
            console_output=llm_prompt
        )
        
        return {
            "target_function": danger_func,
            "chain_context": {
                "paths": [chain["call_path"] for chain in batch_context],
                "code_snippets": [chain["code_snippets"] for chain in batch_context]
            },
            "llm_response": llm_response,
            "batch_metadata": llm_request_data["metadata"]
        }
    except Exception as e:
        return {
            "target_function": danger_func,
            "llm_response": f"异步处理失败: {str(e)}",
            "batch_metadata": llm_request_data["metadata"]
        }

def analyze_with_llm(debug, params, analysis_data, console_output):
    if debug:
        print(console_output)
    client = OpenAI(
        api_key=params['api_key'],
        base_url=params['api_url'],
        timeout=(10, 200) # 连接超时 10 秒，读取超时 200 秒
    )
    
    # 构造自然语言提示词
    current_danger_func = analysis_data["metadata"]["danger_function"]  # 新增
    prompt = f"""
二进制安全分析请求：
=== 元信息 ===
* 风险函数：{current_danger_func}
* 严格按照下面的JSON格式输出，禁止修改任何字段名，只允许输出JSON格式，但是不需要用```json来标注JSON格式，且回复尽可能使用中文
* 一定要仔细分析结合上下文，尽量避免假阳性报告，对于参数内容需要仔细辨别
* 详细分析每个危险函数的参数，避免误报
* 当前函数的文档{DANGER_FUNCTIONS_DOC[current_danger_func]}
=== 详细分析数据 ===
{console_output}

"""

    # 调用LLM接口
    response = client.chat.completions.create(
        model=params['model'],
        messages=[
            {
                "role": "system",
                "content": '''作为全球顶尖二进制安全分析师和利用员，请执行以下操作：

1. 漏洞利用分析：
   - 识别具体的漏洞类型(CWE)
   - 分析利用所需的控制条件
   - 评估内存破坏的可行性
   - 提供PoC构造思路

2. 防御方案：
   - 给出代码层修复建议
   - 建议编译器防护选项
   - 提供运行时加固措施

3. 输出规范：
   -严格按照下面的JSON格式输出，禁止修改任何字段名，只允许输出JSON格式,此外任何内容都不应该输出，但是不需要用```json来标注JSON格式
   -严格按照下面的JSON格式输出，禁止修改任何字段名，只允许输出JSON格式,此外任何内容都不应该输出，但是不需要用```json来标注JSON格式
   -严格按照下面的JSON格式输出，禁止修改任何字段名，只允许输出JSON格式,此外任何内容都不应该输出，但是不需要用```json来标注JSON格式
   -严格按照下面的JSON格式输出，禁止修改任何字段名，只允许输出JSON格式,此外任何内容都不应该输出，但是不需要用```json来标注JSON格式
   -严格按照下面的JSON格式输出，禁止修改任何字段名，只允许输出JSON格式,此外任何内容都不应该输出，但是不需要用```json来标注JSON格式

4. 严格按照下面的JSON格式输出，禁止修改任何字段名，只允许输出JSON格式，但是不需要用```json来标注JSON格式，且回复尽可能使用中文：
{
  "vulnerability": {
    "cwe_id": "CWE-XXXX",
    "description": "技术描述",
    "cvss": {
      "score": "0到10分",
      "vector": "使用中文描述"
    },
    "victim_func": "必须只针对当前元信息中的风险函数进行分析，忽略其他，如有联动漏洞可以连带分析但是以元信息中的风险函数进行分析为主，如有多个函数可以用逗号分隔"
  },
  "exploit": {
    "how_exploit": ["重点用语言分析，漏洞是怎么触发的，结合上下文代码逻辑，详细分析每个危险函数的参数，先了解每个危险函数的参数再去分析，避免误报"]
  },
  "mitigation": {
    "code_fix": ["代码修改建议"],
    "compiler_flags": ["防护编译选项"],
    "runtime_protections": ["系统级防护"]
  }
}'''
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        stream=True,
        temperature=0.1
    )
    # 处理流式响应
    print("\n[LLM Analysis]")
    full_response = ""
    for chunk in response:
        if chunk.choices[0].delta.content:
            content = chunk.choices[0].delta.content
            print(content, end='', flush=True)
            full_response += content
    
    # 返回结构化结果
    def clean_json(s):
        s = s.strip()
        for marker in ["```json", "```"]:
            if s.startswith(marker):
                s = s[len(marker):]
            if s.endswith(marker):
                s = s[:-len(marker)]
        return s.strip()

    try:
        cleaned = clean_json(full_response)
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {"error": "Invalid LLM response format"}


def isolate_call_chains(analysis_entry):
    """提取并标准化调用链数据(生产级稳健版本)"""
    def normalize_chain(chain_data):
        """统一不同格式的调用链数据结构"""
        # 类型1：旧版字符串格式
        if isinstance(chain_data, str):
            return [node.strip() for node in chain_data.split(" → ") if node.strip()]
        
        # 类型2：字典格式 (带元数据)
        if isinstance(chain_data, dict):
            # 优先使用预处理的路径
            if "path" in chain_data and isinstance(chain_data["path"], list):
                return chain_data["path"]
            # 兼容旧版签名
            if "signature" in chain_data and isinstance(chain_data["signature"], str):
                return [node.strip() for node in chain_data["signature"].split(" → ") if node.strip()]
        
        # 类型3：原始列表格式
        if isinstance(chain_data, list):
            processed = []
            for node in chain_data:
                if isinstance(node, dict):  # 节点带元数据
                    processed.append(f"{node.get('name', 'unnamed')}@{node.get('address', '0x0')}")
                else:  # 纯字符串节点
                    processed.append(str(node))
            return processed
        
        # 未知格式记录日志
        print(f"[WARN] 无法识别的调用链格式: {type(chain_data)}")
        return []

    chains = []
    
    # 源数据可能存在的多种存储位置
    data_sources = [
        analysis_entry.get("chain_context", {}).get("paths", []),
        analysis_entry.get("call_chains", []),
        analysis_entry.get("llm_response", {}).get("call_paths", [])
    ]
    
    for source in data_sources:
        if not isinstance(source, list):
            continue
            
        for chain_entry in source:
            try:
                # 深度校验数据结构
                if isinstance(chain_entry, (str, dict, list)):
                    normalized = normalize_chain(chain_entry)
                    if len(normalized) >= 2:  # 有效链至少包含2个节点
                        chains.append({
                            "signature": " → ".join(normalized),
                            "path": normalized,
                            "depth": len(normalized),
                            "raw_data": chain_entry  # 保留原始数据用于调试
                        })
                else:
                    print(f"[WARN] 忽略非法类型的调用链条目: {type(chain_entry)}")
            except Exception as e:
                print(f"[ERROR] 处理调用链时发生异常: {str(e)}")
                if "raw_data" in locals():
                    print(f"问题数据: {raw_data}")

    # 去重处理
    seen = set()
    unique_chains = []
    for chain in chains:
        chain_hash = hash(tuple(chain["path"]))
        if chain_hash not in seen:
            seen.add(chain_hash)
            unique_chains.append(chain)
    
    # 按深度排序
    return sorted(unique_chains, key=lambda x: x["depth"], reverse=True)

def format_analysis_data(raw_data):
    """整理分析数据的规范化格式(完整版)"""
    formatted = {
        "meta": {
            "danger_functions_count": len(raw_data.get("danger_functions", [])),
            "analyzed_functions": len(raw_data.get("analysis", [])),
            "total_chains": sum(len(item.get("chain_context", {}).get("paths", [])) 
                              for item in raw_data.get("analysis", []))
        },
        "risk_overview": defaultdict(lambda: defaultdict(int)),
        "detailed_analysis": [],
        "statistics": {
            "high_risk": 0,
            "medium_risk": 0,
            "critical_chains": 0
        }
    }

    # 第一阶段：合并相同危险函数的漏洞条目
    merged_entries = defaultdict(lambda: {
        "vulnerability": {
            "types": set(),
            "descriptions": [],
            "control_chains": [],
            "cvss_scores": [],
            "affected_versions": set()
        },
        "call_chains": [],
        "mitigation": {
            "code_fix": set(),
            "compiler_flags": set(),
            "runtime_protections": set()
        }
    })

    # 处理原始数据
    for item in raw_data.get("analysis", []):
        func_name = item.get("target_function", "unknown")
        entry = merged_entries[func_name]
        
        # 合并漏洞信息
        vuln_info = item.get("llm_response", {}).get("vulnerability", {})
        vuln_info_exp = item.get("llm_response", {}).get("exploit", {})

        entry["vulnerability"]["types"].add(vuln_info.get("cwe_id", "CWE-UNKNOWN"))
        entry["vulnerability"]["descriptions"].append(vuln_info.get("description", "未获取漏洞描述"))
        entry["vulnerability"]["control_chains"].extend(
            vuln_info_exp.get("how_exploit", ["无控制点信息"])
        )
        if "cvss" in vuln_info:
            entry["vulnerability"]["cvss_scores"].append(
                float(vuln_info["cvss"].get("score", 0))
            )
        entry["vulnerability"]["affected_versions"].add(
            vuln_info.get("affected_versions", "All versions")
        )

        # 合并修复建议
        mitigations = item.get("llm_response", {}).get("mitigation", {})
        entry["mitigation"]["code_fix"].update(mitigations.get("code_fix", []))
        entry["mitigation"]["compiler_flags"].update(mitigations.get("compiler_flags", []))
        entry["mitigation"]["runtime_protections"].update(
            mitigations.get("runtime_protections", [])
        )

        # 合并调用链(带去重)
        for chain in isolate_call_chains(item):
            if isinstance(chain["path"], str):
                path_list = chain["path"].split(" → ")
            else:
                path_list = chain["path"]
                
            chain_str = " → ".join(path_list)
            if chain_str not in {c["signature"] for c in entry["call_chains"]}:
                entry["call_chains"].append({
                    "signature": chain_str,
                    "path": path_list,  # 确保存储为列表
                    "depth": len(path_list)
                })

    # 第二阶段：重组数据结构
    for func_name, data in merged_entries.items():
        # 计算CVSS平均分
        cvss_scores = data["vulnerability"]["cvss_scores"]
        avg_score = sum(cvss_scores)/len(cvss_scores) if cvss_scores else 0.0
        
        # 生成最终条目
        formatted_entry = {
            "target_function": func_name,
            "vulnerability": {
                "type": ", ".join(data["vulnerability"]["types"]),
                "description": merge_descriptions(data["vulnerability"]["descriptions"]),
                "how_exploit": list(dict.fromkeys(data["vulnerability"]["control_chains"])),
                "cvss": {
                    "score": f"{avg_score:.1f}",
                    "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 示例向量
                },
                "affected_versions": "All versions"  # 合并后的统一版本
            },
            "call_chains": sorted(
                data["call_chains"],
                key=lambda x: x["depth"],
                reverse=True
            ),  
            "mitigation": {
                "code_fix": list(data["mitigation"]["code_fix"]),
                "compiler_flags": list(data["mitigation"]["compiler_flags"]),
                "runtime_protections": list(data["mitigation"]["runtime_protections"])
            }
        }
        
        # 风险等级统计
        score = avg_score
        if score >= 7.0:
            formatted["statistics"]["high_risk"] += 1
        elif 4.0 <= score < 7.0:
            formatted["statistics"]["medium_risk"] += 1
            
        formatted["statistics"]["critical_chains"] += len(formatted_entry["call_chains"])
        
        # 风险概况统计
        risk_level = "HIGH" if score >= 7.0 else "MEDIUM" if score >=4 else "LOW"
        formatted["risk_overview"][func_name][risk_level] += 1
        
        formatted["detailed_analysis"].append(formatted_entry)

    return formatted

def merge_descriptions(descriptions):
    """合并重复的漏洞描述"""
    unique_descs = []
    seen = set()
    for desc in descriptions:
        clean_desc = desc.replace("。", "").strip()
        if clean_desc not in seen:
            seen.add(clean_desc)
            unique_descs.append(desc)
    return "；".join(unique_descs)  

def isolate_call_chains(analysis_entry):
    """提取并标准化调用链数据(增强版)"""
    chains = []
    for path_group in analysis_entry.get("chain_context", {}).get("paths", []):
        if isinstance(path_group, list):
            for path in path_group:
                if isinstance(path, str):
                    chain = path.split(" → ")
                    chains.append({
                        "signature": path,
                        "path": chain,
                        "depth": len(chain)
                    })
        elif isinstance(path_group, dict):
            chains.append({
                "signature": " → ".join(path_group["path"]),
                "path": path_group["path"],
                "depth": len(path_group["path"])
            })
    return chains



def generate_enterprise_report_html(formatted_json):
    """生成完整安全分析报告（左右分栏+动态风险等级）"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # 风险等级分类函数
    def get_risk_level(score):
        cvss_score = float(score.split()[0])
        if cvss_score >= 7.0:
            return ('高危', 'text-red-400')
        elif 4.0 <= cvss_score < 7.0:
            return ('中危', 'text-yellow-400')
        else:
            return ('低危', 'text-green-400')

    # 风险等级统计
    high_risk = sum(1 for e in formatted_json["detailed_analysis"] if float(e['vulnerability']['cvss']['score'].split()[0]) >= 7.0)
    medium_risk = sum(1 for e in formatted_json["detailed_analysis"] if 4.0 <= float(e['vulnerability']['cvss']['score'].split()[0]) < 7.0)
    low_risk = sum(1 for e in formatted_json["detailed_analysis"] if float(e['vulnerability']['cvss']['score'].split()[0]) < 4.0)
    total_vulns = high_risk + medium_risk + low_risk

    # JavaScript核心交互逻辑
    js = f"""
    <script>
    const globalCodeDict = {json.dumps(global_code_dict)};
    
    // 分页功能实现
    let currentFilteredVulnItems = [];
    let currentPage = 0;
    const itemsPerPage = 3;

    function updatePagination() {{
        const totalPages = Math.ceil(currentFilteredVulnItems.length / itemsPerPage) || 1;
        
        // 调整当前页数
        currentPage = Math.max(0, Math.min(currentPage, totalPages - 1));
        
        // 强制隐藏所有条目
        document.querySelectorAll('.vuln-item').forEach(el => el.style.display = 'none');

        // 仅显示当前页条目
        currentFilteredVulnItems.slice(
            currentPage * itemsPerPage,
            (currentPage + 1) * itemsPerPage
        ).forEach(({{element}}) => {{
            element.style.display = 'block';
            const content = element.querySelector('[id$="-content"]');
            if (content) {{
                
                element.querySelector('[id$="-arrow"]').style.transform = 'rotate(180deg)';
            }}
        }});
        
        // 更新按钮状态
        document.getElementById('prevPage').disabled = currentPage === 0;
        document.getElementById('nextPage').disabled = currentPage >= totalPages - 1;
        document.getElementById('pageInfo').textContent = currentFilteredVulnItems.length === 0 
            ? '无结果' 
            : `第${{currentPage + 1}}页/共${{totalPages}}页`;
        
        // 隐藏所有条目并显示当前页
        document.querySelectorAll('.vuln-item').forEach(el => el.style.display = 'none');
        currentFilteredVulnItems.slice(
            currentPage * itemsPerPage,
            (currentPage + 1) * itemsPerPage
        ).forEach(({{element}}) => {{
            element.style.display = 'block';
            // 自动展开当前页条目
            const content = element.querySelector('[id$="-content"]');
            if (content && content.classList.contains('hidden')) {{
                
                element.querySelector('[id$="-arrow"]').style.transform = 'rotate(180deg)';
            }}
        }});

        // 滚动到顶部
        if (currentFilteredVulnItems.length > 0) {{
            const firstVisible = currentFilteredVulnItems[currentPage * itemsPerPage]?.element;
            firstVisible?.scrollIntoView({{ behavior: 'auto', block: 'start' }});
        }}
    }}

    // 初始化搜索和分页
    function initSearch() {{
        const vulnItems = Array.from(document.querySelectorAll('.vuln-item'));
        currentFilteredVulnItems = vulnItems.map(element => ({{
            element,
            text: element.innerText.toLowerCase()
        }}));
        
        // 搜索功能
        document.getElementById('vulnSearch').addEventListener('input', function(e) {{
            const term = e.target.value.toLowerCase().trim();
            currentFilteredVulnItems = vulnItems
                .map(element => ({{
                    element,
                    text: element.innerText.toLowerCase()
                }}))
                .filter(({{text}}) => text.includes(term));
            currentPage = 0;
            updatePagination();
        }});
    }}
    // 折叠面板切换
    function toggleSection(id) {{
        const content = document.getElementById(`${{id}}-content`);
        const arrow = document.getElementById(`${{id}}-arrow`);
        const allContents = document.querySelectorAll('[id$="-content"]');
        const allArrows = document.querySelectorAll('[id$="-arrow"]');
        
        allContents.forEach(el => el !== content && el.classList.add('hidden'));
        allArrows.forEach(el => el !== arrow && (el.style.transform = ''));
        
        content.classList.toggle('hidden');
        arrow.style.transform = content.classList.contains('hidden') ? '' : 'rotate(180deg)';
        !content.classList.contains('hidden') && content.scrollIntoView({{ behavior: 'smooth', block: 'nearest' }});
    }}

    document.addEventListener('DOMContentLoaded', function() {{
        initSearch();
        // 新增初始化分页
        currentFilteredVulnItems = Array.from(document.querySelectorAll('.vuln-item'))
            .map(element => ({{
                element,
                text: element.innerText.toLowerCase()
            }}));
        updatePagination();  // 关键初始化调用

        // 分页按钮事件绑定
        document.getElementById('prevPage').addEventListener('click', () => {{
            currentPage = Math.max(0, currentPage - 1);
            updatePagination();
        }});
        document.getElementById('nextPage').addEventListener('click', () => {{
            const totalPages = Math.ceil(currentFilteredVulnItems.length / itemsPerPage);
            currentPage = Math.min(totalPages - 1, currentPage + 1);
            updatePagination();
        }});
        document.getElementById('prevPage').addEventListener('click', () => {{
                    currentPage = Math.max(0, currentPage - 1);
                    updatePagination();
                }});
        document.getElementById('nextPage').addEventListener('click', () => {{
                    const totalPages = Math.ceil(currentFilteredVulnItems.length / itemsPerPage);
                    currentPage = Math.min(totalPages - 1, currentPage + 1);
                    updatePagination();
                }});
        // 函数点击交互
        document.querySelectorAll('.function-name').forEach(func => {{
            func.addEventListener('click', (e) => {{
                e.stopPropagation();
                const [functionName, address] = func.dataset.function.split('@');
                const codeData = globalCodeDict[functionName];
                
                if (codeData) {{
                    // 同时更新左右两列
                    document.getElementById('pseudo-code').innerHTML = `
                        <div class="text-secondary mb-2">📜 伪代码</div>
                        <pre class="text-white/80">${{codeData.pseudo_code.join('\\n')}}</pre>
                    `;
                    document.getElementById('assembly-code').innerHTML = `
                        <div class="text-secondary mb-2">📜 汇编代码</div>
                        <pre class="text-white/80">${{codeData.assembly.join('\\n')}}</pre>
                    `;
                    
                    // 更新状态信息
                    document.getElementById('current-function').textContent = functionName;
                    document.getElementById('code-location').innerHTML = `
                        <i class="ri-map-pin-line"></i>
                        <span>链路上下一调用点地址: ${{address}}</span>
                    `;
                    document.getElementById('code-status').innerHTML = `
                        <i class="ri-terminal-box-line"></i>
                        <span>已加载: ${{functionName}}</span>
                    `;
                    
                    // 显示代码卡片
                    document.getElementById('code-card').style.display = 'block';
                }}
            }});
        }});

        // 代码卡片交互
        let isDragging = false, isResizing = false;
        let startX, startY, startWidth, startHeight, startLeft, startTop;
        const card = document.getElementById('code-card');
        const contentBox = card.querySelector('.glass-card');
        const resizeHandle = card.querySelector('.resize-handle');

        // 拖动处理
        contentBox.addEventListener('mousedown', (e) => {{
            if(e.target !== resizeHandle) {{
                isDragging = true;
                [startX, startY] = [e.clientX, e.clientY];
                [startLeft, startTop] = [parseFloat(contentBox.style.left), parseFloat(contentBox.style.top)];
            }}
        }});

        // 调整大小处理
        resizeHandle.addEventListener('mousedown', (e) => {{
            isResizing = true;
            [startX, startY] = [e.clientX, e.clientY];
            [startWidth, startHeight] = [contentBox.offsetWidth, contentBox.offsetHeight];
            e.preventDefault();
        }});

        document.addEventListener('mousemove', (e) => {{
            if(isDragging) {{
                contentBox.style.left = `${{startLeft + e.clientX - startX}}px`;
                contentBox.style.top = `${{startTop + e.clientY - startY}}px`;
                contentBox.style.transform = 'none';
            }}
            if(isResizing) {{
                contentBox.style.width = `${{Math.max(400, startWidth + e.clientX - startX)}}px`;
                contentBox.style.height = `${{Math.max(300, startHeight + e.clientY - startY)}}px`;
            }}
        }});

        document.addEventListener('mouseup', () => {{
            isDragging = isResizing = false;
        }});

        // 关闭按钮
        document.getElementById('close-btn').addEventListener('click', () => {{
            card.style.display = 'none';
        }});

        // 粒子效果初始化
        Array.from({{length: 50}}).forEach(() => {{
            const particle = document.createElement('div');
            Object.assign(particle.style, {{
                left: `${{Math.random() * 100}}%`,
                top: `${{Math.random() * 100}}%`,
                animation: `sparkle ${{2 + Math.random() * 3}}s infinite`
            }});
            particle.className = 'particle';
            document.body.appendChild(particle);
        }});

        // 初始化状态栏
        function updateCodeStatus() {{
            const pseudoLines = document.getElementById('pseudo-code').querySelector('pre').textContent.split('\\n').length;
            const assemblyLines = document.getElementById('assembly-code').querySelector('pre').textContent.split('\\n').length;
            const totalSize = new Blob([
                document.getElementById('pseudo-code').textContent,
                document.getElementById('assembly-code').textContent
            ]).size / 1024;
            
            document.getElementById('code-lines').innerHTML = `
                <i class="ri-numbers-line"></i>
                <span>行数: 伪码${{pseudoLines}} / 汇编${{assemblyLines}}</span>
            `;
            document.getElementById('code-size').innerHTML = `
                <i class="ri-database-2-line"></i>
                <span>大小: ${{totalSize.toFixed(2)}} KB</span>
            `;
        }}
        updateCodeStatus();
    }});

    
    </script>
    """

    # CSS样式表
    css = """
    <style>
    @keyframes float { 0%,100% { transform:translateY(0) } 50% { transform:translateY(-10px) } }
    @keyframes sparkle { 0%,100% { opacity:0 } 50% { opacity:1 } }
    @keyframes scanline { 0% { transform:translateY(-100%) } 100% { transform:translateY(100%) } }
    #pseudo-code::-webkit-scrollbar,
    #assembly-code::-webkit-scrollbar {
        width: 8px;
        background: rgba(0,0,0,0.2);
    }
    
    .vuln-section {
    overflow-x: auto;
    max-width: 100%;
    padding: 12px;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 8px;
    }

    #pseudo-code::-webkit-scrollbar-thumb,
    #assembly-code::-webkit-scrollbar-thumb {
        background: #8B5CF6;
        border-radius: 4px;
    }

    #pseudo-code::-webkit-scrollbar-track,
    #assembly-code::-webkit-scrollbar-track {
        background: rgba(139,92,246,0.1);
    }
    .magic-card {
        background: rgba(139, 92, 246, 0.1);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255,255,255,0.1);
        box-shadow: 0 8px 32px rgba(31,38,135,0.15);
        position: relative;
        overflow: hidden;
    }
    .magic-card::before {
        content: '';
        position: absolute;
        top:0; left:0; right:0;
        height:2px;
        background: linear-gradient(90deg,transparent,rgba(139,92,246,0.8),transparent);
        animation: scanline 2s linear infinite;
    }
    .cyber-border {
        border:2px solid transparent;
        background-image: linear-gradient(black,black),linear-gradient(135deg,rgba(139,92,246,0.8) 0%,rgba(196,181,253,0.8) 100%);
        background-origin: border-box;
        background-clip: padding-box,border-box;
    }
    .particle {
        position:absolute;
        width:3px; height:3px;
        background:rgba(255,255,255,0.5);
        border-radius:50%;
        pointer-events:none;
    }
    .glass-card {
        background:rgba(31,41,55,0.9);
        border:1px solid rgba(139,92,246,0.3);
        backdrop-filter:blur(10px);
    }
    .resize-handle {
        position:absolute;
        right:0; bottom:0;
        width:20px; height:20px;
        cursor:nwse-resize;
        background:#8B5CF6;
        border-radius:4px 0 0 0;
    }
    .vuln-detail-card {
        background:rgba(255,255,255,0.05);
        border-left:3px solid #8B5CF6;
        padding:1rem;
        margin:1rem 0;
    }
    .call-chain {
        padding-left:1.5rem;
        border-left:2px solid rgba(139,92,246,0.5);
        margin:1rem 0;
    }
    .function-name {
        cursor:pointer;
        transition:all 0.3s ease;
    }
    .function-name:hover {
        color:#C4B5FD !important;
        text-shadow:0 0 10px rgba(139,92,246,0.5);
    }
    </style>
    """

    # 生成漏洞详情部分
    vuln_sections = []
    for idx, entry in enumerate(formatted_json["detailed_analysis"], 1):
        risk_level, text_color = get_risk_level(entry['vulnerability']['cvss']['score'])
        
        vuln_section = f"""
        <div class="bg-white/5 rounded-lg p-6 border border-white/10 hover:border-white/20 transition-all duration-300 vuln-item">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center">
                        <i class="ri-shield-keyhole-line text-red-400 text-xl"></i>
                    </div>
                    <div>
                        <h3 class="font-semibold text-lg">漏洞 {idx}: {entry['target_function']}</h3>
                        <div class="flex items-center gap-4 text-sm text-white/60">
                            <span>{entry['vulnerability']['type']}</span>
                            <span>CVSS: {entry['vulnerability']['cvss']['score']}</span>
                            <span class="{text_color} font-medium">{risk_level}</span>
                        </div>
                    </div>
                </div>
                <button class="text-white/60 hover:text-white" onclick="toggleSection('vuln{idx}')">
                    <i class="ri-arrow-down-s-line transition-transform" id="vuln{idx}-arrow"></i>
                </button>
            </div>
            <div id="vuln{idx}-content" class="hidden space-y-4">
                <div class="bg-white/10 rounded p-4 vuln-section">
                    <h4 class="font-medium mb-2">漏洞描述</h4>
                    <p class="text-white/80">{entry['vulnerability']['description']}</p>
                </div>
                <div class="bg-white/10 rounded p-4 vuln-section">
                    <h4 class="font-medium mb-2">触发流程</h4>
                    <p class="font-mono text-sm text-white/80">
                        {'<br>'.join(entry['vulnerability']['how_exploit'])}
                    </p>
                </div>
                <div class="vuln-section">
                    <h3 class="text-lg mb-2 flex items-center">
                        <i class="ri-node-tree mr-2"></i>
                        调用链路（点击函数名可显示伪代码与汇编代码）
                    </h3>
                    <div class="call-chain">
                        {"".join([f'''
                        <div class="tree-node group flex items-center min-w-max">
                            {'<span class="text-purple-400 mx-2">›</span>'.join([f'''
                            <span class="function-name text-white/80 hover:text-purple-300 cursor-pointer" 
                                data-function="{node}">
                                {node}
                            </span>''' for node in chain["path"]])}
                        </div>''' for chain in entry["call_chains"]])}
                    </div>
                </div>
                <div class="vuln-section">
                    <h3 class="text-lg mb-2 flex items-center">
                        <i class="ri-tools-line mr-2"></i>
                        修复建议
                    </h3>
                    <ul class="list-disc list-inside space-y-2">
                        {"".join([f'<li class="text-white/80">{fix}</li>' for fix in entry["mitigation"]["code_fix"]])}
                    </ul>
                </div>
            </div>
        </div>
        """
        vuln_sections.append(vuln_section)

    # HTML主体结构
    return f"""
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>🪄二进制安全分析报告🪄 ——Power by HRP@Nepnep</title>
    <script src="https://cdn.tailwindcss.com"></script>
    
    <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    colors: {{ primary:"#8B5CF6", secondary:"#C4B5FD" }},
                    borderRadius: {{ DEFAULT:"8px", md:"12px", lg:"16px", full:"9999px" }}
                }}
            }}
        }};
    </script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/remixicon@4.5.0/fonts/remixicon.css">
    {css}
</head>
<body class="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 text-white">
    <div class="container mx-auto px-4 py-8 min-h-screen">
        <!-- 头部 -->
        <div class="text-center mb-12">
            <div class="absolute -top-4 left-1/2 transform -translate-x-1/2 w-32 h-1 bg-gradient-to-r from-transparent via-purple-500 to-transparent"></div>
            <h1 class="text-4xl font-bold mb-4 relative inline-block">
                <span class="relative z-10">🪄二进制安全分析报告🪄</span>
                <div class="absolute -inset-1 bg-gradient-to-r from-purple-600 to-purple-400 opacity-50 blur"></div>
            </h1>
            <p class="text-lg opacity-80">Power by HRP@Nepnep</p>
            <br>
            <p class="text-lg opacity-80">🕛报告生成时间：{current_time}</p>

            <div class="flex items-center justify-center gap-4 mt-4">
                <a href="https://github.com/hexian2001" class="flex items-center gap-2 text-white/80 hover:text-white">
                    <i class="ri-github-line"></i>
                    Visit My GitHub
                </a>
                <span class="text-white/60" id="report-time"></span>
            </div>
        </div>

        <!-- 主要内容 -->
        <div class="grid gap-8 max-w-6xl mx-auto">
            <!-- 风险概况 -->
            <div class="magic-card rounded-lg p-6">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-xl font-semibold flex items-center gap-2">
                        <i class="ri-error-warning-line text-yellow-400"></i>
                        风险概况
                    </h2>
                </div>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-6">
                    <div class="bg-white/10 rounded-lg p-6 cyber-border">
                        <p class="text-lg mb-2">高危漏洞数量</p>
                        <p class="text-3xl font-bold text-red-400">{high_risk}</p>
                    </div>
                    <div class="bg-white/10 rounded-lg p-6 cyber-border">
                        <p class="text-lg mb-2">中危漏洞数量</p>
                        <p class="text-3xl font-bold text-yellow-400">{medium_risk}</p>
                    </div>
                    <div class="bg-white/10 rounded-lg p-6 cyber-border">
                        <p class="text-lg mb-2">低危漏洞数量</p>
                        <p class="text-3xl font-bold text-green-400">{low_risk}</p>
                    </div>
                    <div class="bg-white/10 rounded-lg p-6 cyber-border">
                        <p class="text-lg mb-2">总漏洞数量</p>
                        <p class="text-3xl font-bold text-blue-400">{total_vulns}</p>
                    </div>
                </div>
            </div>

            <!-- 漏洞详情 -->
                <div class="magic-card rounded-lg p-6">
                    <div class="flex items-center justify-between mb-6 flex-wrap gap-4">
                        <h2 class="text-xl font-semibold">漏洞详情</h2>
                        <div class="relative w-full md:w-64">
                            <input 
                                type="text" 
                                id="vulnSearch" 
                                placeholder="搜索漏洞..." 
                                class="w-full px-4 py-2 rounded-lg bg-white/10 border border-white/20 focus:outline-none focus:border-purple-400 focus:ring-1 focus:ring-purple-500 transition-all"
                            >
                            <i class="ri-search-line absolute right-3 top-3 text-white/50"></i>
                        </div>
                    </div>
                    <!-- 滚动容器 -->
                    <div class="overflow-x-auto">
                        <div class="space-y-6 min-w-[600px]" id="vulnContainer">
                            {"".join(vuln_sections)}  <!-- 移除外层vuln-section包裹 -->
                        </div>
                    </div>

                    <div class="pagination-controls flex items-center justify-center gap-4 mt-4">
                        <button id="prevPage" class="px-4 py-2 bg-purple-500 rounded-lg hover:bg-purple-600 disabled:opacity-50 disabled:cursor-not-allowed" disabled>上一页</button>
                        <span id="pageInfo" class="text-white/80">第1页/共3页</span>
                        <button id="nextPage" class="px-4 py-2 bg-purple-500 rounded-lg hover:bg-purple-600 disabled:opacity-50 disabled:cursor-not-allowed">下一页</button>
                    </div>
                </div>
        </div>

        <!-- 代码查看卡片（左右分栏版） -->
        <div id="code-card" class="fixed inset-0 bg-black/50 hidden flex items-center justify-center p-4">
            <div class="glass-card rounded-xl p-6 max-w-6xl w-full h-[90vh] flex flex-col" style="min-width: 800px; min-height: 500px;">
                <div class="resize-handle"></div>
                <div class="flex justify-between items-center mb-4 pb-2 border-b border-purple-400/30">
                    <h3 class="text-xl font-bold flex items-center gap-2">
                        <i class="ri-code-s-slash-line"></i>
                        代码解析 - <span id="current-function" class="text-purple-300"></span>
                    </h3>
                    <button id="close-btn" class="text-2xl hover:text-purple-400 transition-transform hover:scale-125">
                        ×
                    </button>
                </div>
                
                <!-- 左右分栏布局 -->
                <div class="flex-1 grid grid-cols-2 gap-6 overflow-hidden" style="min-height: 400px;">
                    <!-- 伪代码区域 -->
                    <div class="flex-1 flex flex-col overflow-hidden">
                        <div id="pseudo-code" class="flex-1 overflow-auto font-mono text-sm p-4 bg-black/20 rounded-lg">
                            <div class="mb-2 flex items-center gap-2 text-purple-300">
                                <i class="ri-file-code-line"></i>
                                <span>伪代码分析</span>
                            </div>
                        </div>
                    </div>
                    
                    <!-- 汇编代码区域 -->
                    <div class="flex-1 flex flex-col overflow-hidden">
                        <div id="assembly-code" class="flex-1 overflow-auto font-mono text-sm p-4 bg-black/20 rounded-lg">
                            <div class="text-secondary mb-4 flex items-center gap-2">
                                <i class="ri-information-line"></i>
                                <span>点击调用链中的函数查看详细代码</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 状态栏 -->
                <div class="mt-4 pt-2 border-t border-purple-400/30 text-sm text-white/60 flex justify-between items-center">
                    <div class="flex items-center gap-3">
                        <span id="code-status" class="flex items-center gap-2">
                            <i class="ri-terminal-box-line"></i>
                            <span>就绪</span>
                        </span>
                        <span id="code-location" class="flex items-center gap-2">
                            <i class="ri-map-pin-line"></i>
                            <span>链路上下一调用地址: 0x0000</span>
                        </span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    {js}
</body>
</html>
    """




def save_security_report(formatted_json):
    """保存报告为带时间戳的HTML文件"""
    
    content = generate_enterprise_report_html(formatted_json)
    filename = f"Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    
    print(f"✅ 报告已保存为：{filename}")
    return filename

# 在脚本开头添加GUI输入对话框
class AnalysisParamsForm(idaapi.Form):
    """参数输入对话框"""
    def __init__(self):
        F = idaapi.Form
        F.__init__(self, 
r"""STARTITEM 0
HRP Auto Analyze——Power by HRP@Nepnep
{logo}
GitHub:https://github.com/hexian2001

<API Key:{api_key}>
<API URL:{api_url}>
<AI Model:{model}>
<Batch Size:{batch_size}>
<Max Depth:{max_depth}>
<Limit Chains Length:{limit_chains_length}>

勾选检测类型
<溢出检测:{c_buffer_overflow}>
<命令注入:{c_command_injection}>
<格式化漏洞:{c_format_string}>
<目录穿越:{c_directory_traversal}>
<条件竞争:{c_race_condition}>{c_opt_chk}>


每次分析的链路调用数量，建议值20.[因为我默认选择是上下文1M的LLM]
批次越大LLM开销越大，但是有助于加强上下文分析.
但是也有可能因为上下文过长导致输入上限而无法进行正常服务.

Max Depth推荐为20，小型ELF多少都无所谓，但是ELF大小上到1M的自己测试，如果卡住了请调小.

Limi Chains Length为每个危险函数的调用链数目限制，默认为100，可以自行调整.
""", {
    'logo': F.StringLabel(r"""
,--.  ,--.    ,------.     ,------.  
|  '--'  |    |  .--. '    |  .--. ' 
|  .--.  |    |  '--'.'    |  '--' | 
|  |  |  |    |  |\  \     |  | --'  
`--'  `--'    `--' '--'    `--'      
    """, tp=F.FT_ASCII),
    'api_key': F.StringInput(tp=F.FT_ASCII, value="sk-xxxxxxxxxx",swidth=40),
    'api_url': F.StringInput(tp=F.FT_ASCII, value="https://api.example.com/v1", swidth=40),
    'model': F.StringInput(tp=F.FT_ASCII, value="qwen-turbo-2024-11-01",swidth=40),
    'batch_size': F.NumericInput(value=20, tp=F.FT_DEC),
    'max_depth': F.NumericInput(value=20, tp=F.FT_DEC),
    'limit_chains_length': F.NumericInput(value=100, tp=F.FT_DEC),
    'c_opt_chk': F.ChkGroupControl(('c_buffer_overflow', 'c_command_injection', 'c_format_string', 'c_directory_traversal', 'c_race_condition'), value=0)
})

# 在全局区域添加控制变量
async_controller = {
    "should_stop": False,
    "futures": [],
    "executor": None
}

def graceful_stop():
    """优雅停止所有异步任务"""
    async_controller["should_stop"] = True
    
    # 取消所有未完成的任务
    for future in async_controller["futures"]:
        future.cancel()
    
    # 关闭线程池
    if async_controller["executor"]:
        async_controller["executor"].shutdown(wait=False)
    
    print("\n[!] 所有异步任务已终止")


# 在IDA脚本入口处添加中断捕获
if __name__ == "__main__":
    try:
        form = AnalysisParamsForm()
        form.Compile()
        
        if form.Execute():
            params = {
            'api_key': form.api_key.value,
            'api_url': form.api_url.value,
            'model': form.model.value,
            'batch_size': int(form.batch_size.value),
            'max_depth': int(form.max_depth.value),
            'limit_chains_length': int(form.limit_chains_length.value)
            }
            
            # 获取用户选择的危险类别
            selected_categories = []
            if form.c_opt_chk.value & (1 << 0):  # buffer_overflow
                selected_categories.extend(DANGER_CATEGORIES["buffer_overflow"])
            if form.c_opt_chk.value & (1 << 1):  # command_injection
                selected_categories.extend(DANGER_CATEGORIES["command_injection"])
            if form.c_opt_chk.value & (1 << 2):  # format_string
                selected_categories.extend(DANGER_CATEGORIES["format_string"])
            if form.c_opt_chk.value & (1 << 3):  # directory_traversal
                selected_categories.extend(DANGER_CATEGORIES["directory_traversal"])
            if form.c_opt_chk.value & (1 << 4):  # race_condition
                selected_categories.extend(DANGER_CATEGORIES["race_condition"])
            
            # 去重合并为 DANGER_FUNCTIONS
            DANGER_FUNCTIONS = list(set(selected_categories))
            o = analyze_danger_calls(params, debug=False)
            formatted_data = format_analysis_data(o)
            save_security_report(formatted_data)
    except KeyboardInterrupt:
        graceful_stop()
    except Exception as e:
        graceful_stop()
        raise e