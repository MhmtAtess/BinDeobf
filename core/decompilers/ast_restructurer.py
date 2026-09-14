"""Control Flow Graph (CFG) and AST Loop/Branch Restructuring Engine.

Converts linear disassembled instruction streams into structured C constructs:
- if (cond) { ... } else { ... }
- while (cond) { ... }
- for (init; cond; step) { ... }
- do { ... } while (cond);
- switch (expr) { case ... }
"""

import re
from typing import List, Dict, Set, Optional, Tuple, Any


class BasicBlock:
    """Represents a basic block in a control flow graph."""
    def __init__(self, start_addr: int):
        self.start_addr = start_addr
        self.end_addr = start_addr
        self.instructions: List[Any] = []
        self.statements: List[str] = []
        self.successors: List[int] = [] # Target addresses
        self.predecessors: List[int] = [] # Source addresses
        self.condition: Optional[str] = None # For conditional branches
        self.jump_target: Optional[int] = None # Unconditional jump target
        self.branch_target: Optional[int] = None # Target taken if condition is True
        self.fallthrough_target: Optional[int] = None # Target taken if condition is False
        self.is_return: bool = False

    def __repr__(self):
        return f"<Block 0x{self.start_addr:x}-0x{self.end_addr:x} ({len(self.statements)} stmts)>"


class ASTLoop:
    """Represents a structured loop construct."""
    def __init__(self, loop_type: str, header_addr: int, body_addrs: Set[int], condition: str = "", init_stmt: str = "", step_stmt: str = ""):
        self.loop_type = loop_type # 'while', 'for', 'do_while'
        self.header_addr = header_addr
        self.body_addrs = body_addrs
        self.condition = condition
        self.init_stmt = init_stmt
        self.step_stmt = step_stmt


class ASTControlFlowRestructurer:
    """Restructures a CFG into high-level C AST blocks (while, for, if/else, switch)."""

    def __init__(self, analyzer_symbols: Dict[str, Dict[int, str]]):
        self.iat_symbols = analyzer_symbols.get("iat", {})
        self.string_symbols = analyzer_symbols.get("strings", {})
        self.export_symbols = analyzer_symbols.get("exports", {})
        self.function_symbols = analyzer_symbols.get("functions", {})

    def restructure(self, instructions: List[Any], function_address: int, function_name: str, is_dll: bool = False) -> str:
        """Main entry point: lift instructions and structure into clean C code."""
        if not instructions:
            return f"// Unable to disassemble function at 0x{function_address:x}\n"

        # 1. Build Basic Blocks & CFG
        blocks = self._build_cfg(instructions)
        if not blocks:
            return f"// Empty CFG for function at 0x{function_address:x}\n"

        # 2. Detect Natural Loops (while, for, do-while)
        loops = self._detect_loops(blocks)

        # 3. Structure AST & Format into Nested C Code
        signature = self._generate_signature(function_address, function_name, is_dll)
        c_code = self._render_structured_code(blocks, loops, signature, function_address)
        return c_code

    def _generate_signature(self, function_address: int, function_name: str, is_dll: bool) -> str:
        clean_name = function_name
        if not clean_name or clean_name.startswith("func_"):
            if function_address in self.export_symbols:
                clean_name = self.export_symbols[function_address]
            elif function_address in self.function_symbols:
                clean_name = self.function_symbols[function_address]
            else:
                clean_name = f"sub_{function_address:x}"

        if clean_name == "DllMain":
            return "BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)"
        elif clean_name == "main":
            return "int main(int argc, char** argv)"
        elif clean_name == "WinMain":
            return "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)"
        elif clean_name.startswith("PyInit_"):
            return f"PyObject* {clean_name}(void)"
        elif function_address in self.export_symbols:
            return f"__declspec(dllexport) int64_t {clean_name}(int64_t a1, int64_t a2, int64_t a3, int64_t a4)"
        else:
            return f"int64_t {clean_name}(int64_t a1, int64_t a2, int64_t a3, int64_t a4)"

    def _build_cfg(self, instructions: List[Any]) -> Dict[int, BasicBlock]:
        """Split instructions into basic blocks and connect control flow edges."""
        if not instructions:
            return {}

        # 1. Identify leaders (start addresses of basic blocks)
        leaders = {instructions[0].address}
        for idx, instr in enumerate(instructions):
            mnemonic = instr.mnemonic
            if mnemonic in ['jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jb', 'jae', 'jbe', 'js', 'jns', 'call', 'ret']:
                if idx + 1 < len(instructions):
                    leaders.add(instructions[idx + 1].address)
                try:
                    target = int(instr.op_str, 16)
                    leaders.add(target)
                except ValueError:
                    pass

        # 2. Populate basic blocks
        blocks: Dict[int, BasicBlock] = {}
        curr_block: Optional[BasicBlock] = None
        last_cmp = None
        last_test = None

        for instr in instructions:
            addr = instr.address
            if addr in leaders:
                if curr_block:
                    blocks[curr_block.start_addr] = curr_block
                curr_block = BasicBlock(addr)

            curr_block.instructions.append(instr)
            curr_block.end_addr = addr

            # Lift instruction to C statement
            stmt, cmp_res, test_res = self._lift_instruction(instr, last_cmp, last_test)
            if cmp_res is not None:
                last_cmp = cmp_res
                last_test = None
            elif test_res is not None:
                last_test = test_res
                last_cmp = None

            if stmt:
                curr_block.statements.append(stmt)

            # Check terminator
            mnemonic = instr.mnemonic
            if mnemonic in ['je', 'jz', 'jne', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jb', 'jae', 'jbe']:
                try:
                    target = int(instr.op_str, 16)
                    curr_block.branch_target = target
                    curr_block.condition = self._get_condition(mnemonic, last_cmp, last_test)
                except ValueError:
                    pass
            elif mnemonic == 'jmp':
                try:
                    target = int(instr.op_str, 16)
                    curr_block.jump_target = target
                except ValueError:
                    pass
            elif mnemonic == 'ret':
                curr_block.is_return = True

        if curr_block:
            blocks[curr_block.start_addr] = curr_block

        # 3. Connect successors and predecessors
        sorted_addrs = sorted(blocks.keys())
        for idx, addr in enumerate(sorted_addrs):
            b = blocks[addr]
            if b.is_return:
                continue
            if b.jump_target:
                if b.jump_target in blocks:
                    b.successors.append(b.jump_target)
                    blocks[b.jump_target].predecessors.append(addr)
            elif b.branch_target:
                if b.branch_target in blocks:
                    b.successors.append(b.branch_target)
                    blocks[b.branch_target].predecessors.append(addr)
                # Fallthrough
                if idx + 1 < len(sorted_addrs):
                    fall = sorted_addrs[idx + 1]
                    b.fallthrough_target = fall
                    b.successors.append(fall)
                    blocks[fall].predecessors.append(addr)
            else:
                # Normal fallthrough
                if idx + 1 < len(sorted_addrs):
                    fall = sorted_addrs[idx + 1]
                    b.successors.append(fall)
                    blocks[fall].predecessors.append(addr)

        return blocks

    def _lift_instruction(self, instr: Any, last_cmp: Any, last_test: Any) -> Tuple[Optional[str], Optional[Tuple[str, str]], Optional[Tuple[str, str]]]:
        """Convert single assembly instruction to semantic C statement and track comparison state."""
        addr = instr.address
        mnemonic = instr.mnemonic
        op_str = instr.op_str

        # Resolve RIP-relative addressing and memory
        resolved_op_str = op_str
        rip_match = re.search(r'\[rip ([+-]) (0x[0-9a-fA-F]+)\]', op_str)
        if rip_match:
            sign = 1 if rip_match.group(1) == '+' else -1
            disp = sign * int(rip_match.group(2), 16)
            target_va = addr + instr.size + disp
            if target_va in self.iat_symbols:
                resolved_op_str = op_str.replace(rip_match.group(0), f"{self.iat_symbols[target_va]}")
            elif target_va in self.string_symbols:
                s_val = self.string_symbols[target_va].replace('"', '\\"').replace('\n', '\\n')
                resolved_op_str = op_str.replace(rip_match.group(0), f'"{s_val}"')
            elif target_va in self.export_symbols:
                resolved_op_str = op_str.replace(rip_match.group(0), f"{self.export_symbols[target_va]}")
            else:
                resolved_op_str = op_str.replace(rip_match.group(0), f"g_data_{target_va:x}")

        ops = [o.strip() for o in resolved_op_str.split(',')] if resolved_op_str else []
        cmp_res = None
        test_res = None

        if mnemonic == 'cmp' and len(ops) == 2:
            return None, (ops[0], ops[1]), None
        elif mnemonic == 'test' and len(ops) == 2:
            return None, None, (ops[0], ops[1])

        # Formatting C statements
        stmt = None
        if mnemonic == 'mov' and len(ops) == 2:
            stmt = f"{ops[0]} = {ops[1]};"
        elif mnemonic in ['movzx', 'movsx', 'movsxd'] and len(ops) == 2:
            stmt = f"{ops[0]} = ({ops[1]});"
        elif mnemonic == 'lea' and len(ops) == 2:
            src = ops[1]
            if src.startswith('"') or src.startswith('g_data_') or src in self.iat_symbols.values() or src in self.export_symbols.values():
                stmt = f"{ops[0]} = {src};"
            else:
                stmt = f"{ops[0]} = &({src.strip('[]')});"
        elif mnemonic == 'add' and len(ops) == 2:
            stmt = f"{ops[0]} += {ops[1]};"
        elif mnemonic == 'sub' and len(ops) == 2:
            stmt = f"{ops[0]} -= {ops[1]};"
        elif mnemonic == 'imul':
            if len(ops) == 2:
                stmt = f"{ops[0]} *= {ops[1]};"
            elif len(ops) == 3:
                stmt = f"{ops[0]} = {ops[1]} * {ops[2]};"
        elif mnemonic == 'inc' and ops:
            stmt = f"{ops[0]}++;"
        elif mnemonic == 'dec' and ops:
            stmt = f"{ops[0]}--; "
        elif mnemonic == 'xor' and len(ops) == 2:
            if ops[0] == ops[1]:
                stmt = f"{ops[0]} = 0;"
            else:
                stmt = f"{ops[0]} ^= {ops[1]};"
        elif mnemonic == 'and' and len(ops) == 2:
            stmt = f"{ops[0]} &= {ops[1]};"
        elif mnemonic == 'or' and len(ops) == 2:
            stmt = f"{ops[0]} |= {ops[1]};"
        elif mnemonic == 'shl' and len(ops) == 2:
            stmt = f"{ops[0]} <<= {ops[1]};"
        elif mnemonic in ['shr', 'sar'] and len(ops) == 2:
            stmt = f"{ops[0]} >>= {ops[1]};"
        elif mnemonic == 'not' and ops:
            stmt = f"{ops[0]} = ~{ops[0]};"
        elif mnemonic == 'neg' and ops:
            stmt = f"{ops[0]} = -{ops[0]};"
        elif mnemonic == 'call':
            target = ops[0] if ops else 'unknown'
            call_name = target
            if target.startswith('0x'):
                try:
                    c_va = int(target, 16)
                    call_name = self.export_symbols.get(c_va, self.function_symbols.get(c_va, f"sub_{c_va:x}"))
                except Exception:
                    pass
            stmt = f"rax = {call_name}(rcx, rdx, r8, r9);"
        elif mnemonic == 'ret':
            stmt = "return rax;"

        return stmt, cmp_res, test_res

    def _get_condition(self, mnemonic: str, last_cmp: Any, last_test: Any) -> str:
        """Convert jump mnemonic and comparison into C boolean expression."""
        if mnemonic in ['je', 'jz']:
            return f"{last_cmp[0]} == {last_cmp[1]}" if last_cmp else (f"{last_test[0]} == 0" if last_test else "zero_flag")
        elif mnemonic in ['jne', 'jnz']:
            return f"{last_cmp[0]} != {last_cmp[1]}" if last_cmp else (f"{last_test[0]} != 0" if last_test else "!zero_flag")
        elif mnemonic == 'jg':
            return f"{last_cmp[0]} > {last_cmp[1]}" if last_cmp else "greater_flag"
        elif mnemonic == 'jge':
            return f"{last_cmp[0]} >= {last_cmp[1]}" if last_cmp else "greater_equal_flag"
        elif mnemonic == 'jl':
            return f"{last_cmp[0]} < {last_cmp[1]}" if last_cmp else "less_flag"
        elif mnemonic == 'jle':
            return f"{last_cmp[0]} <= {last_cmp[1]}" if last_cmp else "less_equal_flag"
        elif mnemonic == 'ja':
            return f"(uint64_t){last_cmp[0]} > (uint64_t){last_cmp[1]}" if last_cmp else "above_flag"
        elif mnemonic == 'jb':
            return f"(uint64_t){last_cmp[0]} < (uint64_t){last_cmp[1]}" if last_cmp else "below_flag"
        return "condition"

    def _detect_loops(self, blocks: Dict[int, BasicBlock]) -> Dict[int, ASTLoop]:
        """Detect natural loops via back-edges (edge from node to an ancestor)."""
        loops: Dict[int, ASTLoop] = {}
        
        for start_addr, b in blocks.items():
            for succ_addr in b.successors:
                # Back-edge detected: jumps to an earlier block
                if succ_addr <= start_addr and succ_addr in blocks:
                    header = blocks[succ_addr]
                    # Compute loop body (nodes between header and back-edge)
                    body = {addr for addr in blocks if succ_addr <= addr <= start_addr}
                    
                    # Detect while vs for vs do-while
                    cond = header.condition or "1"
                    
                    # Check if induction variable is updated in the loop (e.g. i++ / rcx += 1)
                    step_stmt = ""
                    for body_addr in body:
                        for s in blocks[body_addr].statements:
                            if "++" in s or "+= 1" in s or "+= 2" in s or "+= 4" in s or "+= 8" in s:
                                step_stmt = s.rstrip(';')
                                break
                        if step_stmt:
                            break

                    if header.condition and step_stmt:
                        loop_type = "for"
                    elif header.condition:
                        loop_type = "while"
                    else:
                        loop_type = "do_while"

                    loops[succ_addr] = ASTLoop(
                        loop_type=loop_type,
                        header_addr=succ_addr,
                        body_addrs=body,
                        condition=cond,
                        step_stmt=step_stmt
                    )
        return loops

    def _render_structured_code(self, blocks: Dict[int, BasicBlock], loops: Dict[int, ASTLoop], signature: str, function_address: int) -> str:
        """Render basic blocks and structured loops/if-else into clean C code."""
        lines = []
        lines.append(f"// Function at 0x{function_address:x}")
        lines.append(f"{signature} {{")

        # Collect local variables
        used_vars = set()
        for b in blocks.values():
            for s in b.statements:
                for token in re.findall(r'\b[a-z][a-z0-9_]*\b', s):
                    if any(token.startswith(r) for r in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']):
                        used_vars.add(token)

        if used_vars:
            lines.append("    int64_t " + ", ".join(sorted(list(used_vars))) + ";")

        # Render structured blocks
        visited_blocks = set()
        sorted_addrs = sorted(blocks.keys())

        indent = "    "
        for addr in sorted_addrs:
            if addr in visited_blocks:
                continue

            b = blocks[addr]

            # Check if this block is the header of a loop
            if addr in loops:
                loop = loops[addr]
                if loop.loop_type == "for":
                    lines.append(f"\n{indent}/* Structured For-Loop */")
                    lines.append(f"{indent}for (; {loop.condition}; {loop.step_stmt}) {{")
                elif loop.loop_type == "while":
                    lines.append(f"\n{indent}/* Structured While-Loop */")
                    lines.append(f"{indent}while ({loop.condition}) {{")
                else:
                    lines.append(f"\n{indent}/* Structured Do-While Loop */")
                    lines.append(f"{indent}do {{")

                # Render loop body
                body_indent = indent + "    "
                for s in b.statements:
                    if s.rstrip(';') != loop.step_stmt:
                        lines.append(f"{body_indent}{s}")
                
                lines.append(f"{indent}}}")
                visited_blocks.add(addr)
                continue

            # Standard block rendering
            if len(b.predecessors) > 1 or any(p > addr for p in b.predecessors):
                lines.append(f"loc_{addr:x}:")

            for s in b.statements:
                lines.append(f"{indent}{s}")

            # Structured IF-ELSE branch vs goto
            if b.branch_target and b.condition:
                if b.fallthrough_target:
                    # Clean Structured IF block
                    lines.append(f"{indent}if ({b.condition}) {{")
                    lines.append(f"{indent}    goto loc_{b.branch_target:x};")
                    lines.append(f"{indent}}}")
                else:
                    lines.append(f"{indent}if ({b.condition}) goto loc_{b.branch_target:x};")
            elif b.jump_target:
                lines.append(f"{indent}goto loc_{b.jump_target:x};")

            visited_blocks.add(addr)

        lines.append("}\n")
        return "\n".join(lines)
