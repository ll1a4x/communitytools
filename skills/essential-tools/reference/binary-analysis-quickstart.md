# Binary Analysis - Quick Start Guide

Static analysis techniques for reverse engineering executable files in pentesting and CTF challenges.

---

## When to Use

**Reverse Engineering CTF challenges** — Extract flags, passwords, or logic from compiled binaries without execution.

**Compiled exploit validation** — Verify exploit behavior before running.

**Malware analysis** — Understand what a binary does before dynamic testing.

---

## Static Analysis Workflow

### Step 1: Identify the Binary Type
```bash
file <binary>
# Output: ELF 64-bit LSB pie executable, x86-64, or similar
```

### Step 2: Extract Readable Strings
```bash
strings <binary> | grep -E "password|flag|secret|key"
# Often reveals hardcoded credentials or hints
```

### Step 3: Examine Binary Sections
```bash
objdump -h <binary>
# Lists sections: .text (code), .data (initialized data), .rodata (read-only), .bss (uninitialized)
```

### Step 4: Disassemble Key Functions
```bash
objdump -d <binary> | grep -A 30 "<main>:"
# Focus on: cmp (comparisons), je/jne (conditional jumps), call (function calls)
```

### Step 5: Dump Data Sections
```bash
objdump -s -j .data <binary>
objdump -s -j .rodata <binary>
# Reveals hardcoded values, obfuscated strings, arrays
```

---

## Common Patterns in Very Easy Challenges

### Pattern 1: Hardcoded Passwords
**Indicator:** String output from `strings`, readable in .rodata section  
**Approach:** Extract via `strings`, verify with `objdump -s`

### Pattern 2: Obfuscated Output Arrays
**Indicator:** Data section contains 32-bit or 64-bit values, program outputs multiple characters  
**Approach:**
1. Identify array address from disassembly
2. Dump section with `objdump -s`
3. Extract least significant byte (LSB) from each value
4. Convert hex bytes to ASCII characters

**Example:** Little-endian 32-bit array `0x48000000 0x54000000` decodes to `H` (0x48) + `T` (0x54)

### Pattern 3: Password-Gated Flag Output
**Indicator:** Program reads input, compares against hardcoded value, outputs flag on match  
**Approach:**
1. Extract password from strings or data section
2. Provide password via stdin
3. Capture flag output

---

## Tool Reference

| Tool | Purpose | Example |
|------|---------|---------|
| `file` | Identify binary type | `file pass` → ELF 64-bit |
| `strings` | Extract readable text | `strings pass \| grep password` |
| `objdump -h` | List sections | Identify .data, .rodata locations |
| `objdump -d` | Disassemble code | Follow program flow, spot comparisons |
| `objdump -s` | Dump sections as hex | Read obfuscated data |
| `od` | Octal/hex dump | Alternative to objdump for raw inspection |
| `readelf` (Linux) | ELF metadata | Symbol tables, relocations |

---

## Common Mistakes

❌ **Running untrusted binaries** — Always verify file type and permissions first  
❌ **Ignoring strings output** — Often contains the answer directly  
❌ **Assuming big-endian** — Most modern systems (Intel, ARM) use little-endian; LSB is first byte  
❌ **Forgetting to parse arrays** — 32-bit/64-bit encoded values require LSB extraction  
❌ **Cross-platform issues** — Linux binaries may not run on macOS; use `objdump` instead  

---

## Cross-Platform Execution

| Platform | How to Run ELF 64-bit |
|----------|----------------------|
| Linux | `./binary` (directly) |
| macOS | No native ELF support; use `objdump`, `strings`, disassemblers |
| Windows | WSL, Docker, or Cygwin |

**Recommendation:** Use static analysis (`objdump`, `strings`) to avoid platform dependencies.

---

## One-Liner Cheat Sheet

**Find all strings containing "password":**
```bash
strings <binary> | grep -i password
```

**Extract 32-bit little-endian array and decode to ASCII:**
```bash
objdump -s -j .data <binary> | tail -n +2 | grep -oE '[0-9a-f]{8}' | xargs -I {} python3 -c "import sys; print(chr(int('{}',16) & 0xFF), end='')"
```

**Disassemble main function only:**
```bash
objdump -d <binary> | sed -n '/<main>:/,/^[0-9a-f]* <.*>:/p' | head -50
```

**List section offsets and sizes:**
```bash
objdump -h <binary> | grep -E "\.data|\.rodata|\.text"
```

---

## Generalization Rules

**Apply this workflow to:**
- Very Easy/Easy CTF reverse engineering challenges
- Any compiled binary with suspected hardcoded secrets
- Exploit validation (verify compiled exploit matches source)
- Malware triage (understand structure before dynamic analysis)

**Do NOT use for:**
- Running untrusted binaries as primary analysis (static first)
- Complex obfuscation or encryption (requires dynamic debugging)
- Time-critical exploit development (focus on dynamic analysis in those cases)
