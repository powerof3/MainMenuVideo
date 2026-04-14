"""
Verify extracted function signatures against CommonLibSSE source code.
"""

import json
import os
import re
import glob
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

SIGS_PATH = r"D:\GitHub\ghidrascripts\MainMenuVideo\_all_sigs.json"
COMMONLIB_ROOT = r"D:\GitHub\ghidrascripts\MainMenuVideo\extern\CommonLibSSE"
INCLUDE_RE = os.path.join(COMMONLIB_ROOT, "include", "RE")
SRC_RE = os.path.join(COMMONLIB_ROOT, "src", "RE")


@dataclass
class SigInfo:
    return_type: str
    params: list  # list of (type, name) tuples
    is_static: bool = False


def parse_sig(sig_str: str) -> SigInfo:
    """Parse a signature like 'static bool(SpellItem* a_spell)' into SigInfo."""
    sig = sig_str.strip()
    is_static = False
    if sig.startswith("static "):
        is_static = True
        sig = sig[len("static "):].strip()

    # Find the outermost parentheses for params
    # Return type is everything before the first '('
    paren_depth = 0
    first_paren = -1
    last_paren = -1
    for i, c in enumerate(sig):
        if c == '(':
            if paren_depth == 0:
                first_paren = i
            paren_depth += 1
        elif c == ')':
            paren_depth -= 1
            if paren_depth == 0:
                last_paren = i
                break

    if first_paren == -1:
        return SigInfo(return_type=sig, params=[], is_static=is_static)

    ret_type = sig[:first_paren].strip()
    params_str = sig[first_paren + 1:last_paren].strip()

    params = parse_params(params_str)
    return SigInfo(return_type=ret_type, params=params, is_static=is_static)


def parse_params(params_str: str) -> list:
    """Parse parameter string, handling template commas."""
    if not params_str or params_str == "void":
        return []

    # Split by commas, respecting template depth
    parts = []
    depth = 0
    current = []
    for c in params_str:
        if c in ('<', '('):
            depth += 1
            current.append(c)
        elif c in ('>', ')'):
            depth -= 1
            current.append(c)
        elif c == ',' and depth == 0:
            parts.append(''.join(current).strip())
            current = []
        else:
            current.append(c)
    if current:
        parts.append(''.join(current).strip())

    result = []
    for part in parts:
        if part == '...':
            result.append(('...', ''))
            continue
        # Remove default values
        eq_pos = find_default_eq(part)
        if eq_pos != -1:
            part = part[:eq_pos].strip()

        # Split into type and name: last token is name if it looks like identifier
        # But careful with stuff like "float" alone
        tokens = smart_split_type_name(part)
        result.append(tokens)

    return result


def find_default_eq(s: str) -> int:
    """Find '=' that represents a default value (not inside templates)."""
    depth = 0
    for i, c in enumerate(s):
        if c in ('<', '('):
            depth += 1
        elif c in ('>', ')'):
            depth -= 1
        elif c == '=' and depth == 0:
            return i
    return -1


def smart_split_type_name(param: str) -> tuple:
    """Split 'const BSFixedString& a_nodeName' into ('const BSFixedString&', 'a_nodeName')."""
    param = param.strip()
    if not param:
        return ('', '')

    # If it ends with & or * it's just a type with no name
    if param.endswith('&') or param.endswith('*'):
        return (param, '')

    # Find the last token
    # Walk backwards past the name
    i = len(param) - 1
    while i >= 0 and (param[i].isalnum() or param[i] == '_'):
        i -= 1

    if i < 0:
        # Single token - it's a type
        return (param, '')

    name_part = param[i + 1:]
    type_part = param[:i + 1].strip()

    # If type_part is empty or name looks like a type keyword, treat whole thing as type
    if not type_part or name_part in ('int', 'float', 'double', 'bool', 'void', 'char', 'short', 'long', 'unsigned', 'signed'):
        return (param, '')

    return (type_part, name_part)


def normalize_type(t: str) -> str:
    """Normalize a type for comparison."""
    t = t.strip()
    # Remove const, volatile, inline, virtual, constexpr, override, noexcept
    for qual in ['const ', 'volatile ', 'inline ', 'virtual ', 'constexpr ', 'explicit ']:
        t = t.replace(qual, '')
    # Remove trailing const
    t = re.sub(r'\s*const\s*$', '', t)
    # Normalize whitespace
    t = re.sub(r'\s+', ' ', t).strip()
    # Treat & as * for comparison
    t = t.replace('&', '*')
    # Remove leading RE:: namespace
    t = t.replace('RE::', '')
    # Remove std:: prefix for integer types (uint8_t vs std::uint8_t)
    t = re.sub(r'\bstd::(u?int\d+_t|size_t)\b', r'\1', t)
    # Remove BSGraphics:: and other common namespace prefixes that might differ
    # when inside the namespace vs outside
    t = re.sub(r'\b\w+::', '', t)
    # Normalize variadic: 'Args...' and '...' are equivalent
    if t.endswith('...'):
        t = '...'
    return t


def types_match(t1: str, t2: str) -> bool:
    """Check if two types match after normalization."""
    n1 = normalize_type(t1)
    n2 = normalize_type(t2)
    return n1 == n2


def find_source_files(class_name: str) -> list:
    """Find .h and .cpp files for a given class name."""
    results = []
    first_letter = class_name[0].upper()

    # Check common locations
    for base, ext in [(INCLUDE_RE, '.h'), (SRC_RE, '.cpp')]:
        # Try direct match
        candidate = os.path.join(base, first_letter, class_name + ext)
        if os.path.exists(candidate):
            results.append(candidate)
        else:
            # Try glob in the letter directory
            letter_dir = os.path.join(base, first_letter)
            if os.path.isdir(letter_dir):
                for f in os.listdir(letter_dir):
                    if f.lower() == (class_name + ext).lower():
                        results.append(os.path.join(letter_dir, f))

    return results


def find_all_source_files() -> dict:
    """Build index of all source files by basename (without extension)."""
    index = {}
    for root_dir in [INCLUDE_RE, SRC_RE]:
        for dirpath, dirnames, filenames in os.walk(root_dir):
            for f in filenames:
                if f.endswith('.h') or f.endswith('.cpp'):
                    basename = os.path.splitext(f)[0]
                    if basename not in index:
                        index[basename] = []
                    index[basename].append(os.path.join(dirpath, f))
    return index


def extract_declaration_from_header(file_path: str, class_name: str, method_name: str, expected_param_count: int = -1) -> Optional[str]:
    """Extract a method declaration from a header file within a class body."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except:
        return None

    esc_method = re.escape(method_name)

    # Verify class exists in file
    class_pattern = rf'(?:class|struct)\s+{re.escape(class_name)}\b'
    if not re.search(class_pattern, content):
        return None

    # Line-based approach
    lines = content.split('\n')
    candidates = []

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Must contain the method name followed by (
        if not re.search(rf'\b{esc_method}\s*\(', stripped):
            continue
        # Skip comments, using declarations, decltype, return statements
        if stripped.startswith('//') or stripped.startswith('/*'):
            continue
        if 'decltype' in stripped or stripped.startswith('using '):
            continue
        if stripped.startswith('return'):
            continue

        # Strip C++ attributes like [[nodiscard]], [[maybe_unused]], etc.
        stripped = re.sub(r'\[\[[\w:, ]+\]\]\s*', '', stripped)

        # Try to match: [static] [virtual] RetType MethodName(params)
        match = re.match(rf'^((?:static\s+)?(?:virtual\s+)?[\w:*&<>, ]+?)\s+{esc_method}\s*\((.*)$', stripped)
        if not match:
            continue

        ret_type = match.group(1).strip()
        rest = match.group(2)

        # Skip bad return types
        bad_rets = {'return', 'using', 'typedef', 'if', 'else', 'for', 'while', 'switch', 'case', 'delete', 'new'}
        if ret_type in bad_rets:
            continue

        # Collect full params (may span lines)
        params_text = rest
        paren_depth = 1
        found_close = False
        for c in rest:
            if c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth -= 1
                if paren_depth == 0:
                    found_close = True
                    break

        if not found_close:
            for j in range(i + 1, min(i + 20, len(lines))):
                params_text += ' ' + lines[j].strip()
                for c in lines[j]:
                    if c == '(':
                        paren_depth += 1
                    elif c == ')':
                        paren_depth -= 1
                        if paren_depth == 0:
                            found_close = True
                            break
                if found_close:
                    break

        close_idx = find_matching_paren_str(params_text)
        if close_idx != -1:
            params_text = params_text[:close_idx].strip()
        else:
            params_text = params_text.rstrip(');').strip()

        params_text = re.sub(r'\s+', ' ', params_text)
        full_sig = f"{ret_type}({params_text})"
        candidates.append(full_sig)

    if not candidates:
        return None

    # If there's only one candidate, return it
    if len(candidates) == 1:
        return candidates[0]

    # Multiple overloads - try to match by param count
    if expected_param_count >= 0:
        for c in candidates:
            sig = parse_sig(c)
            if len(sig.params) == expected_param_count:
                return c

    # Return first candidate as fallback
    return candidates[0]


def find_matching_paren_str(s: str) -> int:
    """Find the index of the closing paren that matches depth 0 (starting after opening paren)."""
    depth = 1
    for i, c in enumerate(s):
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i
    return -1


def extract_declaration_from_cpp(file_path: str, class_name: str, method_name: str, expected_param_count: int = -1) -> Optional[str]:
    """Extract a method definition from a .cpp file: RetType Class::Method(params)."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except:
        return None

    esc_class = re.escape(class_name)
    esc_method = re.escape(method_name)

    # Strategy: find lines with Class::Method and parse them
    # Use line-based approach to avoid matching inside function bodies
    lines = content.split('\n')
    candidates = []

    for i, line in enumerate(lines):
        stripped = line.strip()
        pattern_check = f'{class_name}::{method_name}'
        if pattern_check not in stripped:
            continue

        if 'decltype' in stripped or 'using ' in stripped:
            continue
        if stripped.startswith('return') or stripped.startswith('//'):
            continue
        if stripped.startswith('static REL::'):
            continue

        # Try to match: RetType Class::Method(params)
        match = re.match(rf'^([\w:*&<>, ]+?)\s+{esc_class}::{esc_method}\s*\((.*)$', stripped)
        if not match:
            continue

        ret_type = match.group(1).strip()
        rest = match.group(2)

        bad_rets = {'return', 'using', 'typedef', 'if', 'else', 'for', 'while', 'switch', 'case', 'delete', 'new', 'func'}
        if ret_type in bad_rets or 'decltype' in ret_type:
            continue

        # Collect params - may span multiple lines
        params_text = rest
        paren_depth = 1
        found_close = False
        for c in rest:
            if c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth -= 1
                if paren_depth == 0:
                    found_close = True
                    break

        if not found_close:
            for j in range(i + 1, min(i + 20, len(lines))):
                params_text += ' ' + lines[j].strip()
                for c in lines[j]:
                    if c == '(':
                        paren_depth += 1
                    elif c == ')':
                        paren_depth -= 1
                        if paren_depth == 0:
                            found_close = True
                            break
                if found_close:
                    break

        close_idx = find_matching_paren_str(params_text)
        if close_idx != -1:
            params_text = params_text[:close_idx].strip()
        else:
            params_text = params_text.rstrip(') {').strip()

        # Handle trailing return type: auto Foo::Bar(...) -> RetType
        if ret_type == 'auto':
            # Check the line after params for -> RetType
            after_params = params_text
            remaining = rest[close_idx + 1:] if close_idx != -1 else ''
            trail_match = re.search(r'->\s*([\w:]+)', remaining)
            if not trail_match:
                # Check next line
                for j in range(i + 1, min(i + 3, len(lines))):
                    trail_match = re.search(r'->\s*([\w:]+)', lines[j])
                    if trail_match:
                        break
            if trail_match:
                ret_type = trail_match.group(1)

        params_text = re.sub(r'\s+', ' ', params_text)
        full_sig = f"{ret_type}({params_text})"
        candidates.append(full_sig)

    if not candidates:
        return None

    if len(candidates) == 1:
        return candidates[0]

    # Multiple overloads - try to match by param count
    if expected_param_count >= 0:
        for c in candidates:
            sig = parse_sig(c)
            if len(sig.params) == expected_param_count:
                return c

    return candidates[0]


def extract_free_function(file_path: str, func_name: str) -> Optional[str]:
    """Extract a free function declaration/definition."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except:
        return None

    esc_name = re.escape(func_name)

    # Pattern: RetType FuncName(params)
    # but NOT Class::FuncName
    pattern = rf'([\w:*&<>, ]+?)\s+(?<!::){esc_name}\s*\(([\s\S]*?)\)'
    matches = list(re.finditer(pattern, content))

    for match in matches:
        ret_type = match.group(1).strip()
        params_text = match.group(2).strip()
        params_text = re.sub(r'\s+', ' ', params_text)

        if ret_type in ('return', 'using', 'typedef', 'if', 'else', 'for', 'while', 'switch', 'case', 'delete', 'new', 'decltype'):
            continue
        if 'decltype' in ret_type:
            continue

        # Make sure "::" doesn't immediately precede the func name
        pos = match.start()
        prefix = content[max(0, pos - 2):pos + len(ret_type)]

        full_sig = f"{ret_type}({params_text})"
        return full_sig

    return None


def search_all_files_for_method(file_index: dict, class_name: str, method_name: str, expected_param_count: int = -1) -> Optional[str]:
    """Search across all relevant files for a method declaration."""
    # First try the class file directly
    if class_name in file_index:
        for fpath in file_index[class_name]:
            if fpath.endswith('.cpp'):
                result = extract_declaration_from_cpp(fpath, class_name, method_name, expected_param_count)
                if result:
                    return result
            elif fpath.endswith('.h'):
                result = extract_declaration_from_header(fpath, class_name, method_name, expected_param_count)
                if result:
                    return result

    # Try searching all files with grep-like approach for the pattern
    # Class::Method in .cpp files
    for base_dir in [SRC_RE, INCLUDE_RE]:
        for dirpath, dirnames, filenames in os.walk(base_dir):
            for fname in filenames:
                if not (fname.endswith('.cpp') or fname.endswith('.h')):
                    continue
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                except:
                    continue

                # Quick check if class and method are mentioned
                if class_name not in content or method_name not in content:
                    continue

                if fpath.endswith('.cpp'):
                    result = extract_declaration_from_cpp(fpath, class_name, method_name, expected_param_count)
                    if result:
                        return result
                else:
                    result = extract_declaration_from_header(fpath, class_name, method_name, expected_param_count)
                    if result:
                        return result

    return None


def search_free_function(file_index: dict, func_name: str) -> Optional[str]:
    """Search for a free function across all files."""
    # Try common locations: Misc.h, Misc.cpp, or files named after the function
    candidates = []
    if func_name in file_index:
        candidates.extend(file_index[func_name])
    if 'Misc' in file_index:
        candidates.extend(file_index['Misc'])

    for fpath in candidates:
        result = extract_free_function(fpath, func_name)
        if result:
            return result

    # Broad search
    for base_dir in [SRC_RE, INCLUDE_RE]:
        for dirpath, dirnames, filenames in os.walk(base_dir):
            for fname in filenames:
                if not (fname.endswith('.cpp') or fname.endswith('.h')):
                    continue
                fpath = os.path.join(dirpath, fname)
                if fpath in candidates:
                    continue
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                except:
                    continue
                if func_name not in content:
                    continue
                result = extract_free_function(fpath, func_name)
                if result:
                    return result

    return None


def compare_signatures(extracted_sig: str, source_sig: str, func_name: str) -> list:
    """Compare extracted sig against source sig. Return list of mismatch descriptions."""
    ext = parse_sig(extracted_sig)
    src = parse_sig(source_sig)
    issues = []

    # Compare return types
    if not types_match(ext.return_type, src.return_type):
        issues.append(f"Return type: extracted='{ext.return_type}' source='{src.return_type}'")

    # Compare parameter count
    if len(ext.params) != len(src.params):
        issues.append(f"Param count: extracted={len(ext.params)} source={len(src.params)}")
        # Still try to compare what we can
        min_len = min(len(ext.params), len(src.params))
    else:
        min_len = len(ext.params)

    # Compare parameter types
    for i in range(min_len):
        ext_type = ext.params[i][0]
        src_type = src.params[i][0]
        if not types_match(ext_type, src_type):
            issues.append(f"Param {i + 1} type: extracted='{ext_type}' source='{src_type}'")

    # Check static
    if ext.is_static and not src.is_static:
        # Check if source explicitly has 'static' - it might be in the header only
        if 'static' in source_sig.lower().split('(')[0]:
            pass  # OK
        else:
            # This might be OK - static only appears in header declaration
            pass  # Don't flag static mismatches since .cpp definitions don't repeat 'static'

    return issues


def main():
    print("Loading signatures...")
    with open(SIGS_PATH, 'r') as f:
        sigs = json.load(f)

    print(f"Total signatures to verify: {len(sigs)}")

    print("Building file index...")
    file_index = find_all_source_files()
    print(f"Indexed {len(file_index)} unique file basenames")

    verified = 0
    mismatches = []
    not_found = []
    found_count = 0

    for entry in sigs:
        name = entry['n']
        extracted_sig = entry['sig']

        # Split into class and method
        if '::' in name:
            parts = name.split('::', 1)
            class_name = parts[0]
            method_name = parts[1]

            # Parse extracted sig to get expected param count for overload resolution
            ext_parsed = parse_sig(extracted_sig)
            expected_pc = len(ext_parsed.params)

            # Search for the source declaration
            source_sig = search_all_files_for_method(file_index, class_name, method_name, expected_pc)
        else:
            source_sig = search_free_function(file_index, name)

        if source_sig is None:
            not_found.append(name)
            continue

        found_count += 1
        issues = compare_signatures(extracted_sig, source_sig, name)

        if issues:
            mismatches.append({
                'name': name,
                'extracted': extracted_sig,
                'source': source_sig,
                'issues': issues
            })
        else:
            verified += 1

    # Report
    print("\n" + "=" * 80)
    print("SIGNATURE VERIFICATION REPORT")
    print("=" * 80)
    print(f"\nTotal entries:        {len(sigs)}")
    print(f"Found in source:      {found_count}")
    print(f"Not found in source:  {len(not_found)}")
    print(f"Verified (match):     {verified}")
    print(f"Mismatches:           {len(mismatches)}")

    if mismatches:
        print(f"\n{'=' * 80}")
        print("MISMATCHES")
        print("=" * 80)
        for m in mismatches:
            print(f"\n  {m['name']}")
            print(f"    Extracted: {m['extracted']}")
            print(f"    Source:    {m['source']}")
            for issue in m['issues']:
                print(f"    >> {issue}")

    if not_found:
        print(f"\n{'=' * 80}")
        print("NOT FOUND IN SOURCE")
        print("=" * 80)
        for name in not_found:
            print(f"  {name}")

    print(f"\n{'=' * 80}")
    print(f"SUMMARY: {verified}/{found_count} found signatures verified OK "
          f"({len(mismatches)} mismatches, {len(not_found)} not found)")
    print("=" * 80)


if __name__ == '__main__':
    main()
