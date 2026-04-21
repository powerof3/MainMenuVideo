"""
Structural size/field rules for C++ template types that can be resolved
from template arguments alone, without PDB type information.

Each rule is a function that receives the parsed (outer, args) of a
normalised template name and returns (size_bytes, fields_list) or
(0, []) if the rule does not apply.

Fields are dicts:  {'name': str, 'offset': int, 'size': int, 'type': str}
where 'type' is the same internal format used elsewhere in the pipeline:
  'ptr'        — 8-byte pointer
  'bytes:N'    — N opaque bytes
"""

import re as _re

# ---------------------------------------------------------------------------
# Primitive type → byte size table
# ---------------------------------------------------------------------------

INTEGRAL_SIZES = {
    'bool': 1,
    'char': 1, 'signed char': 1, 'unsigned char': 1,
    'short': 2, 'signed short': 2, 'unsigned short': 2,
    'int': 4, 'signed int': 4, 'unsigned int': 4,
    'long': 4, 'signed long': 4, 'unsigned long': 4,
    'long long': 8, 'signed long long': 8, 'unsigned long long': 8,
    # MSVC __int64 alias seen in PDB dumps
    'unsigned __int64': 8, '__int64': 8,
    # stdint
    'std::int8_t': 1,  'int8_t': 1,  'std::uint8_t': 1,  'uint8_t': 1,
    'std::int16_t': 2, 'int16_t': 2, 'std::uint16_t': 2, 'uint16_t': 2,
    'std::int32_t': 4, 'int32_t': 4, 'std::uint32_t': 4, 'uint32_t': 4,
    'std::int64_t': 8, 'int64_t': 8, 'std::uint64_t': 8, 'uint64_t': 8,
    # size/ptrdiff (64-bit target)
    'std::size_t': 8, 'size_t': 8,
    'std::ptrdiff_t': 8, 'ptrdiff_t': 8,
    'std::uintptr_t': 8, 'uintptr_t': 8,
    'std::intptr_t': 8, 'intptr_t': 8,
    # float/double
    'float': 4, 'double': 8,
}

# ---------------------------------------------------------------------------
# Reusable field-list templates
# ---------------------------------------------------------------------------

def _f(name, offset, size, typ=None):
    if typ is None:
        typ = 'bytes:{}'.format(size)
    return {'name': name, 'offset': offset, 'size': size, 'type': typ}


_INT_TYPE = {1: 'i8', 2: 'i16', 4: 'i32', 8: 'i64'}


def _int_field(name, offset, sz):
    return _f(name, offset, sz, _INT_TYPE.get(sz, 'bytes:{}'.format(sz)))


_PTR_FIELD  = [_f('_ptr', 0, 8, 'ptr')]
_IMPL1      = lambda sz: [_f('_impl', 0, sz)]
_IMPL4      = [_f('_impl', 0, 4)]
_IMPL8      = [_f('_impl', 0, 8)]

# BSTScatterTable heap-allocator layout (confirmed from PDB + header): 48 bytes
# Field 0: _sentinel (entry_type* — sentinel node for empty-slot detection)
# Field 8: _allocPad (allocator internal uint64, NOT a pointer)
# Field 16-28: capacity/free/good/pad1C counters
# Field 32: _entries (std::byte* — raw hash bucket storage)
# Field 40: _allocPad2 (allocator trailing uint64, NOT a pointer)
_BSTSCATTERTABLE_HEAP_FIELDS = [
    _f('_sentinel',  0,  8, 'ptr'),
    _int_field('_allocPad',   8,  8),
    _int_field('_capacity',  16,  4),
    _int_field('_free',      20,  4),
    _int_field('_good',      24,  4),
    _int_field('_pad1C',     28,  4),
    _f('_entries',  32,  8, 'ptr'),
    _int_field('_allocPad2', 40,  8),
]

# ---------------------------------------------------------------------------
# Parser helpers (inline so this module is self-contained)
# ---------------------------------------------------------------------------

_TMPL_WS_RE = _re.compile(r'\s+(?=[>,])|(?<=[<,])\s+')


def norm_tmpl(s):
    """Normalise template-type whitespace (strip spaces adjacent to <,>)."""
    return _TMPL_WS_RE.sub('', s) if s else s


def parse_tmpl(name):
    """Split 'Outer<A,B>' → ('Outer', ['A', 'B']). Returns (name, []) for non-templates."""
    lt = name.find('<')
    if lt < 0 or not name.endswith('>'):
        return name, []
    outer = name[:lt]
    inner = name[lt + 1:-1]
    args, depth, start = [], 0, 0
    for i, c in enumerate(inner):
        if c == '<':
            depth += 1
        elif c == '>':
            depth -= 1
        elif c == ',' and depth == 0:
            a = inner[start:i].strip()
            if a:
                args.append(a)
            start = i + 1
    a = inner[start:].strip()
    if a:
        args.append(a)
    return outer, args


def _bare(name):
    """Strip leading 'RE::' or 'detail::' namespace prefix."""
    for prefix in ('RE::', 'detail::'):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _integral_size(typ):
    """Return byte size for a primitive C++ type string, or 0 if unknown."""
    return INTEGRAL_SIZES.get(typ.strip(), 0)


_PRIM_PTR = {
    'float': 'ptr:f32', 'double': 'ptr:f64',
    'char': 'ptr:i8', 'unsigned char': 'ptr:i8', 'wchar_t': 'ptr:i16',
    'short': 'ptr:i16', 'unsigned short': 'ptr:i16',
    'int': 'ptr:i32', 'unsigned int': 'ptr:i32', 'long': 'ptr:i32',
    'unsigned long': 'ptr:i32',
    'long long': 'ptr:i64', 'unsigned long long': 'ptr:i64',
    '__int64': 'ptr:i64', 'unsigned __int64': 'ptr:i64',
}


def _ptr_type_for(arg):
    """Build a typed pointer type string for a field that stores T*.

    Examples:
      'Actor'       → 'ptr:struct:RE::Actor'
      'Actor *'     → 'ptr:ptr:struct:RE::Actor'   (array of pointers)
      'float'       → 'ptr:f32'                    (pointer to float)
      'unsigned int'→ 'ptr:i32'                    (pointer to uint32)
    """
    arg = arg.strip()
    # Named primitive → typed primitive pointer
    if arg in _PRIM_PTR:
        return _PRIM_PTR[arg]
    if _integral_size(arg):
        return 'ptr'   # fallback for unknown integral types
    # Strip trailing 'const' qualifier before the star
    if arg.endswith(' const'):
        arg = arg[:-6].strip()
    # Pointer to pointer: T* → ptr:T_type
    if arg.endswith('*'):
        inner_arg = arg[:-1].strip()
        inner_type = _ptr_type_for(inner_arg)
        if inner_type != 'ptr':
            return 'ptr:' + inner_type
        return 'ptr'
    inner_o, _ = parse_tmpl(arg)
    bare = _bare(inner_o)
    if bare in INTEGRAL_SIZES:
        return 'ptr'
    # Build RE::-prefixed struct pointer
    full = arg if arg.startswith('RE::') else 'RE::' + arg
    return 'ptr:struct:{}'.format(full)


def _elem_type_for(arg, known_sizes=None):
    """Return the field type string for storing a value of type T directly (not T*).

    Used for tuple/container fields where the value is stored inline.
    Returns None if the type cannot be determined.
    """
    arg = arg.strip()
    if arg in ('float',):
        return 'f32'
    if arg in ('double',):
        return 'f64'
    sz = _integral_size(arg)
    if sz:
        if sz == 1: return 'i8'
        if sz == 2: return 'i16'
        if sz == 4: return 'i32'
        if sz == 8: return 'i64'
        return 'bytes:{}'.format(sz)
    if arg.endswith(' const'):
        arg = arg[:-6].strip()
    # Pointer type stored inline → ptr:struct:RE::T
    if arg.endswith('*'):
        inner_arg = arg[:-1].strip()
        return _ptr_type_for(inner_arg)
    inner_o, inner_a = parse_tmpl(arg)
    bare = _bare(inner_o)
    if bare in INTEGRAL_SIZES:
        sz = INTEGRAL_SIZES[bare]
        if sz == 1: return 'i8'
        if sz == 2: return 'i16'
        if sz == 4: return 'i32'
        return 'i64'
    # Smart-pointer wrappers store one pointer (8 bytes)
    if bare in ('NiPointer', 'BSTSmartPointer', 'hkRefPtr') and inner_a:
        return _ptr_type_for(inner_a[0])
    # Struct/template instantiation stored by value
    full = arg if arg.startswith('RE::') else 'RE::' + arg
    return 'struct:{}'.format(full)


def _elem_size(arg, known_sizes=None):
    """Infer byte size of a template argument (primitive, raw pointer, or known smart ptr).
    known_sizes maps bare type name → size for structs/enums already resolved by the pipeline.
    """
    arg = arg.strip()
    sz = _integral_size(arg)
    if sz:
        return sz
    if arg.endswith('*') or arg.endswith('* const'):
        return 8
    inner_o, inner_a = parse_tmpl(arg)
    bare_inner = _bare(inner_o)
    if bare_inner in ('NiPointer', 'BSTSmartPointer', 'hkRefPtr') and inner_a:
        return 8
    # BSPointerHandle<T,...> — 4-byte handle (confirmed from PDB across all instances)
    if bare_inner in ('BSPointerHandle', 'BSUntypedPointerHandle', 'BSUntrackedPointerHandle'):
        return 4
    if known_sizes:
        # Try exact match, then strip leading RE::/detail:: namespace
        sz = known_sizes.get(arg, 0) or known_sizes.get(bare_inner, 0)
        if sz:
            return sz
    return 0


# ---------------------------------------------------------------------------
# Individual rule functions
# Each receives (outer_bare, args) and returns (size, fields) or (0, []).
# ---------------------------------------------------------------------------

def _rule_enum_wrapper(outer, args, known_sizes=None):
    """REX::EnumSet<E, U> and REX::Enum<E, U> — size = sizeof(U).
    If only one arg is given, falls back to known_sizes lookup on the enum type.
    """
    if outer not in ('REX::EnumSet', 'REX::Enum'):
        return 0, []
    if len(args) >= 2:
        sz = _integral_size(args[1])
        if sz:
            return sz, [_int_field('_impl', 0, sz)]
    # 1-arg form: look up the enum's underlying size from already-resolved types
    if known_sizes and args:
        enum_bare = _bare(args[0])
        sz = known_sizes.get(args[0], 0) or known_sizes.get(enum_bare, 0)
        if sz:
            return sz, [_int_field('_impl', 0, sz)]
    return 0, []


def _rule_bstarray(outer, args, known_sizes=None):
    """BSTArray<T[, Alloc]> — size depends on allocator.

    BSTArrayHeapAllocator layout (24 bytes):
      _data(8) | _capacity:u32(4) + _pad0C(4) | _size:u32(4) + _pad14(4)

    BSTSmallArrayHeapAllocator<N> layout (16 + max(8,N) bytes):
      _capflags:u32(4) + _pad04(4) | _local[max(8,N)](N/8) | _size:u32(4) + _pad_tail(4)
    """
    if outer != 'BSTArray' or not args:
        return 0, []
    alloc = _bare(args[1].strip()) if len(args) >= 2 else ''
    data_type = _ptr_type_for(args[0])

    if alloc in ('', 'BSTArrayHeapAllocator'):
        return 24, [
            _f('_data',              0,  8, data_type),
            _int_field('_capacity',  8,  4),
            _int_field('_pad0C',    12,  4),
            _int_field('_size',     16,  4),
            _int_field('_pad14',    20,  4),
        ]

    if alloc == 'BSScrapArrayAllocator':
        return 32, [
            _f('_data',             0,  8, data_type),
            _int_field('_capacity', 8,  4),
            _int_field('_pad0C',   12,  4),
            _int_field('_size',    16,  4),
            _int_field('_pad14',   20,  4),
            _f('_allocator',       24,  8, 'ptr:struct:RE::ScrapHeap'),
        ]

    m = _re.fullmatch(r'BSTSmallArrayHeapAllocator<(\d+)>', alloc)
    if m:
        n = int(m.group(1))
        data_sz = max(8, n)
        total = data_sz + 16
        return total, [
            _int_field('_capflags',    0,  4),   # _capacity:31 + _local:1 bitfields
            _int_field('_pad04',       4,  4),
            _f('_local',               8,  data_sz, data_type if n <= 8 else None),
            _int_field('_size',        8 + data_sz, 4),
            _int_field('_pad_tail',   12 + data_sz, 4),
        ]

    return 0, []


def _rule_smart_ptr(outer, args, known_sizes=None):
    """NiPointer<T>, BSTSmartPointer<T>, hkRefPtr<T>, GPtr<T> — one 8-byte typed pointer."""
    if outer not in ('NiPointer', 'BSTSmartPointer', 'hkRefPtr', 'GPtr') or not args:
        return 0, []
    return 8, [_f('_ptr', 0, 8, _ptr_type_for(args[0]))]


def _rule_bstsimplelist(outer, args, known_sizes=None):
    """BSSimpleList<T> — head pointer + count + pad = 16 bytes.

    _listHead is typed as T* so Ghidra can navigate to the element at offset 0 of
    each node (which is the item field).
    """
    if outer != 'BSSimpleList' or not args:
        return 0, []
    head_type = _ptr_type_for(args[0])
    return 16, [
        _f('_listHead',          0,  8, head_type),
        _int_field('_listSize',  8,  4),
        _int_field('_pad0C',    12,  4),
    ]


def _rule_bstscattertable(outer, args):
    """BSTScatterTable<Key,Eq,Traits,Alloc> — 48 bytes for heap/scrap allocators."""
    if outer != 'BSTScatterTable' or len(args) < 4:
        return 0, []
    alloc = _bare(args[3].strip())
    if alloc == 'BSTScatterTableHeapAllocator':
        return 48, list(_BSTSCATTERTABLE_HEAP_FIELDS)
    if alloc == 'BSTScatterTableScrapAllocator':
        # Matches header layout: _pad08 is u32 (4 bytes), _capacity at 0x0C
        return 48, [
            _int_field('_pad00',    0,  8),   # u64 sentinel seed
            _int_field('_pad08',    8,  4),   # u32 padding
            _int_field('_capacity', 12, 4),
            _int_field('_free',     16, 4),
            _int_field('_good',     20, 4),
            _f('_sentinel',         24, 8, 'ptr'),
            _f('_allocator',        32, 8, 'ptr:struct:RE::ScrapHeap'),
            _f('_entries',          40, 8, 'ptr'),  # byte*
        ]
    return 0, []


def _rule_bstscattertable_traits(outer, args):
    """BSTScatterTableTraits<K,V> — stateless traits type, size=1."""
    if outer != 'BSTScatterTableTraits' or len(args) < 2:
        return 0, []
    return 1, [_f('_pad', 0, 1)]


def _rule_bscrc32(outer, args):
    """BSCRC32<T> — stateless hash functor, size=1."""
    if outer != 'BSCRC32' or not args:
        return 0, []
    return 1, [_f('_pad', 0, 1)]


def _rule_std_equal_to(outer, args):
    """std::equal_to<T> — stateless comparator, size=1."""
    if outer != 'std::equal_to' or not args:
        return 0, []
    return 1, [_f('_pad', 0, 1)]


def _rule_std_array(outer, args, known_sizes=None):
    """std::array<T, N> — size = N * sizeof(T)."""
    if outer != 'std::array' or len(args) < 2:
        return 0, []
    sz_elem = _elem_size(args[0], known_sizes)
    if not sz_elem:
        return 0, []
    try:
        n = int(args[1])
    except ValueError:
        return 0, []
    sz = sz_elem * n
    if not sz:
        return 0, []
    return sz, [_f('_data', 0, sz)]


def _rule_std_vector(outer, args, known_sizes=None):
    """std::vector<T[, Alloc]> — pointer + size + capacity = 24 bytes."""
    if outer != 'std::vector' or not args:
        return 0, []
    data_type = _ptr_type_for(args[0])
    return 24, [
        _f('_data',              0,  8, data_type),
        _int_field('_capacity',  8,  8),
        _int_field('_size',     16,  8),
    ]


def _rule_std_span(outer, args, known_sizes=None):
    """std::span<T[, Extent]> — pointer + size = 16 bytes (dynamic extent only)."""
    if outer != 'std::span' or not args:
        return 0, []
    data_type = _ptr_type_for(args[0])
    return 16, [_f('_data', 0, 8, data_type), _int_field('_size', 8, 8)]


def _rule_std_basic_string(outer, args):
    """std::basic_string<CharT> — MSVC SSO layout = 32 bytes."""
    if outer != 'std::basic_string' or not args:
        return 0, []
    return 32, [
        _f('_bx',               0,  16),   # SSO union: inline buf or heap ptr
        _int_field('_size',    16,   8),
        _int_field('_res',     24,   8),
    ]


def _rule_nitilistitem(outer, args, known_sizes=None):
    """NiTListItem<T> — doubly-linked node: prev(8) + next(8) + data(sizeof T)."""
    if outer != 'NiTListItem' or not args:
        return 0, []
    elem_sz = _elem_size(args[0], known_sizes)
    if not elem_sz:
        return 0, []
    data_off = 16
    sz = (data_off + elem_sz + 7) & ~7
    data_type = _elem_type_for(args[0], known_sizes) or 'bytes:{}'.format(elem_sz)
    node_type = _ptr_type_for('NiTListItem<{}>'.format(args[0]))
    return sz, [
        _f('_prev', 0,        8, node_type),
        _f('_next', 8,        8, node_type),
        _f('_data', data_off, elem_sz, data_type),
    ]


def _rule_bsttuple(outer, args, known_sizes=None):
    """BSTTuple<A, B> — std::pair-like; size derived from element sizes + alignment."""
    if outer != 'BSTTuple' or len(args) < 2:
        return 0, []
    sz_a = _elem_size(args[0], known_sizes)
    sz_b = _elem_size(args[1], known_sizes)
    if not sz_a or not sz_b:
        return 0, []
    # Standard struct layout: B aligned to min(sz_b, 8)
    align_b = min(sz_b, 8)
    off_b = (sz_a + align_b - 1) & ~(align_b - 1)
    total = off_b + sz_b
    # Round total up to alignment of the largest field
    align_total = max(min(sz_a, 8), min(sz_b, 8))
    total = (total + align_total - 1) & ~(align_total - 1)
    type_a = _elem_type_for(args[0], known_sizes) or 'bytes:{}'.format(sz_a)
    type_b = _elem_type_for(args[1], known_sizes) or 'bytes:{}'.format(sz_b)
    return total, [_f('first', 0, sz_a, type_a), _f('second', off_b, sz_b, type_b)]


def _rule_gallocator(outer, args):
    """GAllocatorGH<T, N> — stateless GFx heap allocator, size=1."""
    if outer != 'GAllocatorGH' or not args:
        return 0, []
    return 1, [_f('_pad', 0, 1)]


def _rule_hkarray(outer, args, known_sizes=None):
    """hkArray<T[, Alloc]> / hkArrayBase<T> — _data:T*@0, _size:i32@8, _capFlags:i32@12 = 16."""
    if outer not in ('hkArray', 'hkArrayBase') or not args:
        return 0, []
    data_type = _ptr_type_for(args[0])
    return 16, [
        _f('_data',             0,  8, data_type),
        _int_field('_size',     8,  4),
        _int_field('_capFlags', 12, 4),
    ]


def _rule_hksmallarry(outer, args, known_sizes=None):
    """hkSmallArray<T> — data:T*@0, size:u16@8, capFlags:u16@10, pad:u32@12 = 16."""
    if outer != 'hkSmallArray' or not args:
        return 0, []
    data_type = _ptr_type_for(args[0])
    return 16, [
        _f('data',             0,  8, data_type),
        _int_field('size',     8,  2),
        _int_field('capFlags', 10, 2),
        _int_field('pad0C',    12, 4),
    ]


def _rule_hkinplacearray(outer, args, known_sizes=None):
    """hkInplaceArray<T, N[, Alloc]> — hkArray layout + inline storage of N elements."""
    if outer != 'hkInplaceArray' or len(args) < 2:
        return 0, []
    data_type = _ptr_type_for(args[0])
    try:
        n = int(args[1])
    except ValueError:
        return 0, []
    elem_sz = _elem_size(args[0], known_sizes)
    if not elem_sz:
        return 0, []
    storage_sz = n * elem_sz
    total = 16 + storage_sz
    return total, [
        _f('_data',              0,  8, data_type),
        _int_field('_size',      8,  4),
        _int_field('_capFlags',  12, 4),
        _f('storage',            16, storage_sz),
    ]


def _rule_nitarray(outer, args, known_sizes=None):
    """NiTObjectArray/NiTPrimitiveArray<T> — vtable@0, _data:T*@8, + u16 fields = 24."""
    if outer not in ('NiTObjectArray', 'NiTPrimitiveArray') or not args:
        return 0, []
    data_type = _ptr_type_for(args[0])
    return 24, [
        _f('__vftable',             0,  8, 'ptr'),
        _f('_data',                 8,  8, data_type),
        _int_field('_capacity',     16, 2),
        _int_field('_freeIdx',      18, 2),
        _int_field('_size',         20, 2),
        _int_field('_growthSize',   22, 2),
    ]


def _rule_nitlargearray(outer, args, known_sizes=None):
    """NiTLargeObjectArray/NiTLargePrimitiveArray<T> — vtable@0, _data:T*@8, + u32 fields = 32."""
    if outer not in ('NiTLargeObjectArray', 'NiTLargePrimitiveArray') or not args:
        return 0, []
    data_type = _ptr_type_for(args[0])
    return 32, [
        _f('__vftable',             0,  8, 'ptr'),
        _f('_data',                 8,  8, data_type),
        _int_field('_capacity',     16, 4),
        _int_field('_freeIdx',      20, 4),
        _int_field('_size',         24, 4),
        _int_field('_growthSize',   28, 4),
    ]


def _rule_nitset(outer, args, known_sizes=None):
    """NiTPrimitiveSet/NiTObjectSet<T> — _data:T*@0, _capacity:u32@8, _size:u32@12 = 16."""
    if outer not in ('NiTPrimitiveSet', 'NiTObjectSet') or not args:
        return 0, []
    data_type = _ptr_type_for(args[0])
    return 16, [
        _f('_data',               0,  8, data_type),
        _int_field('_capacity',   8,  4),
        _int_field('_size',       12, 4),
    ]


def _rule_nitlist(outer, args, known_sizes=None):
    """NiTList/NiTPointerList<T> — head:T*@0, tail:T*@8, count:u32@16, pad@20 = 24."""
    if outer not in ('NiTList', 'NiTPointerList') or not args:
        return 0, []
    node_type = _ptr_type_for(args[0])
    return 24, [
        _f('head',              0,  8, node_type),
        _f('tail',              8,  8, node_type),
        _int_field('_count',    16, 4),
        _int_field('_pad14',    20, 4),
    ]


def _rule_simplearray(outer, args, known_sizes=None):
    """SimpleArray<T> — _data:T*@0 (size stored before allocation) = 8."""
    if outer != 'SimpleArray' or not args:
        return 0, []
    data_type = _ptr_type_for(args[0])
    return 8, [_f('_data', 0, 8, data_type)]


def _rule_gatom(outer, args, known_sizes=None):
    """GAtomicInt<T> — volatile T value@0."""
    if outer != 'GAtomicInt' or not args:
        return 0, []
    sz = _elem_size(args[0], known_sizes)
    if not sz:
        return 0, []
    return sz, [_int_field('value', 0, sz)]


def _rule_rtti_rva(outer, args, known_sizes=None):
    """RTTI::RVA<T> — uint32 _rva@0 = 4."""
    if outer not in ('RVA', 'RTTI::RVA') or not args:
        return 0, []
    return 4, [_int_field('_rva', 0, 4)]


def _rule_float_pair(outer, args, known_sizes=None):
    """GPoint<T>, BSTPoint2<T>, MultAdd<T> — two T-sized fields = 2*sizeof(T)."""
    _OUTER_NAMES = {
        'GPoint':                        ('x', 'y'),
        'BSTPoint2':                     ('x', 'y'),
        'BSTPoint2Base':                 ('x', 'y'),
        'MultAdd':                       ('mult', 'add'),
        'ImageSpaceModifierData::MultAdd': ('mult', 'add'),
    }
    if outer not in _OUTER_NAMES or not args:
        return 0, []
    sz = _integral_size(args[0])
    if not sz:
        return 0, []
    ft = _elem_type_for(args[0], known_sizes) or 'bytes:{}'.format(sz)
    names = _OUTER_NAMES[outer]
    return 2 * sz, [_f(names[0], 0, sz, ft), _f(names[1], sz, sz, ft)]


def _rule_float_triple(outer, args, known_sizes=None):
    """BSTPoint3<T> — three T-sized fields = 3*sizeof(T)."""
    if outer not in ('BSTPoint3', 'BSTPoint3Base') or not args:
        return 0, []
    sz = _integral_size(args[0])
    if not sz:
        return 0, []
    ft = _elem_type_for(args[0], known_sizes) or 'bytes:{}'.format(sz)
    return 3 * sz, [_f('x', 0, sz, ft), _f('y', sz, sz, ft), _f('z', 2 * sz, sz, ft)]


def _rule_float_quad(outer, args, known_sizes=None):
    """GRect<T>, NiRect<T> — four T-sized fields = 4*sizeof(T)."""
    if outer not in ('GRect', 'NiRect') or not args:
        return 0, []
    sz = _integral_size(args[0])
    if not sz:
        return 0, []
    ft = _elem_type_for(args[0], known_sizes) or 'bytes:{}'.format(sz)
    names = {
        'GRect':  ('left', 'top', 'right', 'bottom'),
        'NiRect': ('left', 'right', 'top', 'bottom'),
    }[outer]
    return 4 * sz, [_f(names[i], i * sz, sz, ft) for i in range(4)]


def _rule_nitmap(outer, args, known_sizes=None):
    """NiTMap<K,V> / NiTPointerMap<K,V> — vtable@0, _capacity@8, _pad0C@12,
    _data:NiTMapItem<K,V>*@16, _count@24 = 32 bytes.
    """
    if outer not in ('NiTMap', 'NiTPointerMap') or len(args) < 2:
        return 0, []
    k, v = args[0], args[1]
    item_name = 'RE::NiTMapItem<{},{}>'.format(k, v)
    data_type = 'ptr:struct:{}'.format(item_name)
    return 32, [
        _f('__vftable',         0,  8, 'ptr'),
        _int_field('_capacity', 8,  4),
        _int_field('_pad0C',   12,  4),
        _f('_data',            16,  8, data_type),
        _int_field('_count',   24,  4),
        _int_field('_pad1C',   28,  4),
    ]


def _rule_bsfixedstring(outer, args, known_sizes=None):
    """detail::BSFixedString<CharT> / BSFixedString — interned string, one const char* = 8 bytes."""
    if outer not in ('BSFixedString', 'detail::BSFixedString') or not args:
        return 0, []
    char_t = args[0].strip()
    ptr_type = 'ptr:i16' if 'wchar' in char_t else 'ptr:i8'
    return 8, [_f('_data', 0, 8, ptr_type)]


def _rule_bslight_nodelistt(outer, args, known_sizes=None):
    """BSLight::NodeListT<T> — NiTPointerList<T>(24) + fence:NiTListItem<T>*@24 = 32."""
    if outer not in ('BSLight::NodeListT', 'NodeListT') or not args:
        return 0, []
    node_type = _ptr_type_for(args[0])
    return 32, [
        _f('head',              0,  8, node_type),
        _f('tail',              8,  8, node_type),
        _int_field('_count',   16,  4),
        _int_field('_pad14',   20,  4),
        _f('fence',            24,  8, node_type),
    ]


def _rule_bstsmallsharedarray(outer, args, known_sizes=None):
    """BSTSmallSharedArray<T> — _size:u32@0, _pad@4, _data (heap ptr or inline T) @8 = 16."""
    if outer != 'BSTSmallSharedArray' or not args:
        return 0, []
    data_type = _ptr_type_for(args[0])
    return 16, [
        _int_field('_size',  0, 4),
        _int_field('_pad04', 4, 4),
        _f('_data',          8, 8, data_type),
    ]


def _rule_bsstringt(outer, args, known_sizes=None):
    """BSStringT<CharT, N, Policy> — _data:char*@0, _size:u16@8, _capacity:u16@10, _pad:u32@12 = 16."""
    if outer != 'BSStringT' or not args:
        return 0, []
    char_t = args[0].strip()
    data_ptr = 'ptr:i16' if 'wchar' in char_t else 'ptr:i8'
    return 16, [
        _f('_data',              0,  8, data_ptr),
        _int_field('_size',      8,  2),
        _int_field('_capacity', 10,  2),
        _int_field('_pad0C',    12,  4),
    ]


def _rule_bstcommonllmessagequeue(outer, args, known_sizes=None):
    """BSTCommonLLMessageQueue<T> — vtable@0, lock+pad@8, freeList+head node ptrs@16 = 40."""
    if outer != 'BSTCommonLLMessageQueue' or not args:
        return 0, []
    node_type = _ptr_type_for(args[0])
    return 40, [
        _f('__vftable',         0,  8, 'ptr'),
        _int_field('lock',      8,  4),
        _int_field('pad0C',    12,  4),
        _f('freeList',         16,  8, node_type),
        _f('head',             24,  8, node_type),
        _f('tail',             32,  8, node_type),
    ]


def _rule_avs_localmap(outer, args, known_sizes=None):
    """ActorValueStorage::LocalMap<T> — actorValues:BSFixedString@0, entries:T*@8 = 16."""
    if outer not in ('ActorValueStorage::LocalMap', 'LocalMap') or not args:
        return 0, []
    entries_type = _ptr_type_for(args[0])
    return 16, [
        _f('actorValues', 0, 8, 'struct:RE::detail::BSFixedString<char>'),
        _f('entries',     8, 8, entries_type),
    ]


def _t_size(t, known_sizes):
    """Return sizeof(T) for a queue element type string."""
    t = t.strip()
    if t.endswith('*') or t.endswith('* const'):
        return 8
    sz = _integral_size(t)
    if sz:
        return sz
    if known_sizes:
        for key in (t, ('RE::' + t) if not t.startswith('RE::') else t, _bare(t)):
            v = known_sizes.get(key, 0)
            if v:
                return v
        outer_t, _ = parse_tmpl(t)
        if _bare(outer_t) in ('BSTSmartPointer', 'NiPointer', 'hkRefPtr', 'GPtr'):
            return 8
    return 0


def _rule_bststaticfreelist(outer, args, known_sizes=None):
    """BSTStaticFreeList<T, N> — vtable(8)+lock(4)+pad(4)+free:FreeListElem*(8)+elems[N](raw) = 24+N*(sizeof(T)+8)."""
    if outer != 'BSTStaticFreeList' or len(args) < 2:
        return 0, []
    t = args[0].strip()
    try:
        n = int(args[1].strip())
    except (ValueError, TypeError):
        return 0, []
    t_sz = _t_size(t, known_sizes)
    if not t_sz:
        return 0, []
    elem_sz = t_sz + 8  # sizeof(BSTFreeListElem<T>)
    elems_sz = elem_sz * n
    total = 24 + elems_sz
    free_type = _ptr_type_for('BSTFreeListElem<{}>'.format(t))
    return total, [
        _f('__vftable',      0,  8, 'ptr'),
        _int_field('lock',   8,  4),
        _int_field('pad0C', 12,  4),
        _f('free',          16,  8, free_type),
        _f('elems',         24,  elems_sz),
    ]


def _rule_bstcommonstaticmessagequeue(outer, args, known_sizes=None):
    """BSTCommonStaticMessageQueue<T, N> — vtable(8)+lock(4)+pad(4)+buf(T*N)+numEntries/pushIdx/popIdx/pad(4 each)."""
    if outer != 'BSTCommonStaticMessageQueue' or len(args) < 2:
        return 0, []
    t = args[0].strip()
    try:
        n = int(args[1].strip())
    except (ValueError, TypeError):
        return 0, []
    t_sz = _t_size(t, known_sizes)
    if not t_sz:
        return 0, []
    buf_sz = t_sz * n
    total = 16 + buf_sz + 16  # vtable+lock+pad(16) + buffer + numEntries+pushIdx+popIdx+pad(16)
    return total, [
        _f('__vftable',            0,  8, 'ptr'),
        _int_field('lock',         8,  4),
        _int_field('pad0C',       12,  4),
        _f('queueBuffer',         16,  buf_sz),
        _int_field('numEntries',  16 + buf_sz, 4),
        _int_field('pushIdx',     20 + buf_sz, 4),
        _int_field('popIdx',      24 + buf_sz, 4),
        _int_field('_pad_end',    28 + buf_sz, 4),
    ]


def _rule_bstcommonscrapheapmessagequeue(outer, args, known_sizes=None):
    """BSTCommonScrapHeapMessageQueue<T> — vtable(8)+lock(4)+pad(4)+ScrapHeap*(8)+u64(8)+u64(8) = 40."""
    if outer != 'BSTCommonScrapHeapMessageQueue' or not args:
        return 0, []
    return 40, [
        _f('__vftable',     0,  8, 'ptr'),
        _int_field('lock',  8,  4),
        _int_field('pad0C', 12, 4),
        _f('unk10',         16, 8, 'ptr:struct:RE::ScrapHeap'),
        _int_field('unk18', 24, 8),
        _int_field('unk20', 32, 8),
    ]


def _rule_bsteventsource(outer, args, known_sizes=None):
    """BSTEventSource<Event> — 3×BSTArray<Sink*>(24) + BSSpinLock(8) + bool + u8 + u16 + u32 = 88."""
    if outer != 'BSTEventSource' or not args:
        return 0, []
    event = args[0].strip()
    if not event.startswith('RE::') and not _integral_size(event) and '*' not in event:
        event_q = 'RE::' + event
    else:
        event_q = event
    sink_t = 'struct:RE::BSTArray<RE::BSTEventSink<{}> *,RE::BSTArrayHeapAllocator>'.format(event_q)
    return 88, [
        _f('sinks',               0,  24, sink_t),
        _f('pendingRegisters',   24,  24, sink_t),
        _f('pendingUnregisters', 48,  24, sink_t),
        _f('lock',               72,   8, 'struct:RE::BSSpinLock'),
        _f('notifying',          80,   1, 'bool'),
        _int_field('pad51',      81,   1),
        _int_field('pad52',      82,   2),
        _int_field('pad54',      84,   4),
    ]


def _rule_bsresource_rhandletype(outer, args, known_sizes=None):
    """BSResource::RHandleType<T_Entry, T_EntryDB> — _entry: T_Entry* @0 = 8."""
    if outer not in ('BSResource::RHandleType', 'RHandleType') or not args:
        return 0, []
    entry_type = _ptr_type_for(args[0])
    return 8, [_f('_entry', 0, 8, entry_type)]


def _rule_bsresource_entrybucketqueue(outer, args, known_sizes=None):
    """BSResource::EntryBucketQueue<T, SIZE> — N bucket_i:EntryQueue<T>(24) + step:u32 + pad = N*24+8."""
    if outer not in ('BSResource::EntryBucketQueue', 'EntryBucketQueue') or len(args) < 2:
        return 0, []
    t = args[0]
    try:
        n = int(args[1])
    except (ValueError, TypeError):
        return 0, []
    queue_type = 'struct:RE::BSResource::EntryQueue<{}>'.format(t)
    bucket_sz = 24  # sizeof(EntryQueue<T>) == 0x18
    total = bucket_sz * n + 8  # step(4) + trailing_pad(4)
    fields = [_f('bucket_{}'.format(i), i * bucket_sz, bucket_sz, queue_type) for i in range(n)]
    fields.append(_int_field('step',     n * bucket_sz,     4))
    fields.append(_int_field('_pad_end', n * bucket_sz + 4, 4))
    return total, fields


# ---------------------------------------------------------------------------
# Dispatch table — rules tried in order
# ---------------------------------------------------------------------------

_RULES = [
    _rule_enum_wrapper,
    _rule_bstarray,
    _rule_smart_ptr,
    _rule_bstsimplelist,
    _rule_bsttuple,
    _rule_gallocator,
    _rule_bstscattertable,
    _rule_bstscattertable_traits,
    _rule_bscrc32,
    _rule_std_equal_to,
    _rule_std_array,
    _rule_std_vector,
    _rule_std_span,
    _rule_std_basic_string,
    _rule_nitilistitem,
    # Havok containers
    _rule_hkarray,
    _rule_hksmallarry,
    _rule_hkinplacearray,
    # NiT containers
    _rule_nitarray,
    _rule_nitlargearray,
    _rule_nitset,
    _rule_nitlist,
    # Other containers
    _rule_simplearray,
    _rule_gatom,
    _rule_rtti_rva,
    # Float geometry types
    _rule_float_pair,
    _rule_float_triple,
    _rule_float_quad,
    # Map / string / other
    _rule_nitmap,
    _rule_bsfixedstring,
    _rule_bslight_nodelistt,
    _rule_bstsmallsharedarray,
    _rule_bsstringt,
    _rule_bstcommonllmessagequeue,
    _rule_avs_localmap,
    _rule_bststaticfreelist,
    _rule_bstcommonstaticmessagequeue,
    _rule_bstcommonscrapheapmessagequeue,
    _rule_bsteventsource,
    _rule_bsresource_rhandletype,
    _rule_bsresource_entrybucketqueue,
]


def structural_rule(orig_n, known_sizes=None):
    """Return (size, fields) for a normalised template type, or (0, []) if no rule applies.

    known_sizes: optional dict mapping type name (bare or full) → byte size, used to
    resolve element sizes for tuple/array rules when the element is a struct or enum
    already processed by the pipeline.
    """
    outer, args = parse_tmpl(orig_n)
    bare_outer = _bare(outer)
    for rule in _RULES:
        try:
            sz, fields = rule(bare_outer, args, known_sizes)
        except TypeError:
            # Rule doesn't accept known_sizes (shouldn't happen, but safe fallback)
            sz, fields = rule(bare_outer, args)
        if sz:
            return sz, fields
    return 0, []
