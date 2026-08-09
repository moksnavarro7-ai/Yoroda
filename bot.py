import requests
import time
import os
import zipfile
import tempfile
import shutil
import struct
import zlib
import base64
import re
from pathlib import Path

# ============================================================
# BOT CONFIG
# ============================================================
TOKEN = "8658169058:AAHC1gGtFhM_tWmagQjQ3Fvsp_Y_5YzAMdg"
API_URL = f"https://api.telegram.org/bot{TOKEN}"

# ============================================================
# PROXY CONFIG (Optional)
# ============================================================
PROXY = None
# PROXY = {
#     "http": "socks5://127.0.0.1:9050",
#     "https": "socks5://127.0.0.1:9050"
# }

# ============================================================
# DECRYPTION TOOL
# ============================================================

LUA_MAGIC_53 = b'\x1bLua\x53'
LUA_MAGIC_52 = b'\x1bLua\x52'
LUA_MAGIC_51 = b'\x1bLua\x51'
ZLIB_MAGIC = 0x78

def decode_andlua(raw):
    if raw[:4] in (LUA_MAGIC_53[:4], LUA_MAGIC_52[:4], LUA_MAGIC_51[:4]):
        return raw
    raw = raw.rstrip(b'\n\r ')
    prefixes = [b'H', b'h', b'G', b'I', b'J']
    for pfix in prefixes:
        modified = pfix + raw[1:]
        pad = (4 - len(modified) % 4) % 4
        try:
            decoded = base64.b64decode(modified + b'=' * pad)
        except Exception:
            continue
        for use_xor in (True, False):
            data = bytearray(decoded)
            if use_xor:
                v = 0
                for i in range(len(data)):
                    v ^= data[i]
                    data[i] = v
            for off in range(len(data)):
                orig = data[off]
                data[off] = ZLIB_MAGIC
                try:
                    result = zlib.decompress(bytes(data[off:]))
                    if result and result[0] == 0x1C:
                        result = b'\x1b' + result[1:]
                    if result[:3] == b'\x1bLu':
                        return result
                except Exception:
                    pass
                data[off] = orig
    try:
        txt = raw.decode('utf-8', errors='replace')
        if 'require' in txt or 'import' in txt or 'function' in txt:
            return raw
    except Exception:
        pass
    raise ValueError('Could not decode')

class Reader:
    __slots__ = ('d', 'p')
    def __init__(self, d):
        self.d = d
        self.p = 0
    def u8(self):
        v = self.d[self.p]
        self.p += 1
        return v
    def u32(self):
        v = struct.unpack_from('<I', self.d, self.p)[0]
        self.p += 4
        return v
    def i32(self):
        v = struct.unpack_from('<i', self.d, self.p)[0]
        self.p += 4
        return v
    def i64(self):
        v = struct.unpack_from('<q', self.d, self.p)[0]
        self.p += 8
        return v
    def f64(self):
        v = struct.unpack_from('<d', self.d, self.p)[0]
        self.p += 8
        return v
    def lua_str(self):
        sz = self.u8()
        if sz == 0:
            return None
        if sz == 0xFF:
            sz = self.u32()
        raw = self.d[self.p:self.p + sz - 1]
        self.p += sz - 1
        try:
            return raw.decode('utf-8')
        except:
            return raw.decode('latin-1')

def detect_header(data):
    if data[:4] != b'\x1bLua':
        raise ValueError('Not a Lua bytecode file')
    ver = data[4]
    if ver == 0x53:
        return 34
    elif ver == 0x54:
        return 35
    elif ver == 0x52:
        return 18
    elif ver == 0x51:
        return 12
    return 34

def parse_proto(r):
    src = r.lua_str()
    r.i32()
    r.i32()
    r.u8()
    r.u8()
    r.u8()
    nc = r.u32()
    code = [r.u32() for _ in range(nc)]
    nk = r.u32()
    consts = []
    for _ in range(nk):
        tag = r.u8()
        if tag == 0:
            consts.append(None)
        elif tag == 1:
            consts.append(bool(r.u8()))
        elif tag == 3:
            consts.append(r.f64())
        elif tag == 19:
            consts.append(r.i64())
        elif tag in (4, 20):
            consts.append(r.lua_str())
        else:
            consts.append(None)
    nup = r.u32()
    for _ in range(nup):
        r.u8()
        r.u8()
    np = r.u32()
    protos = [parse_proto(r) for _ in range(np)]
    nl = r.u32()
    for _ in range(nl):
        r.u32()
    nloc = r.u32()
    locs = []
    for _ in range(nloc):
        locs.append(r.lua_str())
        r.u32()
        r.u32()
    nun = r.u32()
    upnames = [r.lua_str() for _ in range(nun)]
    return {'code': code, 'consts': consts, 'protos': protos, 'locs': locs, 'upnames': upnames}

def parse_luac(data):
    r = Reader(data)
    r.p = detect_header(data)
    return parse_proto(r)

def decrypt_str(data):
    n = len(data)
    if n == 0:
        return ''
    key = n
    p0 = data[0] ^ key
    step = (p0 + n) & 0xFF
    out = bytearray(n)
    for i, b in enumerate(data):
        out[i] = b ^ key
        total = key + step
        key = ((total & 0xFF) + 1) if total >= 256 else total
    try:
        return out.decode('utf-8')
    except:
        return out.decode('latin-1', errors='replace')

def to_bytes(s):
    for enc in ('latin-1', 'utf-8', 'ascii'):
        try:
            return s.encode(enc)
        except:
            pass
    return s.encode('ascii', errors='replace')

def decrypt_all(proto, cache=None):
    if cache is None:
        cache = {}
    new_consts = []
    for c in proto['consts']:
        if isinstance(c, str) and c:
            if c not in cache:
                cache[c] = decrypt_str(to_bytes(c))
            new_consts.append(cache[c])
        else:
            new_consts.append(c)
    proto['consts'] = new_consts
    for sub in proto['protos']:
        decrypt_all(sub, cache)
    return cache

OPCODES = [
    'MOVE', 'LOADK', 'LOADKX', 'LOADBOOL', 'LOADNIL', 'GETUPVAL',
    'GETTABUP', 'GETTABLE', 'SETTABUP', 'SETUPVAL', 'SETTABLE',
    'NEWTABLE', 'SELF', 'ADD', 'SUB', 'MUL', 'MOD', 'POW', 'DIV',
    'IDIV', 'BAND', 'BOR', 'BXOR', 'SHL', 'SHR', 'UNM', 'BNOT',
    'NOT', 'LEN', 'CONCAT', 'JMP', 'EQ', 'LT', 'LE', 'TEST',
    'TESTSET', 'CALL', 'TAILCALL', 'RETURN', 'FORLOOP', 'FORPREP',
    'TFORCALL', 'TFORLOOP', 'SETLIST', 'CLOSURE', 'VARARG', 'EXTRAARG'
]

OP_ARITH = {
    'ADD': '+', 'SUB': '-', 'MUL': '*', 'DIV': '/', 'MOD': '%',
    'POW': '^', 'IDIV': '//', 'BAND': '&', 'BOR': '|', 'BXOR': '~',
    'SHL': '<<', 'SHR': '>>'
}

def is_ident(s):
    return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', s))

def val_repr(v):
    if v is None:
        return 'nil'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, str):
        esc = v.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
        return f'"{esc}"'
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    if isinstance(v, int):
        if v > 0xFFFF or v < 0:
            return hex(v & 0xFFFFFFFF) if v < 0 else hex(v)
        return str(v)
    return repr(v)

def dot(obj, key_expr):
    if key_expr.startswith('"') and key_expr.endswith('"'):
        inner = key_expr[1:-1]
        if is_ident(inner):
            return f'{obj}.{inner}'
    return f'{obj}[{key_expr}]'

def build_source(proto, depth=0, name=''):
    ind = '    ' * depth
    consts = proto['consts']
    code = proto['code']
    subs = proto['protos']
    locs = proto.get('locs', [])
    upnames = proto.get('upnames', [])
    lines = []
    if depth == 0 and name:
        lines += [f'-- {"=" * 60}', f'-- DECRYPTED: {name}', f'-- {"=" * 60}', '']
    regs = {}
    loc_names = {}
    for idx, nm in enumerate(locs):
        nm = (nm or '').strip()
        if nm and is_ident(nm) and nm not in ('(for index)', '(for limit)', '(for step)'):
            loc_names[idx] = nm
    declared = set()
    used_tmp = {}
    def uv(b):
        if b < len(upnames) and upnames[b]:
            return upnames[b]
        return '_ENV' if b == 0 else f'_UV{b}'
    def grx(r):
        if r in regs and regs[r]:
            return regs[r]
        if r in loc_names and loc_names[r]:
            return loc_names[r]
        return f'r{r}'
    def srx(r, expr):
        regs[r] = expr
    def kval(k):
        return consts[k] if 0 <= k < len(consts) else None
    def kstr(k):
        return val_repr(kval(k))
    def rkx(x):
        return kstr(x - 256) if x >= 256 else grx(x)
    def emit_local(r, rhs):
        nm = loc_names.get(r, '')
        if nm and is_ident(nm):
            if r not in declared:
                declared.add(r)
                lines.append(f'{ind}local {nm} = {rhs}')
            else:
                lines.append(f'{ind}{nm} = {rhs}')
            srx(r, nm)
        else:
            srx(r, rhs)
    def build_args(a, b):
        if b == 1:
            return ''
        return ', '.join(grx(a + x) for x in range(1, b))
    i = 0
    while i < len(code):
        ins = code[i]
        op_n = ins & 0x3F
        a = (ins >> 6) & 0xFF
        b = (ins >> 23) & 0x1FF
        c = (ins >> 14) & 0x1FF
        bx = (ins >> 14) & 0x3FFFF
        sbx = bx - 131071
        op = OPCODES[op_n] if op_n < len(OPCODES) else f'OP{op_n}'
        if op == 'MOVE':
            emit_local(a, grx(b))
        elif op == 'LOADK':
            emit_local(a, val_repr(kval(bx)))
        elif op == 'LOADKX':
            pass
        elif op == 'LOADBOOL':
            emit_local(a, 'true' if b else 'false')
        elif op == 'LOADNIL':
            for x in range(a, a + b + 1):
                emit_local(x, 'nil')
        elif op == 'GETUPVAL':
            emit_local(a, uv(b))
        elif op == 'GETTABUP':
            emit_local(a, dot(uv(b), rkx(c)))
        elif op == 'GETTABLE':
            emit_local(a, dot(grx(b), rkx(c)))
        elif op == 'SETTABUP':
            lines.append(f'{ind}{dot(uv(a), rkx(b))} = {rkx(c)}')
        elif op == 'SETUPVAL':
            lines.append(f'{ind}{uv(b)} = {grx(a)}')
        elif op == 'SETTABLE':
            lines.append(f'{ind}{dot(grx(a), rkx(b))} = {rkx(c)}')
        elif op == 'NEWTABLE':
            if a not in loc_names:
                t_name = f'_t{a}'
                srx(a, t_name)
                lines.append(f'{ind}local {t_name} = {{}}')
                declared.add(a)
            else:
                emit_local(a, '{}')
        elif op == 'SELF':
            obj = grx(b)
            srx(a + 1, obj)
            srx(a, dot(obj, rkx(c)))
        elif op in OP_ARITH:
            emit_local(a, f'{rkx(b)} {OP_ARITH[op]} {rkx(c)}')
        elif op == 'UNM':
            emit_local(a, f'-({grx(b)})')
        elif op == 'BNOT':
            emit_local(a, f'~({grx(b)})')
        elif op == 'NOT':
            emit_local(a, f'not ({grx(b)})')
        elif op == 'LEN':
            emit_local(a, f'#{grx(b)}')
        elif op == 'CONCAT':
            emit_local(a, ' .. '.join(grx(x) for x in range(b, c + 1)))
        elif op == 'JMP':
            if sbx < 0:
                lines.append(f'{ind}end -- loop')
        elif op in ('EQ', 'LT', 'LE'):
            sym_t = {'EQ': ('==', '~='), 'LT': ('<', '>='), 'LE': ('<=', '>')}[op]
            sym = sym_t[0 if a == 0 else 1]
            cond = f'{rkx(b)} {sym} {rkx(c)}'
            if i + 1 < len(code):
                ni = code[i + 1]
                if OPCODES[ni & 0x3F] == 'JMP':
                    lines.append(f'{ind}if {cond} then')
                    i += 1
                else:
                    lines.append(f'{ind}-- cmp: {cond}')
            else:
                lines.append(f'{ind}-- cmp: {cond}')
        elif op in ('TEST', 'TESTSET'):
            cond_str = grx(a) if c != 0 else f'not {grx(a)}'
            lines.append(f'{ind}if {cond_str} then')
        elif op == 'CALL':
            func = grx(a)
            args = build_args(a, b)
            call = f'{func}({args})'
            def make_ret_name(reg, base_func):
                nm = loc_names.get(reg, '')
                if nm and is_ident(nm):
                    return nm
                tail = base_func.split('.')[-1].split('[')[0]
                tail = re.sub(r'[^a-zA-Z0-9_]', '', tail)
                base = f'{tail}_ret' if tail and is_ident(tail) else f'_r{reg}'
                if base in used_tmp:
                    used_tmp[base] += 1
                    return f'{base}{used_tmp[base]}'
                used_tmp[base] = 0
                return base
            if c == 1:
                lines.append(f'{ind}{call}')
            elif c == 2:
                ret = make_ret_name(a, func)
                nm_a = loc_names.get(a, '')
                if nm_a and is_ident(nm_a) and ret == nm_a:
                    emit_local(a, call)
                else:
                    lines.append(f'{ind}local {ret} = {call}')
                    srx(a, ret)
            else:
                n_rets = (c - 1) if c > 0 else 1
                ret_names = [make_ret_name(a + x, func) for x in range(n_rets)]
                rets = ', '.join(ret_names)
                lines.append(f'{ind}local {rets} = {call}')
                for x, rn in enumerate(ret_names):
                    srx(a + x, rn)
        elif op == 'TAILCALL':
            lines.append(f'{ind}return {grx(a)}({build_args(a, b)})')
        elif op == 'RETURN':
            is_last = (i == len(code) - 1)
            if b == 1:
                if not is_last:
                    lines.append(f'{ind}return')
            elif b == 2:
                lines.append(f'{ind}return {grx(a)}')
            else:
                lines.append(f'{ind}return {", ".join(grx(a+x) for x in range(b-1))}')
        elif op == 'FORPREP':
            var = loc_names.get(a + 3, f'_i{a}')
            lines.append(f'{ind}for {var} = {grx(a)}, {grx(a+1)}, {grx(a+2)} do')
        elif op == 'FORLOOP':
            lines.append(f'{ind}end -- for')
        elif op == 'TFORCALL':
            rets = ', '.join(loc_names.get(a+3+x, f'r{a+3+x}') for x in range(c))
            lines.append(f'{ind}{rets} = {grx(a)}({grx(a+1)}, {grx(a+2)})')
        elif op == 'TFORLOOP':
            pass
        elif op == 'SETLIST':
            for j in range(1, b + 1):
                lines.append(f'{ind}{grx(a)}[{(c-1)*50+j}] = {grx(a+j)}')
        elif op == 'CLOSURE':
            sub = subs[bx] if bx < len(subs) else None
            sub_lines = build_source(sub, depth + 1) if sub else [f'{ind}    -- (empty)']
            nm = loc_names.get(a, f'r{a}')
            if a in loc_names and a not in declared:
                declared.add(a)
                lines.append(f'{ind}local {nm} = function()')
            else:
                lines.append(f'{ind}{nm} = function()')
            lines += sub_lines
            lines.append(f'{ind}end')
            srx(a, nm)
        elif op == 'VARARG':
            if b == 2:
                emit_local(a, '...')
            elif b > 2:
                for x in range(b - 1):
                    emit_local(a + x, '...')
        i += 1
    return lines
    
def extract_lua(apk_path):
    lua_files = {}
    with zipfile.ZipFile(apk_path, 'r') as z:
        for info in z.infolist():
            if info.filename.endswith('.lua') or info.filename.endswith('.luac'):
                data = z.read(info.filename)
                name = os.path.basename(info.filename)
                lua_files[info.filename] = (name, data)
    return lua_files

def process_lua(zip_path, name, raw, out_dir):
    result = {'name': name, 'ok': False, 'strings': {}, 'error': ''}
    try:
        try:
            luac = decode_andlua(raw)
        except Exception as e:
            result['error'] = f'decode: {e}'
            raw_out = os.path.join(out_dir, name + '.raw')
            with open(raw_out, 'wb') as f:
                f.write(raw)
            return result
        luac_out = os.path.join(out_dir, name + '.luac')
        with open(luac_out, 'wb') as f:
            f.write(luac)
        if luac[:3] != b'\x1bLu':
            src_out = os.path.join(out_dir, name + '_plain.lua')
            with open(src_out, 'wb') as f:
                f.write(luac)
            result['ok'] = True
            result['note'] = 'plain text'
            return result
        try:
            proto = parse_luac(luac)
        except Exception as e:
            result['error'] = f'parse: {e}'
            return result
        cache = decrypt_all(proto)
        result['strings'] = cache
        src_lines = build_source(proto, name=name)
        src_out = os.path.join(out_dir, name + '_decrypted.lua')
        with open(src_out, 'w', encoding='utf-8', errors='replace') as f:
            f.write('\n'.join(src_lines))
        str_out = os.path.join(out_dir, name + '_strings.txt')
        with open(str_out, 'w', encoding='utf-8', errors='replace') as f:
            f.write(f'# strings from {name}\n\n')
            for idx, (enc, dec) in enumerate(cache.items()):
                f.write(f'[{idx:4d}]  {repr(enc)}\n')
                f.write(f'       => {repr(dec)}\n\n')
        result['ok'] = True
    except Exception as e:
        import traceback
        result['error'] = f'{e}\n{traceback.format_exc()}'
    return result

# ============================================================
# TELEGRAM BOT FUNCTIONS
# ============================================================

def send_message(chat_id, text):
    url = f"{API_URL}/sendMessage"
    data = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    try:
        if PROXY:
            requests.post(url, data=data, timeout=3, proxies=PROXY)
        else:
            requests.post(url, data=data, timeout=3)
    except Exception as e:
        print(f"Send error: {e}")

def send_document(chat_id, file_path, caption=""):
    url = f"{API_URL}/sendDocument"
    try:
        with open(file_path, 'rb') as f:
            files = {'document': f}
            data = {'chat_id': chat_id, 'caption': caption}
            if PROXY:
                requests.post(url, data=data, files=files, timeout=30, proxies=PROXY)
            else:
                requests.post(url, data=data, files=files, timeout=30)
    except Exception as e:
        print(f"Send document error: {e}")

def get_updates(offset=None):
    url = f"{API_URL}/getUpdates"
    if offset:
        url += f"?offset={offset}"
    try:
        if PROXY:
            response = requests.get(url, timeout=2, proxies=PROXY)
        else:
            response = requests.get(url, timeout=2)
        return response.json()
    except Exception as e:
        return {"ok": False}

def download_file(file_id):
    try:
        url = f"{API_URL}/getFile?file_id={file_id}"
        if PROXY:
            response = requests.get(url, timeout=3, proxies=PROXY)
        else:
            response = requests.get(url, timeout=3)
        if response.ok:
            file_path = response.json()["result"]["file_path"]
            download_url = f"https://api.telegram.org/file/bot{TOKEN}/{file_path}"
            if PROXY:
                file_response = requests.get(download_url, timeout=30, proxies=PROXY)
            else:
                file_response = requests.get(download_url, timeout=30)
            if file_response.ok:
                return file_response.content
    except Exception as e:
        print(f"Download error: {e}")
    return None

def process_apk(apk_data, file_name):
    result = {'ok': False, 'files': [], 'error': ''}
    try:
        temp_dir = tempfile.mkdtemp()
        apk_path = os.path.join(temp_dir, file_name)
        with open(apk_path, 'wb') as f:
            f.write(apk_data)
        lua_files = extract_lua(apk_path)
        if not lua_files:
            result['error'] = "No .lua files found in APK"
            shutil.rmtree(temp_dir, ignore_errors=True)
            return result
        apk_name = Path(file_name).stem
        out_dir = os.path.join(temp_dir, f'decrypted_{apk_name}')
        os.makedirs(out_dir, exist_ok=True)
        for zip_path, (name, raw) in lua_files.items():
            try:
                lua_result = process_lua(zip_path, name, raw, out_dir)
                if lua_result.get('ok'):
                    result['files'].append({
                        'name': name,
                        'path': os.path.join(out_dir, name + '_decrypted.lua')
                    })
            except Exception as e:
                print(f"Error processing {name}: {e}")
        if result['files']:
            result['ok'] = True
            result['output_dir'] = out_dir
        else:
            result['error'] = "No files could be decrypted"
    except Exception as e:
        result['error'] = str(e)
    return result

def process_lua_file(lua_data, file_name):
    result = {'ok': False, 'files': [], 'error': ''}
    try:
        temp_dir = tempfile.mkdtemp()
        lua_path = os.path.join(temp_dir, file_name)
        with open(lua_path, 'wb') as f:
            f.write(lua_data)
        lua_name = Path(file_name).stem
        out_dir = os.path.join(temp_dir, f'decrypted_{lua_name}')
        os.makedirs(out_dir, exist_ok=True)
        lua_result = process_lua(lua_path, file_name, lua_data, out_dir)
        if lua_result.get('ok'):
            for f in os.listdir(out_dir):
                if f.endswith('_decrypted.lua') or f.endswith('_strings.txt'):
                    result['files'].append({
                        'name': f,
                        'path': os.path.join(out_dir, f)
                    })
            if result['files']:
                result['ok'] = True
                result['output_dir'] = out_dir
            else:
                result['error'] = "No decrypted files generated"
        else:
            result['error'] = lua_result.get('error', 'Unknown error')
    except Exception as e:
        result['error'] = str(e)
    return result

# ============================================================
# MAIN FAST LOOP
# ============================================================

print("Yoroda Decryptor Bot is running")
print("Bot: @Yoroda_Bot")
print("Response time: < 1 second")
print("Waiting for messages...")

last_update_id = 0
error_count = 0

while True:
    try:
        updates = get_updates(last_update_id + 1)
        error_count = 0
        
        if updates.get("ok"):
            for update in updates.get("result", []):
                if update["update_id"] > last_update_id:
                    last_update_id = update["update_id"]
                    
                    if "message" in update:
                        chat_id = update["message"]["chat"]["id"]
                        text = update["message"].get("text", "")
                        
                        if text == "/start":
                            send_message(chat_id, 
                                "Yoroda Decryptor Bot\n\n"
                                "Send me an APK or .lua/.luac file to decrypt.\n\n"
                                "Commands:\n"
                                "/start - Show this menu\n"
                                "/help - Show help\n"
                                "/info - Bot info"
                            )
                            continue
                        
                        if text == "/help":
                            send_message(chat_id,
                                "How to use:\n\n"
                                "1. Send an APK file\n"
                                "2. Send a .lua or .luac file\n"
                                "3. I will decrypt it automatically\n"
                                "4. Download the decrypted files\n\n"
                                "Supported:\n"
                                "- APK files\n"
                                "- .lua files\n"
                                "- .luac files"
                            )
                            continue
                        
                        if text == "/info":
                            send_message(chat_id,
                                "Yoroda Decryptor Bot\n\n"
                                "Version: 1.0 (Fast)\n"
                                "Status: Online\n\n"
                                "Created by: Yoroda"
                            )
                            continue
                        
                        if "document" in update["message"]:
                            doc = update["message"]["document"]
                            file_name = doc.get("file_name", "file")
                            file_id = doc["file_id"]
                            file_size = doc.get("file_size", 0)
                            
                            is_apk = file_name.endswith('.apk')
                            is_lua = file_name.endswith('.lua') or file_name.endswith('.luac')
                            
                            if not is_apk and not is_lua:
                                send_message(chat_id, "Unsupported file. Send APK, .lua, or .luac.")
                                continue
                            
                            send_message(chat_id, f"Received: {file_name}\nProcessing...")
                            
                            file_data = download_file(file_id)
                            
                            if not file_data:
                                send_message(chat_id, "Failed to download file.")
                                continue
                            
                            if is_apk:
                                result = process_apk(file_data, file_name)
                            else:
                                result = process_lua_file(file_data, file_name)
                            
                            if result.get('ok'):
                                send_message(chat_id, f"Decryption complete! {len(result['files'])} file(s)")
                                
                                for file_info in result['files']:
                                    file_path = file_info['path']
                                    file_name2 = file_info['name']
                                    file_size2 = os.path.getsize(file_path) / 1024
                                    
                                    if file_size2 > 50 * 1024:
                                        send_message(chat_id, f"{file_name2} is too large.")
                                        continue
                                    
                                    send_document(chat_id, file_path, f"{file_name2} ({file_size2:.1f} KB)")
                                    time.sleep(0.2)
                                
                                send_message(chat_id, "All files sent.")
                                
                                if result.get('output_dir'):
                                    shutil.rmtree(result['output_dir'], ignore_errors=True)
                            else:
                                send_message(chat_id, f"Decryption failed.\nError: {result.get('error', 'Unknown')}")
        
        time.sleep(0.3)
        
    except KeyboardInterrupt:
        print("\nBot stopped.")
        break
    except Exception as e:
        error_count += 1
        print(f"Error: {e}")
        if error_count > 10:
            print("Too many errors, restarting...")
            time.sleep(3)
            error_count = 0
        else:
            time.sleep(0.5)