"""Authenticated Sienna DBC packages. No plaintext files or shared DBC fallback."""
import base64
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct

from Crypto.Cipher import AES
import zstandard

FORMAT = 'chipmunk-dbc-aes256gcm-v1'
PLATFORM = 'TOYOTA_SIENNA_PATCHED_LTA'
SOURCES = {'toyota_sienna_patched_lta_pt': 'toyota_secoc_pt_generated',
           'toyota_sienna_patched_lta_adas': 'toyota_tss2_adas'}
CHUNK_SIZE = 1048576
MAX_SIZE = 16 * CHUNK_SIZE
MAGIC = b'CHDBCENC\x01'
HEADER = struct.Struct('>9s16s4sQ')
DOMAIN = b'CHDBCENC-BLOCK-v1'
STORAGE = Path('/data/dbc/sienna-patched-lta')


def sha256(data: bytes) -> str:
  return hashlib.sha256(data).hexdigest()


def json_bytes(value) -> bytes:
  return (json.dumps(value, indent=2) + '\n').encode()


def _unique(pairs):
  result = {}
  for key, value in pairs:
    if key in result:
      raise ValueError('duplicate JSON field')
    result[key] = value
  return result


def parse_json(raw: bytes, limit=16384):
  if len(raw) > limit:
    raise ValueError('JSON exceeds limit')
  return json.loads(raw, object_pairs_hook=_unique)


def _fields(value, fields):
  if not isinstance(value, dict) or set(value) != set(fields.split()):
    raise ValueError('invalid fields')


def _hex(value, length):
  return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def _size_hash(value):
  if type(value.get('size')) is not int or not 0 < value['size'] <= MAX_SIZE or not _hex(value.get('sha256'), 64):
    raise ValueError('invalid size or digest')


def parse_manifest(raw: bytes) -> dict:
  m = parse_json(raw)
  _fields(m, 'format namespace id platform source_sha key_id data_date chunk_size tag_size nonce_scheme package plaintext assets')
  if (m['format'] != FORMAT or m['namespace'] != 'dbc' or m['platform'] != PLATFORM or
      not _hex(m['source_sha'], 40) or not _hex(m['key_id'], 32) or
      m['id'] != m['source_sha'] + '-' + m['key_id'] or type(m['chunk_size']) is not int or m['chunk_size'] != CHUNK_SIZE or
      type(m['tag_size']) is not int or m['tag_size'] != 16 or m['nonce_scheme'] != 'file-id32-counter64-be'):
    raise ValueError('invalid DBC manifest')
  if not isinstance(m['data_date'], str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', m['data_date']):
    raise ValueError('invalid date')
  date.fromisoformat(m['data_date'])
  _fields(m['package'], 'file size sha256')
  _fields(m['plaintext'], 'size sha256')
  _size_hash(m['package'])
  _size_hash(m['plaintext'])
  if m['package']['file'] != 'package.enc' or not isinstance(m['assets'], list) or len(m['assets']) != 2:
    raise ValueError('invalid package assets')
  for asset, (name, source) in zip(m['assets'], SOURCES.items(), strict=True):
    _fields(asset, 'name source size sha256')
    _size_hash(asset)
    if asset['name'] != name or asset['source'] != source:
      raise ValueError('invalid asset identity/order')
  if sum(a['size'] for a in m['assets']) != m['plaintext']['size']:
    raise ValueError('invalid plaintext size')
  return m


def release_key(raw: bytes, manifest_raw: bytes) -> bytes:
  m = parse_manifest(manifest_raw)
  record = parse_json(raw, 4096)
  _fields(record, 'namespace id key_format algorithm key_id data_date manifest_sha256 key_wrap key_b64')
  expected = {'namespace': 'dbc', 'id': m['id'], 'key_format': 1, 'algorithm': 'AES-256-GCM',
              'key_id': m['key_id'], 'data_date': m['data_date'], 'manifest_sha256': sha256(manifest_raw), 'key_wrap': 'none'}
  if type(record['key_format']) is not int or any(record[k] != v for k, v in expected.items()):
    raise ValueError('release key does not match manifest')
  encoded = record['key_b64']
  if not isinstance(encoded, str) or len(encoded) != 44:
    raise ValueError('invalid release key')
  key = base64.b64decode(encoded, validate=True)
  if len(key) != 32 or base64.b64encode(key).decode() != encoded:
    raise ValueError('invalid release key')
  return key


def decrypt_package(manifest_raw: bytes, encrypted: bytes, key: bytes) -> dict[str, bytes]:
  m = parse_manifest(manifest_raw)
  if len(key) != 32 or len(encrypted) != m['package']['size'] or sha256(encrypted) != m['package']['sha256']:
    raise ValueError('invalid encrypted package')
  if len(encrypted) < HEADER.size:
    raise ValueError('truncated package')
  magic, key_id, file_id, compressed_size = HEADER.unpack(encrypted[:HEADER.size])
  if magic != MAGIC or key_id.hex() != m['key_id'] or not 0 < compressed_size <= MAX_SIZE:
    raise ValueError('invalid package header')
  blocks = (compressed_size + CHUNK_SIZE - 1) // CHUNK_SIZE
  if len(encrypted) != HEADER.size + compressed_size + blocks * 16:
    raise ValueError('invalid package framing')
  compressed = bytearray()
  offset = HEADER.size
  for counter in range(blocks):
    size = min(CHUNK_SIZE, compressed_size - counter * CHUNK_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=file_id + counter.to_bytes(8, 'big'), mac_len=16)
    cipher.update(DOMAIN + encrypted[:HEADER.size] + struct.pack('>QI', counter, size))
    compressed.extend(cipher.decrypt_and_verify(encrypted[offset:offset + size], encrypted[offset + size:offset + size + 16]))
    offset += size + 16
  try:
    if zstandard.frame_content_size(compressed) != m['plaintext']['size']:
      raise ValueError('invalid zstd output size')
    plaintext = zstandard.ZstdDecompressor().decompress(compressed, max_output_size=m['plaintext']['size'], allow_extra_data=False)
  except zstandard.ZstdError:
    raise ValueError('invalid zstd payload') from None
  if len(plaintext) != m['plaintext']['size'] or sha256(plaintext) != m['plaintext']['sha256']:
    raise ValueError('invalid plaintext')
  assets = {}
  offset = 0
  for asset in m['assets']:
    content = plaintext[offset:offset + asset['size']]
    if sha256(content) != asset['sha256']:
      raise ValueError('invalid asset digest')
    assets[asset['name']] = content
    offset += asset['size']
  return assets


def source_sha() -> str:
  # A stripped release has no source Git history. Never substitute release HEAD.
  path = Path(__file__).resolve().parents[3] / 'SOURCE_SHA'
  value = path.read_text().strip()
  if not _hex(value, 40):
    raise ValueError('missing or invalid SOURCE_SHA')
  return value


def running_source_sha() -> str | None:
  try:
    return source_sha()
  except (OSError, ValueError):
    return None


def private_write(path: Path, data: bytes):
  path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
  temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
  try:
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
      output.write(data)
      output.flush()
      os.fsync(output.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
      os.fsync(fd)
    finally:
      os.close(fd)
  finally:
    temporary.unlink(missing_ok=True)


def private_read(path: Path, limit=MAX_SIZE) -> bytes:
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
  with os.fdopen(fd, 'rb') as source:
    info = os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit:
      raise ValueError('unsafe protected storage')
    return source.read(limit + 1)


def hardware_serial() -> str:
  from openpilot.common.hardware import HARDWARE, PC
  if PC:
    raise PermissionError('Sienna Patched LTA 需要车机硬件序列号')
  return HARDWARE.get_serial()


class ProtectedDBCStore:
  def __init__(self, root: Path, revision: str | None, device_serial=None):
    if revision is not None and not _hex(revision, 40):
      raise ValueError('invalid source revision')
    self.root, self.revision = root, revision
    self.device_serial = hardware_serial if device_serial is None else device_serial

  def _targets(self):
    if self.revision is None:
      raise PermissionError('运行树 SOURCE_SHA 不可用')
    targets = sorted((p for p in (self.root / 'releases').glob(self.revision + '-*')
                      if re.fullmatch(self.revision + '-[0-9a-f]{32}', p.name) and p.is_dir()),
                     key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
    try:
      current = private_read(self.root / 'current', 128).decode()
    except (OSError, ValueError, UnicodeError):
      current = ''
    return sorted(targets, key=lambda p: p.name != current)

  def signature(self):
    targets = self._targets()
    if not targets:
      raise FileNotFoundError('no installed DBC for source')
    paths = [target / name for target in targets for name in ('manifest.json', 'package.enc', 'release.key')]
    paths.append(self.root / 'device.key')
    signature = []
    for path in paths:
      try:
        info = path.lstat()
        signature.append((str(path), info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
      except OSError:
        signature.append((str(path), None))
    return self.revision, tuple(signature)

  def install(self, manifest_raw: bytes, encrypted: bytes, record_raw: bytes):
    m = parse_manifest(manifest_raw)
    key = release_key(record_raw, manifest_raw)
    if m['source_sha'] != self.revision:
      raise ValueError('DBC source mismatch')
    decrypt_package(manifest_raw, encrypted, key)
    device_path = self.root / 'device.key'
    if not device_path.exists():
      private_write(device_path, secrets.token_bytes(32))
    device_key = private_read(device_path, 32)
    cipher = AES.new(device_key, AES.MODE_GCM, nonce=secrets.token_bytes(12))
    cipher.update(b'CHDBCENC-DEVICE-v1' + manifest_raw)
    wrapped, tag = cipher.encrypt_and_digest(key)
    # shortcut: AGNOS software wrapping cannot resist root; upgrade to hardware-backed storage when available.
    target = self.root / 'releases' / m['id']
    private_write(target / 'manifest.json', manifest_raw)
    private_write(target / 'package.enc', encrypted)
    private_write(target / 'release.key', bytes(cipher.nonce) + wrapped + tag)
    private_write(self.root / 'current', m['id'].encode())

  def load(self, name: str) -> bytes:
    if name not in SOURCES:
      raise ValueError('unknown protected DBC')
    state = parse_json(private_read(self.root / 'state.json'))
    if state.get('revoked') or state.get('cleanup_pending') or not state.get('token'):
      raise PermissionError('Sienna Patched LTA 未激活或吊销清理未完成')
    try:
      serial = self.device_serial()
    except Exception:
      raise PermissionError('无法读取当前车机硬件序列号，拒绝加载 DBC') from None
    if not isinstance(serial, str) or not serial.strip() or len(serial) > 256 or state.get('device_id') != serial:
      raise PermissionError('Sienna Patched LTA 授权与当前车机序列号不匹配')
    for target in self._targets():
      try:
        return self._load_release(target)[name]
      except (OSError, ValueError, UnicodeError):
        continue
    raise PermissionError('当前源码没有可用的已安装 DBC 包')

  def _load_release(self, target):
    raw = private_read(target / 'manifest.json', 16384)
    m = parse_manifest(raw)
    if m['id'] != target.name or m['source_sha'] != self.revision:
      raise ValueError('DBC identity mismatch')
    wrapped = private_read(target / 'release.key', 60)
    if len(wrapped) != 60:
      raise ValueError('invalid wrapped key')
    cipher = AES.new(private_read(self.root / 'device.key', 32), AES.MODE_GCM, nonce=wrapped[:12])
    cipher.update(b'CHDBCENC-DEVICE-v1' + raw)
    key = cipher.decrypt_and_verify(wrapped[12:44], wrapped[44:])
    return decrypt_package(raw, private_read(target / 'package.enc'), key)


def default_store() -> ProtectedDBCStore:
  return ProtectedDBCStore(STORAGE, source_sha(), hardware_serial)


def load_protected_dbc(name: str) -> str:
  try:
    return default_store().load(name).decode('utf-8')
  except (OSError, ValueError, UnicodeError, zstandard.ZstdError) as exc:
    raise PermissionError('Sienna Patched LTA 未激活、未 provision 或受保护 DBC 校验失败') from exc
