import hashlib
import json
import random

from Crypto.Cipher import AES
import pytest
import zstandard

from opendbc.can.dbc import DBC
from opendbc.can import dbc_asset
from opendbc.car import Bus
from opendbc.car.toyota.values import CAR, DBC as VEHICLE_DBC


def test_protected_names_never_fall_back_to_shared_plaintext(tmp_path, monkeypatch):
  monkeypatch.setattr(dbc_asset, 'default_store', lambda: dbc_asset.ProtectedDBCStore(tmp_path, 'a' * 40))
  for name in dbc_asset.SOURCES:
    with pytest.raises(PermissionError):
      DBC(name)
    path = tmp_path / (name + '.dbc')
    path.write_text('BO_ 1 FAKE: 8 XXX\n')
    with pytest.raises(PermissionError):
      DBC(str(path))
  assert VEHICLE_DBC[CAR.TOYOTA_SIENNA_PATCHED_LTA][Bus.pt] == 'toyota_sienna_patched_lta_pt'
  assert VEHICLE_DBC[CAR.TOYOTA_SIENNA_PATCHED][Bus.pt] == 'toyota_secoc_pt_generated'
  assert DBC('toyota_secoc_pt_generated').name_to_msg['STEERING_LTA_2'].address == 0x131


def test_manifest_rejects_extra_duplicate_and_wrong_asset_identity():
  for raw in (b'{"format":"x", "format":"y"}', b'[]', b'{}'):
    with pytest.raises(ValueError):
      dbc_asset.parse_manifest(raw)


def reference_package(extra_compressed=b''):
  # Independent wire encoder for the specified big-endian nonce/AAD contract, spanning two blocks.
  contents = [random.Random(10).randbytes(800000), random.Random(11).randbytes(800000)]
  plaintext = b''.join(contents)
  compressed = zstandard.ZstdCompressor().compress(plaintext) + extra_compressed
  header = b'CHDBCENC\x01' + bytes(16) + b'\x01\x23\x45\x67' + len(compressed).to_bytes(8, 'big')
  encrypted = header
  for index, offset in enumerate(range(0, len(compressed), 1048576)):
    block = compressed[offset:offset + 1048576]
    cipher = AES.new(bytes(32), AES.MODE_GCM, nonce=b'\x01\x23\x45\x67' + index.to_bytes(8, 'big'))
    cipher.update(b'CHDBCENC-BLOCK-v1' + header + index.to_bytes(8, 'big') + len(block).to_bytes(4, 'big'))
    ciphertext, tag = cipher.encrypt_and_digest(block)
    encrypted += ciphertext + tag

  def digest(data):
    return hashlib.sha256(data).hexdigest()
  manifest = {'format': 'chipmunk-dbc-aes256gcm-v1', 'namespace': 'dbc', 'id': 'a' * 40 + '-' + '0' * 32,
              'platform': 'TOYOTA_SIENNA_PATCHED_LTA', 'source_sha': 'a' * 40, 'key_id': '0' * 32,
              'data_date': '2026-10-28', 'chunk_size': 1048576, 'tag_size': 16, 'nonce_scheme': 'file-id32-counter64-be',
              'package': {'file': 'package.enc', 'size': len(encrypted), 'sha256': digest(encrypted)},
              'plaintext': {'size': len(plaintext), 'sha256': digest(plaintext)},
              'assets': [{'name': name, 'source': source, 'size': len(content), 'sha256': digest(content)}
                         for (name, source), content in zip(dbc_asset.SOURCES.items(), contents, strict=True)]}
  return manifest, encrypted, contents


def test_independent_multiblock_wire_package():
  manifest, encrypted, contents = reference_package()
  assert dbc_asset.decrypt_package(json.dumps(manifest).encode(), encrypted, bytes(32)) == dict(zip(dbc_asset.SOURCES, contents, strict=True))


@pytest.mark.parametrize('fault', ['extra', 'date', 'asset', 'plaintext_hash', 'asset_hash', 'duplicate', 'size', 'zstd_trailing'])
def test_manifest_and_plaintext_authentication_reject_invalid_content(fault):
  manifest, encrypted, _ = reference_package(b'junk' if fault == 'zstd_trailing' else b'')
  if fault == 'extra':
    manifest['key_b64'] = 'forbidden'
  elif fault == 'date':
    manifest['data_date'] = '2026-02-30'
  elif fault == 'asset':
    manifest['assets'][0]['source'] = 'other'
  elif fault == 'plaintext_hash':
    manifest['plaintext']['sha256'] = 'f' * 64
  elif fault == 'asset_hash':
    manifest['assets'][0]['sha256'] = 'f' * 64
  elif fault == 'size':
    manifest['plaintext']['size'] = True
  raw = json.dumps(manifest).encode()
  if fault == 'duplicate':
    raw = raw[:-1] + b',"namespace":"dbc"}'
  with pytest.raises((ValueError, zstandard.ZstdError)):
    dbc_asset.decrypt_package(raw, encrypted, bytes(32))
