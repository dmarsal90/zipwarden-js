import { crc32, deflateRawSync } from 'node:zlib';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Builds malicious ZIP files at test time, so no binaries live in the repo.
 * The bytes are written by hand because common ZIP libraries refuse these shapes.
 */

const UNIX_FILE = 0o100644;
const UNIX_SYMLINK = 0o120777;

export interface Entry {
  name: string;
  data: Buffer;
  mode?: number;
  /** Size written in the headers when it should differ from the real one. */
  declaredSize?: number;
  /** Defaults to true. */
  deflate?: boolean;
  /** General purpose bit flags. */
  flags?: number;
}

export function buildZip(entries: Entry[]): Buffer {
  const body: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const deflate = entry.deflate ?? true;
    const payload = deflate ? deflateRawSync(entry.data) : entry.data;
    const method = deflate ? 8 : 0;
    const crc = crc32(entry.data);
    const size = entry.declaredSize ?? entry.data.length;
    const name = Buffer.from(entry.name, 'utf8');

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(entry.flags ?? 0, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(0, 10); // time
    local.writeUInt16LE(33, 12); // date: 1980-01-01
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(payload.length, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28); // extra length

    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE((3 << 8) | 20, 4); // made by: Unix
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(entry.flags ?? 0, 8);
    header.writeUInt16LE(method, 10);
    header.writeUInt16LE(0, 12);
    header.writeUInt16LE(33, 14);
    header.writeUInt32LE(crc, 16);
    header.writeUInt32LE(payload.length, 20);
    header.writeUInt32LE(size, 24);
    header.writeUInt16LE(name.length, 28);
    // extra, comment, disk and internal attributes stay 0 (offsets 30-37)
    header.writeUInt32LE(((entry.mode ?? UNIX_FILE) << 16) >>> 0, 38);
    header.writeUInt32LE(offset, 42);

    body.push(local, name, payload);
    central.push(header, name);
    offset += local.length + name.length + payload.length;
  }

  const centralBuffer = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuffer.length, 12);
  end.writeUInt32LE(offset, 16);

  return Buffer.concat([...body, centralBuffer, end]);
}

export type FixtureName =
  | 'zip-slip'
  | 'zip-slip-backslash'
  | 'absolute-path'
  | 'symlink'
  | 'null-byte'
  | 'bomb'
  | 'nested-bomb'
  | 'false-size';

/** Create every fixture in a new temporary directory. Call `cleanup` when done. */
export async function createMaliciousZips(): Promise<{
  dir: string;
  paths: Record<FixtureName, string>;
  cleanup: () => Promise<void>;
}> {
  const dir = await mkdtemp(join(tmpdir(), 'zipwarden-'));
  const x = Buffer.from('x');
  const bomb = buildZip([{ name: 'zeros.bin', data: Buffer.alloc(20 * 1024 * 1024) }]);

  const fixtures: Record<FixtureName, Buffer> = {
    'zip-slip': buildZip([{ name: '../evil.txt', data: x }]),
    'zip-slip-backslash': buildZip([{ name: '..\\evil.txt', data: x }]),
    'absolute-path': buildZip([{ name: '/tmp/evil.txt', data: x }]),
    symlink: buildZip([{ name: 'link', data: Buffer.from('/etc/passwd'), mode: UNIX_SYMLINK }]),
    'null-byte': buildZip([{ name: 'safe.txt\0.exe', data: x }]),
    bomb,
    'nested-bomb': buildZip([{ name: 'inner.zip', data: bomb, deflate: false }]),
    'false-size': buildZip([{ name: 'big.txt', data: Buffer.alloc(4096, 'A'), declaredSize: 1 }]),
  };

  await mkdir(dir, { recursive: true });
  const paths = {} as Record<FixtureName, string>;
  for (const [name, bytes] of Object.entries(fixtures) as [FixtureName, Buffer][]) {
    paths[name] = join(dir, `${name}.zip`);
    await writeFile(paths[name], bytes);
  }

  return { dir, paths, cleanup: () => rm(dir, { recursive: true, force: true }) };
}
