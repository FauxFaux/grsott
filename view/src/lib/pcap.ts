export type BlockKind = "SectionHeader" | "InterfaceDescription" | "EnhancedPacket";

const le = true;

interface BlockBase {
  kind: BlockKind;
  offset: number;
  length: number;
}

export interface SectionHeaderBlock extends BlockBase {
  kind: "SectionHeader";
  majorVersion: number;
  minorVersion: number;
  /** -1n when the section length is unspecified. */
  sectionLength: bigint;
}

export interface InterfaceDescriptionBlock extends BlockBase {
  kind: "InterfaceDescription";
  linkType: number;
  snapLen: number;
  timestampTicksPerSecond: bigint;
  timestampOffsetSeconds: bigint;
}

export interface EnhancedPacketBlock extends BlockBase {
  kind: "EnhancedPacket";
  interfaceId: number;
  timestampRaw: bigint;
  capturedLength: number;
  originalLength: number;
  data: Uint8Array;
}

export type Block = SectionHeaderBlock | InterfaceDescriptionBlock | EnhancedPacketBlock;

export interface Section {
  header: SectionHeaderBlock;
  blocks: Block[];
}

export interface PcapNg {
  sections: Section[];
}

// Block type constants
const BT_SHB = 0x0a0d0d0a;
const BT_IDB = 0x00000001;
const BT_EPB = 0x00000006;

const SHB_MAGIC = 0x1a2b3c4d;

export class PcapNgParseError extends Error {
  readonly offset: number;
  constructor(message: string, offset: number) {
    super(`${message} (at offset 0x${offset.toString(16)})`);
    this.name = "PcapNgParseError";
    this.offset = offset;
  }
}

export function parsePcapNg(input: ArrayBuffer | Uint8Array | ArrayBufferView): PcapNg {
  const bytes = toUint8Array(input);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const sections: Section[] = [];
  let pos = 0;
  let section: Section | null = null;

  while (pos < dv.byteLength) {
    if (dv.byteLength - pos < 12) {
      throw new PcapNgParseError("Truncated block header", pos);
    }

    const blockTypeLE = dv.getUint32(pos, true);
    if (blockTypeLE === BT_SHB) {
      ensureValidSectionHeader(dv, pos);
      const shb = readSectionHeader(dv, pos);
      section = { header: shb, blocks: [] };
      sections.push(section);
      pos += shb.length;
      continue;
    }

    const blockType = dv.getUint32(pos, le);
    const totalLength = dv.getUint32(pos + 4, le);
    if (totalLength < 12 || totalLength % 4 !== 0) {
      throw new PcapNgParseError(`Invalid block total length ${totalLength}`, pos);
    }
    if (pos + totalLength > dv.byteLength) {
      throw new PcapNgParseError("Truncated block", pos);
    }
    const trailing = dv.getUint32(pos + totalLength - 4, le);
    if (trailing !== totalLength) {
      throw new PcapNgParseError(
        `Block trailing length ${trailing} != leading length ${totalLength}`,
        pos,
      );
    }

    if (!section) {
      throw new PcapNgParseError("Non-SHB block encountered before any Section Header", pos);
    }

    const bodyStart = pos + 8;
    const bodyEnd = pos + totalLength - 4;
    const block = readBlock(blockType, dv, bodyStart, bodyEnd, pos, totalLength);
    section.blocks.push(block);
    pos += totalLength;
  }

  return { sections };
}

function toUint8Array(input: ArrayBuffer | Uint8Array | ArrayBufferView): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
}

function ensureValidSectionHeader(dv: DataView, blockOffset: number) {
  // Magic lives 8 bytes into the block body (after type + length).
  const magicOffset = blockOffset + 8;
  if (magicOffset + 4 > dv.byteLength) {
    throw new PcapNgParseError("Truncated Section Header magic", blockOffset);
  }
  const asLE = dv.getUint32(magicOffset, true);
  if (asLE === SHB_MAGIC) return;
  throw new PcapNgParseError("Invalid Section Header magic (maybe BE?)", blockOffset);
}

function readSectionHeader(dv: DataView, offset: number): SectionHeaderBlock {
  const totalLength = dv.getUint32(offset + 4, true);
  if (totalLength < 28 || offset + totalLength > dv.byteLength) {
    throw new PcapNgParseError("Invalid Section Header length", offset);
  }
  const trailing = dv.getUint32(offset + totalLength - 4, true);
  if (trailing !== totalLength) {
    throw new PcapNgParseError(`SHB trailing length ${trailing} != leading ${totalLength}`, offset);
  }
  const majorVersion = dv.getUint16(offset + 12, true);
  const minorVersion = dv.getUint16(offset + 14, true);
  const sectionLength = dv.getBigInt64(offset + 16, true);

  return {
    kind: "SectionHeader",
    offset,
    length: totalLength,
    majorVersion,
    minorVersion,
    sectionLength,
  };
}

function readBlock(
  blockType: number,
  dv: DataView,
  bodyStart: number,
  bodyEnd: number,
  offset: number,
  length: number,
): Block {
  switch (blockType) {
    case BT_IDB:
      return readInterfaceDescription(dv, bodyStart, bodyEnd, offset, length);
    case BT_EPB:
      return readEnhancedPacket(dv, bodyStart, bodyEnd, offset, length);
    default:
      throw new PcapNgParseError(`Unknown block type: ${blockType}`, offset);
  }
}

function readInterfaceDescription(
  dv: DataView,
  bodyStart: number,
  bodyEnd: number,
  offset: number,
  length: number,
): InterfaceDescriptionBlock {
  if (bodyEnd - bodyStart < 8) {
    throw new PcapNgParseError("IDB body too short", offset);
  }
  const linkType = dv.getUint16(bodyStart, le);
  // skip 2 reserved bytes
  const snapLen = dv.getUint32(bodyStart + 4, le);

  return {
    kind: "InterfaceDescription",
    offset,
    length,
    linkType,
    snapLen,
    timestampTicksPerSecond: 1_000_000n,
    timestampOffsetSeconds: 0n,
  };
}

function readEnhancedPacket(
  dv: DataView,
  bodyStart: number,
  bodyEnd: number,
  offset: number,
  length: number,
): EnhancedPacketBlock {
  if (bodyEnd - bodyStart < 20) {
    throw new PcapNgParseError("EPB body too short", offset);
  }
  const interfaceId = dv.getUint32(bodyStart, le);
  const tsUpper = dv.getUint32(bodyStart + 4, le);
  const tsLower = dv.getUint32(bodyStart + 8, le);
  const capturedLength = dv.getUint32(bodyStart + 12, le);
  const originalLength = dv.getUint32(bodyStart + 16, le);
  const dataStart = bodyStart + 20;
  const paddedCaptured = pad4(capturedLength);
  if (dataStart + paddedCaptured > bodyEnd) {
    throw new PcapNgParseError("EPB packet data overruns block", offset);
  }
  const data = viewSlice(dv, dataStart, dataStart + capturedLength);
  const timestampRaw = (BigInt(tsUpper) << 32n) | BigInt(tsLower);
  return {
    kind: "EnhancedPacket",
    offset,
    length,
    interfaceId,
    timestampRaw,
    capturedLength,
    originalLength,
    data,
  };
}

function pad4(n: number): number {
  return (n + 3) & ~3;
}

function viewSlice(dv: DataView, start: number, end: number): Uint8Array {
  return new Uint8Array(dv.buffer, dv.byteOffset + start, end - start);
}
