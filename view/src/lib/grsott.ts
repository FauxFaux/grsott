import type { PcapNg } from "./pcap.ts";

export function decodeGrsott(file: PcapNg) {
  const ret: { direction: "c2s" | "s2c"; time: number; data: Uint8Array }[] = [];
  for (const section of file.sections) {
    let c2s: number | undefined;
    let s2c: number | undefined;
    let iidx = 0;
    for (const block of section.blocks) {
      if (block.kind === "InterfaceDescription") {
        switch (block.linkType) {
          case 159:
            c2s = iidx++;
            break;
          case 160:
            s2c = iidx++;
            break;
          default:
            throw new Error(`Unsupported link type ${block.linkType}`);
        }
      }
    }
    if (iidx !== 2 || c2s === undefined || s2c === undefined) {
      throw new Error("GRSOTT file must have exactly two interfaces");
    }
    for (const block of section.blocks) {
      if (block.kind !== "EnhancedPacket") continue;
      ret.push({
        direction: block.interfaceId === c2s ? "c2s" : "s2c",
        time:
          Number(block.timestampRaw / 1_000_000n) +
          Number(block.timestampRaw % 1_000_000n) / 1_000_000,
        data: block.data,
      });
    }
  }
  return ret;
}
