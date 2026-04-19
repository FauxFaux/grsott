import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parsePcapNg } from "../src/lib/pcap.ts";

it("should parse pcap", async () => {
  const buf = await readFile(join(import.meta.dirname, "1.pcapng"));
  expect(parsePcapNg(buf)).toMatchSnapshot();
});
