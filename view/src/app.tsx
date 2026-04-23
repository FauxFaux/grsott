import { useEffect, useState } from "preact/hooks";
import { andThen, type Result } from "./lib/ts.ts";
import { z } from "zod/mini";
import { FileList } from "./file-list.tsx";
import { WholeFile } from "./whole-file.tsx";

const Files = z.array(z.string());

const JsPackets = z.array(
  z.object({
    ts: z.string(),
    dir: z.union([z.literal("to_inverter"), z.literal("from_inverter")]),
    header: z.array(z.number()),
    body: z.string(),
  }),
);

export type JsPackets = z.infer<typeof JsPackets>;

// none of this brings me joy

export function App() {
  const [files, setFiles] = useState<Result<string[]> | undefined>();
  const [fileName, setFileName] = useState<string | undefined>();
  const [file, setFile] = useState<Result<JsPackets> | undefined>();

  useEffect(() => {
    andThen(async () => {
      const resp = await fetch("http://localhost:4444/cap");
      if (!resp.ok) {
        throw new Error(`Failed to fetch: ${resp.status} ${resp.statusText}`);
      }
      const value = Files.parse(await resp.json());
      return { success: true, value };
    }, setFiles);
  }, []);

  useEffect(() => {
    if (!fileName) return;
    andThen(async () => {
      const resp = await fetch("http://localhost:4444/cap/" + fileName);

      if (!resp.ok) {
        throw new Error(`Failed to fetch: ${resp.status} ${resp.statusText}`);
      }
      const value = JsPackets.parse(await resp.json());
      return { success: true, value };
    }, setFile);
  }, [fileName]);

  return fileName ? <WholeFile file={file} /> : <FileList files={files} onSelect={setFileName} />;
}
