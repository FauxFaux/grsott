import { useEffect, useState } from "preact/hooks";
import { andThen, type Result } from "./lib/ts.ts";
import { z } from "zod/mini";

const JsPackets = z.array(
  z.object({
    ts: z.string(),
    dir: z.union([z.literal("to_inverter"), z.literal("from_inverter")]),
    header: z.array(z.number()),
    body: z.string(),
  }),
);

type JsPackets = z.infer<typeof JsPackets>;

export function App() {
  const [state, setState] = useState<Result<JsPackets> | undefined>(undefined);
  useEffect(() => {
    andThen(async () => {
      const resp = await fetch("http://localhost:4444/cap/1769605648355.49157.pcapng");

      if (!resp.ok) {
        throw new Error(`Failed to fetch: ${resp.status} ${resp.statusText}`);
      }
      const value = JsPackets.parse(await resp.json());
      return { success: true, value };
    }, setState);
  }, []);
  if (!state) return <div>Loading...</div>;
  if (!state.success) return <div>Error: {state.error.message}</div>;
  const objs = state.value.map((v) => ({
    ts: new Date(v.ts).getTime(),
    dir: v.dir,
    header: v.header,
    // @ts-expect-error too new
    body: Uint8Array.fromBase64(v.body),
  }));
  const start = objs[0].ts;
  return (
    <>
      {objs.map((obj) => (
        <div>
          {obj.dir} {((obj.ts - start) / 1000).toFixed(2)} {obj.header.join(",")} {obj.body.length}
        </div>
      ))}
    </>
  );
}
