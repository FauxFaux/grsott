import { useEffect, useState } from "preact/hooks";
import { andThen, type Result } from "./lib/ts.ts";
import { parsePcapNg } from "./lib/pcap.ts";
import { decodeGrsott } from "./lib/grsott.ts";

export function App() {
  const [state, setState] = useState<Result<ArrayBuffer> | undefined>(undefined);
  useEffect(() => {
    andThen(async () => {
      const resp = await fetch("http://localhost:4444/cap/1769605648355.49157.pcapng");

      if (!resp.ok) {
        throw new Error(`Failed to fetch: ${resp.status} ${resp.statusText}`);
      }
      const value = await resp.arrayBuffer();
      return { success: true, value };
    }, setState);
  }, []);
  if (!state) return <div>Loading...</div>;
  if (!state.success) return <div>Error: {state.error.message}</div>;
  const resp = state.value;
  const objs = decodeGrsott(parsePcapNg(resp));
  const start = objs[0].time;
  return (
    <>
      {objs.map((obj) => (
        <div>
          {obj.direction} {(obj.time - start).toFixed(3)} {obj.data.toHex()}
        </div>
      ))}
    </>
  );
}
