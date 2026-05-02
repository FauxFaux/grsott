import { andThen, type Result } from "./lib/ts.ts";
import { useEffect, useState } from "preact/hooks";
import { JsPackets } from "./lib/schema.ts";

export function WholeFile(props: { fileName: string }) {
  const { fileName } = props;
  console.log(props);
  const [file, setFile] = useState<Result<JsPackets> | undefined>();
  useEffect(() => {
    andThen(async () => {
      const resp = await fetch("http://localhost:4444/cap/" + fileName);

      if (!resp.ok) {
        throw new Error(`Failed to fetch: ${resp.status} ${resp.statusText}`);
      }
      const value = JsPackets.parse(await resp.json());
      return { success: true, value };
    }, setFile);
  }, [fileName]);

  if (!file) return <div>Loading...</div>;
  if (!file.success) return <div>Error: {file.error.message}</div>;
  const objs = file.value.map((v) => ({
    ts: new Date(v.ts).getTime(),
    dir: v.dir,
    header: v.header,
    // @ts-expect-error too new
    body: Uint8Array.fromBase64(v.body),
  }));

  const keys: Record<string, number> = {};
  for (const obj of objs) {
    const k = key(obj.header);
    keys[k] ??= 0;
    keys[k]++;
  }

  const start = objs[0].ts;
  return (
    <>
      <table>
        <tbody>
          {Object.entries(keys).map(([key, count]) => (
            <tr>
              <td>{key}</td>
              <td>{count}</td>
              <td>{knownKeys[key] ?? "unknown key"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <table>
        <tbody>
          {objs.map((obj) => (
            <tr>
              <td>{obj.dir}</td>
              <td>{((obj.ts - start) / 1000).toFixed(2)}</td>
              <td>{knownKeys[key(obj.header)] ?? key(obj.header)}</td>
              <td>{obj.body.length}</td>
              <td>{unambig(obj.body)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function unambig(data: Uint8Array): string {
  const arr = Array.from(data);
  return arr.map((c) => (isAlphaNumeric(c) ? String.fromCharCode(c) : " {" + c + "} ")).join("");
}

function key(header: number[]) {
  let [_u0, _seq, _u2, major, _len1, _len0, n0, n1] = header;

  return [major, n0, n1].map(h).join("");
}

const h = (n: number) => n.toString(16).padStart(2, "0");

const isAlphaNumeric = (c: number) =>
  (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);

const knownKeys: Record<string, string> = {
  "065129": "serials and date",
  "060118": "one byte at the end",
  "060116": "all nulls",
  "065119": "two bytes at the end",
  "065104": "config dump?",
  "065120": "data dump",
};
