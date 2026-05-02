import { serializeError } from "serialize-error";
import type { Result } from "./lib/ts.ts";
import { Link } from "wouter-preact";

export function FileList({ files }: { files: Result<string[]> | undefined }) {
  if (!files) {
    return <div>Loading...</div>;
  }

  if (!files.success) {
    return <div>Error fetching files: {JSON.stringify(serializeError(files.error))}</div>;
  }

  const data = files.value;

  return (
    <ul>
      {data
        .map((file) => {
          const [ts, port, _pacp] = file.split(".");
          return [Number(ts), Number(port)] as const;
        })
        .sort((a, b) => b[0] - a[0])
        .map(([ts, port]) => {
          const when = new Date(Number(ts)).toISOString();
          return (
            <li>
              <Link href={`/whole/${ts}.${port}.pcapng`}>
                {when} ({port})
              </Link>
            </li>
          );
        })}
    </ul>
  );
}
