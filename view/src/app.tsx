import { useEffect, useState } from "preact/hooks";
import { andThen, type Result } from "./lib/ts.ts";
import { FileList } from "./file-list.tsx";
import { WholeFile } from "./whole-file.tsx";
import { Route, Router } from "wouter-preact";
import { useHashLocation } from "wouter-preact/use-hash-location";
import { Files } from "./lib/schema.ts";

export function App() {
  const [files, setFiles] = useState<Result<string[]> | undefined>();

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

  return (
    <Router hook={useHashLocation}>
      <Route path="/">
        <FileList files={files} />
      </Route>
      <Route path="/whole/:fileName">{({ fileName }) => <WholeFile fileName={fileName} />}</Route>
    </Router>
  );
}
