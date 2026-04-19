import express from "express";

async function main() {
  const app = express();
  app.get("/cap/:file", (req, res) => {
    const file = req.params.file;
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", "application/octet-stream");
    res.sendFile(file, { root: ".." });
  });
  app.listen(4444);
}

await main();
