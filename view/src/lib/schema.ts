import { z } from "zod/mini";

export const Files = z.array(z.string());

export const JsPackets = z.array(
  z.object({
    ts: z.string(),
    dir: z.union([z.literal("to_inverter"), z.literal("from_inverter")]),
    header: z.array(z.number()),
    body: z.string(),
  }),
);

export type JsPackets = z.infer<typeof JsPackets>;
