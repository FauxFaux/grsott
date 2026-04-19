import ensureError from "ensure-error";

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export type Result<T> = { success: true; value: T } | { success: false; error: Error };

/** notably, the returned promise does not reject */
export async function tryTo<T>(fn: () => Promise<T>): Promise<Result<T>> {
  try {
    const value = await fn();
    return { success: true, value };
  } catch (error) {
    return { success: false, error: ensureError(error) };
  }
}

export function andThen<T>(fn: () => Promise<Result<T>>, set: (v: Result<T>) => void) {
  fn()
    .then((r) => set(r))
    .catch((error) => set({ success: false, error }));
}
