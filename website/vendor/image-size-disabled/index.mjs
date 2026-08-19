const MESSAGE =
  "Local image dimension parsing is disabled; use the bounded Cloudflare image transform path.";

export const types = Object.freeze([]);

export function disableTypes() {}

export function imageSize() {
  throw new TypeError(MESSAGE);
}

export async function imageSizeFromFile() {
  throw new TypeError(MESSAGE);
}
