import type { JsonValue } from "./generated/desktop-api/serde_json/JsonValue";
import type { EvidenceLocator } from "./types";

export interface RawJsonLine {
  pointer: string;
  text: string;
}

export interface ResolvedRawEvidence {
  pointer: string;
  fragment: string | null;
  start: number | null;
  end: number | null;
}

export function resolveEvidencePointer(raw: JsonValue, source: string): string | null {
  if (!source.startsWith("/")) return null;
  const candidates = [source, `/request/body${source}`];
  return candidates.find((pointer) => readJsonPointer(raw, pointer).found) ?? null;
}

export function resolveEvidenceLocator(raw: JsonValue, locator: EvidenceLocator): ResolvedRawEvidence | null {
  const pointer = resolveEvidencePointer(raw, locator.pointer);
  if (!pointer) return null;
  if (locator.kind === "json_pointer") {
    return { pointer, fragment: null, start: null, end: null };
  }

  const resolved = readJsonPointer(raw, pointer);
  if (!resolved.found || typeof resolved.value !== "string") return null;
  const bytes = new TextEncoder().encode(resolved.value);
  if (!Number.isSafeInteger(locator.start) || !Number.isSafeInteger(locator.end)
    || locator.start < 0 || locator.end < locator.start || locator.end > bytes.length) {
    return null;
  }
  return {
    pointer,
    fragment: new TextDecoder().decode(bytes.slice(locator.start, locator.end)),
    start: locator.start,
    end: locator.end,
  };
}

export function formatRawJson(raw: JsonValue): RawJsonLine[] {
  const lines: RawJsonLine[] = [];
  appendJsonValue(lines, raw, "", 0, "", "");
  return lines;
}

function readJsonPointer(raw: JsonValue, pointer: string): { found: boolean; value?: JsonValue } {
  if (pointer === "") return { found: true, value: raw };
  if (!pointer.startsWith("/")) return { found: false };

  let current: JsonValue = raw;
  for (const encoded of pointer.slice(1).split("/")) {
    const segment = encoded.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(current)) {
      if (!/^(0|[1-9]\d*)$/.test(segment)) return { found: false };
      const index = Number(segment);
      if (index >= current.length) return { found: false };
      current = current[index];
    } else if (current !== null && typeof current === "object") {
      if (!Object.prototype.hasOwnProperty.call(current, segment)) return { found: false };
      current = current[segment];
    } else {
      return { found: false };
    }
  }
  return { found: true, value: current };
}

function appendJsonValue(
  lines: RawJsonLine[],
  value: JsonValue,
  pointer: string,
  depth: number,
  prefix: string,
  suffix: string,
) {
  const indent = "  ".repeat(depth);
  if (Array.isArray(value)) {
    if (value.length === 0) {
      lines.push({ pointer, text: `${indent}${prefix}[]${suffix}` });
      return;
    }
    lines.push({ pointer, text: `${indent}${prefix}[` });
    value.forEach((child, index) => appendJsonValue(
      lines,
      child,
      `${pointer}/${index}`,
      depth + 1,
      "",
      index === value.length - 1 ? "" : ",",
    ));
    lines.push({ pointer, text: `${indent}]${suffix}` });
    return;
  }

  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length === 0) {
      lines.push({ pointer, text: `${indent}${prefix}{}${suffix}` });
      return;
    }
    lines.push({ pointer, text: `${indent}${prefix}{` });
    entries.forEach(([key, child], index) => appendJsonValue(
      lines,
      child,
      `${pointer}/${escapePointerSegment(key)}`,
      depth + 1,
      `${JSON.stringify(key)}: `,
      index === entries.length - 1 ? "" : ",",
    ));
    lines.push({ pointer, text: `${indent}}${suffix}` });
    return;
  }

  lines.push({ pointer, text: `${indent}${prefix}${JSON.stringify(value)}${suffix}` });
}

function escapePointerSegment(segment: string) {
  return segment.replace(/~/g, "~0").replace(/\//g, "~1");
}
