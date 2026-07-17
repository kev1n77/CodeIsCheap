import { diffWordsWithSpace } from "diff";
import type { AnatomyItem, AnatomySection, CapturedRequest } from "./types";

export type DiffStatus = "same" | "changed" | "added" | "removed";

export interface StructureDiffRow {
  id: string;
  sectionId: string;
  sectionTitle: string;
  label: string;
  role: string | null;
  status: DiffStatus;
  left: string | null;
  right: string | null;
}

export interface StructureDiff {
  rows: StructureDiffRow[];
  counts: Record<DiffStatus, number>;
}

export interface TextDiffSegment {
  value: string;
  status: "same" | "added" | "removed";
}

export function compareStructure(left: CapturedRequest, right: CapturedRequest): StructureDiff {
  const leftSections = new Map(left.detail.anatomy.map((section) => [section.id, section]));
  const rightSections = new Map(right.detail.anatomy.map((section) => [section.id, section]));
  const sectionIds = [
    ...leftSections.keys(),
    ...[...rightSections.keys()].filter((id) => !leftSections.has(id)),
  ];
  const rows = sectionIds.flatMap((sectionId) => compareSection(
    leftSections.get(sectionId),
    rightSections.get(sectionId),
  ));
  const counts: Record<DiffStatus, number> = { same: 0, changed: 0, added: 0, removed: 0 };
  rows.forEach((row) => { counts[row.status] += 1; });
  return { rows, counts };
}

export function comparePromptText(left: CapturedRequest, right: CapturedRequest): TextDiffSegment[] {
  return diffWordsWithSpace(promptText(left), promptText(right)).map((part) => ({
    value: part.value,
    status: part.added ? "added" : part.removed ? "removed" : "same",
  }));
}

export function requestSearchText(request: CapturedRequest): string {
  return [
    request.application,
    request.provider,
    request.operation,
    request.model,
    request.promptPreview,
    ...request.detail.anatomy.flatMap((section) => [
      section.title,
      ...section.items.flatMap((item) => [item.label, item.role ?? "", item.content]),
    ]),
  ].join("\n").toLocaleLowerCase();
}

function compareSection(left: AnatomySection | undefined, right: AnatomySection | undefined) {
  const section = left ?? right;
  if (!section) return [];
  const keyed = section.id === "tools" || section.id === "parameters";
  const pairs = keyed
    ? pairBySemanticKey(left?.items ?? [], right?.items ?? [])
    : pairByPosition(left?.items ?? [], right?.items ?? []);
  return pairs.map(({ key, left: leftItem, right: rightItem }, index): StructureDiffRow => ({
    id: `${section.id}:${key}`,
    sectionId: section.id,
    sectionTitle: section.title,
    label: rightItem?.label ?? leftItem?.label ?? `${section.title} ${index + 1}`,
    role: rightItem?.role ?? leftItem?.role ?? null,
    status: diffStatus(leftItem, rightItem),
    left: leftItem?.content ?? null,
    right: rightItem?.content ?? null,
  }));
}

function pairByPosition(left: AnatomyItem[], right: AnatomyItem[]) {
  return Array.from({ length: Math.max(left.length, right.length) }, (_, index) => ({
    key: String(index),
    left: left[index],
    right: right[index],
  }));
}

function pairBySemanticKey(left: AnatomyItem[], right: AnatomyItem[]) {
  const leftItems = indexedItems(left);
  const rightItems = indexedItems(right);
  const keys = [
    ...leftItems.keys(),
    ...[...rightItems.keys()].filter((key) => !leftItems.has(key)),
  ];
  return keys.map((key) => ({ key, left: leftItems.get(key), right: rightItems.get(key) }));
}

function indexedItems(items: AnatomyItem[]) {
  const occurrences = new Map<string, number>();
  return new Map(items.map((item) => {
    const semantic = `${item.role ?? ""}:${item.label}`.toLocaleLowerCase();
    const occurrence = occurrences.get(semantic) ?? 0;
    occurrences.set(semantic, occurrence + 1);
    return [`${semantic}:${occurrence}`, item] as const;
  }));
}

function diffStatus(left: AnatomyItem | undefined, right: AnatomyItem | undefined): DiffStatus {
  if (!left) return "added";
  if (!right) return "removed";
  return left.content === right.content && left.label === right.label && left.role === right.role
    ? "same"
    : "changed";
}

function promptText(request: CapturedRequest) {
  const promptSections = new Set(["instructions", "messages", "context"]);
  return request.detail.anatomy
    .filter((section) => promptSections.has(section.id))
    .flatMap((section) => section.items.map((item) => {
      const label = item.role ?? item.label;
      return `[${section.title} / ${label}]\n${item.content}`;
    }))
    .join("\n\n");
}
