import { describe, expect, it } from "vitest";
import styles from "./styles.css?raw";

describe("theme accessibility", () => {
  it("keeps small tertiary text above WCAG AA contrast in both themes", () => {
    const light = themeBlock(":root {", ":root[data-theme=\"dark\"] {");
    const dark = themeBlock(":root[data-theme=\"dark\"] {", "* { box-sizing");

    for (const [name, theme] of [["light", light], ["dark", dark]] as const) {
      const tertiary = color(theme, "--text-tertiary");
      expect(contrast(tertiary, color(theme, "--surface")), name).toBeGreaterThanOrEqual(4.5);
      expect(contrast(tertiary, color(theme, "--surface-subtle")), name)
        .toBeGreaterThanOrEqual(4.5);
    }
  });
});

function themeBlock(start: string, end: string) {
  const startIndex = styles.indexOf(start);
  const endIndex = styles.indexOf(end, startIndex + start.length);
  if (startIndex < 0 || endIndex < 0) throw new Error(`Theme block ${start} is unavailable`);
  return styles.slice(startIndex, endIndex);
}

function color(block: string, token: string) {
  const match = block.match(new RegExp(`${token}:\\s*(#[0-9a-fA-F]{6})`));
  if (!match) throw new Error(`Color token ${token} is unavailable`);
  return match[1];
}

function contrast(foreground: string, background: string) {
  const first = luminance(foreground);
  const second = luminance(background);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}

function luminance(colorValue: string) {
  const channels = [1, 3, 5].map((offset) => (
    Number.parseInt(colorValue.slice(offset, offset + 2), 16) / 255
  )).map((channel) => (
    channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
  ));
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}
