import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

Object.defineProperties(HTMLElement.prototype, {
  offsetHeight: {
    configurable: true,
    get() {
      return this.classList.contains("request-list") ? 600 : 0;
    },
  },
  offsetWidth: {
    configurable: true,
    get() {
      return this.classList.contains("request-list") ? 390 : 0;
    },
  },
});

HTMLElement.prototype.scrollTo = function scrollTo(options?: ScrollToOptions | number, y?: number) {
  this.scrollTop = typeof options === "number" ? (y ?? 0) : (options?.top ?? this.scrollTop);
  this.scrollLeft = typeof options === "number" ? options : (options?.left ?? this.scrollLeft);
  this.dispatchEvent(new Event("scroll"));
};

afterEach(cleanup);
