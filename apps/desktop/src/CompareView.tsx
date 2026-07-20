import { useMemo, useState } from "react";
import { ArrowLeftRight, Braces, X } from "lucide-react";
import type { CapturedRequest } from "./types";
import { comparePromptText, compareStructure } from "./compare";
import { handleTabListKeyDown } from "./accessibility";

export type CompareMode = "structure" | "text";

export function CompareView({ left, right, mode, onMode, onSwap, onClose }: {
  left: CapturedRequest;
  right: CapturedRequest;
  mode: CompareMode;
  onMode: (mode: CompareMode) => void;
  onSwap: () => void;
  onClose: () => void;
}) {
  const [showUnchanged, setShowUnchanged] = useState(false);
  const structure = useMemo(() => compareStructure(left, right), [left, right]);
  const text = useMemo(() => comparePromptText(left, right), [left, right]);
  const rows = showUnchanged ? structure.rows : structure.rows.filter((row) => row.status !== "same");

  return (
    <section className="inspector compare-view" aria-label="Request comparison">
      <header className="compare-header">
        <div className="compare-request">
          <span>Baseline</span>
          <strong>{left.model}</strong>
          <small>{left.provider} · {left.operation}</small>
        </div>
        <ArrowLeftRight size={18} aria-hidden="true" />
        <div className="compare-request">
          <span>Target</span>
          <strong>{right.model}</strong>
          <small>{right.provider} · {right.operation}</small>
        </div>
        <div className="compare-actions">
          <button className="icon-button" title="Swap baseline and target" aria-label="Swap comparison sides" onClick={onSwap}><ArrowLeftRight size={16} /></button>
          <button className="icon-button" title="Close comparison" aria-label="Close comparison" onClick={onClose}><X size={16} /></button>
        </div>
      </header>
      <div className="compare-summary" aria-label="Comparison summary">
        <span><b>{structure.counts.changed}</b> changed</span>
        <span><b>{structure.counts.added}</b> added</span>
        <span><b>{structure.counts.removed}</b> removed</span>
        <span><b>{structure.counts.same}</b> unchanged</span>
      </div>
      <div className="inspector-tabs" role="tablist" aria-label="Comparison views" onKeyDown={handleTabListKeyDown}>
        <button id="compare-tab-structure" role="tab" aria-controls="compare-panel" aria-selected={mode === "structure"} tabIndex={mode === "structure" ? 0 : -1} onClick={() => onMode("structure")}><Braces size={14} />Structure</button>
        <button id="compare-tab-text" role="tab" aria-controls="compare-panel" aria-selected={mode === "text"} tabIndex={mode === "text" ? 0 : -1} onClick={() => onMode("text")}><span className="text-diff-icon" aria-hidden="true">Aa</span>Text</button>
      </div>
      <div id="compare-panel" className="inspector-content compare-content" role="tabpanel" aria-labelledby={`compare-tab-${mode}`} tabIndex={0}>
        {mode === "structure" && <>
          <label className="compare-unchanged"><input type="checkbox" checked={showUnchanged} onChange={(event) => setShowUnchanged(event.target.checked)} />Show unchanged</label>
          {rows.length > 0 ? <table className="compare-table">
            <thead><tr><th>Field</th><th>Baseline</th><th>Target</th></tr></thead>
            <tbody>{rows.map((row) => <tr key={row.id} className={`diff-${row.status}`}>
              <th scope="row"><span>{row.sectionTitle}</span><strong>{row.role ?? row.label}</strong><em>{row.status}</em></th>
              <td>{row.left == null ? <span className="diff-empty">Not present</span> : <pre>{row.left}</pre>}</td>
              <td>{row.right == null ? <span className="diff-empty">Not present</span> : <pre>{row.right}</pre>}</td>
            </tr>)}</tbody>
          </table> : <div className="compare-empty"><Braces size={24} /><strong>No structural differences</strong><span>Messages, tools, and parameters are identical.</span></div>}
        </>}
        {mode === "text" && <pre className="text-diff" aria-label="Prompt text difference">{text.length > 0 ? text.map((segment, index) => <span key={`${segment.status}-${index}`} className={`text-${segment.status}`}>{segment.value}</span>) : <span className="text-same">No prompt text available.</span>}</pre>}
      </div>
    </section>
  );
}
