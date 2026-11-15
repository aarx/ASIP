import React from "react";

/** Accessible table header control shared by sortable data tables. */
export default function SortableHeader({ label, field, sortBy, sortDir, onSort }) {
  const active = sortBy === field;
  const direction = active ? sortDir : null;
  return (
    <th aria-sort={active ? (direction === "asc" ? "ascending" : "descending") : "none"}>
      <button
        type="button"
        className="table-sort-button"
        onClick={() => onSort(field)}
        aria-label={`Sort by ${label}${active ? `, currently ${direction === "asc" ? "ascending" : "descending"}` : ""}`}
      >
        {label}<span className={active ? "table-sort-indicator active" : "table-sort-indicator"} aria-hidden="true">
          {active ? (direction === "asc" ? "↑" : "↓") : "↕"}
        </span>
      </button>
    </th>
  );
}
