"use strict";
// CLI: node check-ids.cjs <design.md> <testsDir>
// Reads the first cells of the section 9 (F-ids) and section 10 (T-ids) tables of the design
// file, collects the title strings passed to test(/it(/describe( in <testsDir>/*.test.ts, prints
// "MISSING: <id>" per missing id (exit 1) or "OK: <n> ids found" (exit 0). Usage or input
// errors: "ERROR: <reason>" on stderr, exit 2.
const fs = require("fs");
const path = require("path");

/** Lines of the section starting with `## <start>` up to (not including) the line starting `## <end>`. */
function sectionLines(text, start, end) {
  const lines = text.split(/\r?\n/);
  const from = lines.findIndex((l) => l.startsWith(start));
  if (from < 0) throw new Error("design section not found: " + start);
  let to = lines.findIndex((l, i) => i > from && l.startsWith(end));
  if (to < 0) to = lines.length;
  return lines.slice(from + 1, to);
}

/** First cells of the markdown table data rows of a section (header and |---| rows skipped). */
function firstCells(lines) {
  const cells = [];
  let sawSep = false;
  for (const l of lines) {
    if (!l.startsWith("|")) {
      sawSep = false;
      continue;
    }
    if (/^\|\s*-{3,}/.test(l)) {
      sawSep = true;
      continue;
    }
    if (sawSep) cells.push(l.split("|")[1].trim());
  }
  return cells;
}

/** Ids of the section 9 table (F-..) and section 10 table (T-..): leading id of the first cell. */
function designIds(text) {
  const f = firstCells(sectionLines(text, "## 9.", "## 10.")).map((c) => (/^F-\d+[a-z]?/.exec(c) || [])[0]);
  const t = firstCells(sectionLines(text, "## 10.", "## 11.")).map((c) => (/^T-\d+[a-z]?/.exec(c) || [])[0]);
  return [...f, ...t].filter((x) => x !== undefined);
}

const TITLE_RE = /\b(?:test|it|describe)(?:\.[a-z]+)?\(\s*(["'`])((?:\\.|(?!\1)[^\\])*)\1/g;

/** Title strings of every test()/it()/describe() call in `source`. */
function titlesOf(source) {
  const out = [];
  let m;
  TITLE_RE.lastIndex = 0;
  while ((m = TITLE_RE.exec(source)) !== null) out.push(m[2]);
  return out;
}

function collectTitles(dir) {
  const titles = [];
  for (const name of fs.readdirSync(dir).sort()) {
    if (!name.endsWith(".test.ts")) continue;
    titles.push(...titlesOf(fs.readFileSync(path.join(dir, name), "utf8")));
  }
  return titles;
}

/** An id counts when not followed by a digit or lowercase letter (F-02 is not satisfied by F-02a). */
function idInTitles(id, titles) {
  const re = new RegExp("(?<![A-Za-z0-9-])" + id.replace(/-/g, "\\-") + "(?![0-9a-z])");
  return titles.some((t) => re.test(t));
}

function main(argv) {
  if (argv.length < 2) {
    process.stderr.write("ERROR: usage: node check-ids.cjs <design.md> <testsDir>\n");
    return 2;
  }
  let ids;
  let titles;
  try {
    ids = designIds(fs.readFileSync(argv[0], "utf8"));
    titles = collectTitles(argv[1]);
  } catch (e) {
    process.stderr.write("ERROR: " + (e instanceof Error ? e.message : String(e)) + "\n");
    return 2;
  }
  const missing = ids.filter((id) => !idInTitles(id, titles));
  if (missing.length > 0) {
    process.stdout.write(missing.map((id) => "MISSING: " + id).join("\n") + "\n");
    return 1;
  }
  process.stdout.write("OK: " + ids.length + " ids found\n");
  return 0;
}

module.exports = { sectionLines, firstCells, designIds, titlesOf, collectTitles, idInTitles };

if (require.main === module) process.exitCode = main(process.argv.slice(2));
