import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { type FormEvent, useId, useState } from "react";

import {
  activeFilterCount,
  EMPTY_FILTERS,
  type HistoryFilters,
  type HistoryFinding,
  type HistoryScan,
  type HistoryTab,
  historySearchFromFilters,
  parseHistorySearch,
  SCAN_STATES,
  SEVERITIES,
  SOURCE_KINDS,
  TRIAGE_STATES,
  useApplicationOptions,
  useHistoryFindings,
  useHistoryScans,
  useVendorOptions,
  VERDICTS,
} from "../api/history";
import { SeverityBadge, SeverityCountBadges } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import { Button } from "../components/ui/button";
import { Checkbox } from "../components/ui/checkbox";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { EmptyState, ErrorNotice, Field, LoadingText, PageHeader } from "../components/ui/page";
import { Select } from "../components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { findingsCsvUrl } from "../lib/csv";
import { formatDateTime, humanize, shortSha } from "../lib/format";

// ------------------------------------------------------------------------------------------ filters

function CheckboxGroup({
  legend,
  options,
  selected,
  onChange,
}: {
  legend: string;
  options: readonly string[];
  selected: string[];
  onChange: (next: string[]) => void;
}) {
  const base = useId();
  return (
    <fieldset className="min-w-0 border-0 p-0">
      <legend className="mb-1.5 text-sm font-medium">{legend}</legend>
      <div className="flex flex-wrap gap-x-4 gap-y-1.5">
        {options.map((option) => {
          const id = `${base}-${option}`;
          return (
            <div key={option} className="flex items-center gap-2">
              <Checkbox
                id={id}
                checked={selected.includes(option)}
                onCheckedChange={(checked) =>
                  onChange(
                    checked === true
                      ? [...selected, option]
                      : selected.filter((value) => value !== option),
                  )
                }
              />
              <Label htmlFor={id} className="font-normal">
                {humanize(option)}
              </Label>
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}

function splitList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

function FilterBar({
  tab,
  filters,
  onApply,
}: {
  tab: HistoryTab;
  filters: HistoryFilters;
  onApply: (next: HistoryFilters) => void;
}) {
  const [draft, setDraft] = useState<HistoryFilters>(filters);
  const [toolsText, setToolsText] = useState(filters.tools.join(", "));
  const applications = useApplicationOptions();
  const vendors = useVendorOptions();
  const uid = useId();
  const set = <K extends keyof HistoryFilters>(key: K, value: HistoryFilters[K]) =>
    setDraft((current) => ({ ...current, [key]: value }));

  const submit = (event: FormEvent) => {
    event.preventDefault();
    onApply({ ...draft, tools: splitList(toolsText) });
  };
  const clear = () => {
    setDraft(EMPTY_FILTERS);
    setToolsText("");
    onApply(EMPTY_FILTERS);
  };

  return (
    <form
      onSubmit={submit}
      aria-label="Filters"
      className="mb-4 flex flex-col gap-4 rounded-md border border-border p-4"
    >
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Field id={`${uid}-app`} label="Application">
          <Select
            id={`${uid}-app`}
            value={draft.application}
            onChange={(e) => set("application", e.target.value)}
          >
            <option value="">All applications</option>
            {applications.data?.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field id={`${uid}-vendor`} label="Vendor">
          <Select
            id={`${uid}-vendor`}
            value={draft.vendor}
            onChange={(e) => set("vendor", e.target.value)}
          >
            <option value="">All vendors</option>
            {vendors.data?.map((v) => (
              <option key={v.id} value={v.id}>
                {v.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field id={`${uid}-type`} label="Internal or vendor">
          <Select
            id={`${uid}-type`}
            value={draft.type}
            onChange={(e) => set("type", e.target.value as HistoryFilters["type"])}
          >
            <option value="">Internal and vendor</option>
            <option value="internal">Internal applications</option>
            <option value="vendor">Vendor applications</option>
          </Select>
        </Field>
        <Field id={`${uid}-tool`} label="Tools" help="Separate several with commas.">
          <Input
            id={`${uid}-tool`}
            value={toolsText}
            onChange={(e) => setToolsText(e.target.value)}
            placeholder="semgrep, gitleaks"
          />
        </Field>
        <Field id={`${uid}-from`} label="From date">
          <Input
            id={`${uid}-from`}
            type="date"
            value={draft.from}
            onChange={(e) => set("from", e.target.value)}
          />
        </Field>
        <Field id={`${uid}-to`} label="To date">
          <Input
            id={`${uid}-to`}
            type="date"
            value={draft.to}
            onChange={(e) => set("to", e.target.value)}
          />
        </Field>
        <Field id={`${uid}-by`} label="Started by (user ID)">
          <Input
            id={`${uid}-by`}
            value={draft.startedBy}
            onChange={(e) => set("startedBy", e.target.value.trim())}
            placeholder="User ID from the audit log"
          />
        </Field>
        {tab === "scans" ? (
          <Field id={`${uid}-kind`} label="Kind of scan">
            <Select
              id={`${uid}-kind`}
              value={draft.kind}
              onChange={(e) => set("kind", e.target.value as HistoryFilters["kind"])}
            >
              <option value="">SAST and DAST</option>
              <option value="sast">SAST (code)</option>
              <option value="dast">DAST (running site)</option>
            </Select>
          </Field>
        ) : (
          <Field id={`${uid}-source`} label="Source">
            <Select
              id={`${uid}-source`}
              value={draft.source}
              onChange={(e) => set("source", e.target.value)}
            >
              <option value="">Any source</option>
              {SOURCE_KINDS.map((kind) => (
                <option key={kind} value={kind}>
                  {humanize(kind)}
                </option>
              ))}
            </Select>
          </Field>
        )}
      </div>

      {tab === "scans" ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <CheckboxGroup
            legend="Scan state"
            options={SCAN_STATES}
            selected={draft.scanStates}
            onChange={(next) => set("scanStates", next)}
          />
          <CheckboxGroup
            legend="Verdict"
            options={VERDICTS}
            selected={draft.verdicts}
            onChange={(next) => set("verdicts", next)}
          />
        </div>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field id={`${uid}-cwe`} label="CWE number">
              <Input
                id={`${uid}-cwe`}
                inputMode="numeric"
                value={draft.cwe}
                onChange={(e) => set("cwe", e.target.value.trim())}
                placeholder="79"
              />
            </Field>
            <Field id={`${uid}-cve`} label="CVE">
              <Input
                id={`${uid}-cve`}
                value={draft.cve}
                onChange={(e) => set("cve", e.target.value.trim())}
                placeholder="CVE-2024-12345"
              />
            </Field>
            <Field id={`${uid}-q`} label="Title contains">
              <Input id={`${uid}-q`} value={draft.q} onChange={(e) => set("q", e.target.value)} />
            </Field>
          </div>
          <CheckboxGroup
            legend="Severity"
            options={SEVERITIES}
            selected={draft.severities}
            onChange={(next) => set("severities", next)}
          />
          <div className="grid gap-4 lg:grid-cols-2">
            <CheckboxGroup
              legend="State today"
              options={TRIAGE_STATES}
              selected={draft.statesNow}
              onChange={(next) => set("statesNow", next)}
            />
            <CheckboxGroup
              legend="State when scanned"
              options={TRIAGE_STATES}
              selected={draft.statesThen}
              onChange={(next) => set("statesThen", next)}
            />
          </div>
        </>
      )}

      <div className="flex flex-wrap gap-2">
        <Button type="submit">Apply filters</Button>
        <Button type="button" variant="outline" onClick={clear}>
          Clear filters
        </Button>
      </div>
    </form>
  );
}

// ------------------------------------------------------------------------------------------ tables

function ScansTable({ scans }: { scans: HistoryScan[] }) {
  return (
    <Table aria-label="Scans">
      <TableHeader>
        <TableRow>
          <TableHead>Started</TableHead>
          <TableHead>Application</TableHead>
          <TableHead>Version</TableHead>
          <TableHead>Kind</TableHead>
          <TableHead>State</TableHead>
          <TableHead>Tools</TableHead>
          <TableHead>Open findings</TableHead>
          <TableHead>Verdict</TableHead>
          <TableHead>Started by</TableHead>
          <TableHead>
            <span className="sr-only">Actions</span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {scans.map((scan) => (
          <TableRow key={scan.id}>
            <TableCell className="whitespace-nowrap">{formatDateTime(scan.created_at)}</TableCell>
            <TableCell>
              <span className="font-medium">{scan.application_name}</span>
              {scan.vendor_name ? (
                <span className="block text-xs text-muted-foreground">Vendor: {scan.vendor_name}</span>
              ) : null}
            </TableCell>
            <TableCell>
              {scan.version_label}
              {scan.commit_sha ? (
                <span className="block font-mono text-xs text-muted-foreground">
                  {shortSha(scan.commit_sha)}
                </span>
              ) : null}
            </TableCell>
            <TableCell>
              {scan.kind.toUpperCase()}
              <span className="block text-xs text-muted-foreground">{scan.profile_name}</span>
            </TableCell>
            <TableCell>
              <StatusBadge status={scan.state} />
            </TableCell>
            <TableCell>{scan.tools.join(", ") || "-"}</TableCell>
            <TableCell>
              <SeverityCountBadges counts={scan.counts} />
            </TableCell>
            <TableCell>
              <StatusBadge status={scan.verdict} />
            </TableCell>
            <TableCell>{scan.started_by_name ?? humanize(scan.trigger)}</TableCell>
            <TableCell>
              <Link to="/scans/$scanId" params={{ scanId: scan.id }} className="underline">
                Open<span className="sr-only"> scan of {scan.application_name}</span>
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function findingLocation(finding: HistoryFinding): string {
  if (finding.file_path) return finding.file_path + (finding.line ? ":" + String(finding.line) : "");
  if (finding.url) return finding.url;
  if (finding.component) {
    return finding.component + (finding.component_version ? " " + finding.component_version : "");
  }
  return "-";
}

function FindingsTable({ findings }: { findings: HistoryFinding[] }) {
  return (
    <Table aria-label="Findings">
      <TableHeader>
        <TableRow>
          <TableHead>Scanned</TableHead>
          <TableHead>Application</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Finding</TableHead>
          <TableHead>Tool</TableHead>
          <TableHead>Location</TableHead>
          <TableHead>When scanned</TableHead>
          <TableHead>Today</TableHead>
          <TableHead>
            <span className="sr-only">Links</span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((finding) => (
          <TableRow key={finding.id}>
            <TableCell className="whitespace-nowrap">{formatDateTime(finding.scanned_at)}</TableCell>
            <TableCell>
              {finding.application_name}
              <span className="block text-xs text-muted-foreground">{finding.version_label}</span>
            </TableCell>
            <TableCell>
              <SeverityBadge severity={finding.severity} />
            </TableCell>
            <TableCell className="max-w-md">
              <span className="break-words font-medium">{finding.title}</span>
              <span className="block text-xs text-muted-foreground">
                {[finding.cwe ? "CWE-" + String(finding.cwe) : null, finding.cve]
                  .filter(Boolean)
                  .join(" - ")}
              </span>
            </TableCell>
            <TableCell>{finding.tool}</TableCell>
            <TableCell className="max-w-xs break-all font-mono text-xs">{findingLocation(finding)}</TableCell>
            <TableCell>{humanize(finding.state_at_scan)}</TableCell>
            <TableCell>{humanize(finding.state_now)}</TableCell>
            <TableCell className="whitespace-nowrap">
              <Link to="/scans/$scanId" params={{ scanId: finding.scan_id }} className="underline">
                Scan<span className="sr-only"> of this finding</span>
              </Link>
              {" | "}
              <a
                href={finding.defectdojo_url}
                target="_blank"
                rel="noopener noreferrer"
                className="underline"
              >
                DefectDojo<span className="sr-only"> (opens in a new tab)</span>
              </a>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

// ------------------------------------------------------------------------------------------ panes

function Pager({
  page,
  hasNext,
  fetching,
  onPrevious,
  onNext,
}: {
  page: number;
  hasNext: boolean;
  fetching: boolean;
  onPrevious: () => void;
  onNext: () => void;
}) {
  return (
    <nav aria-label="Pages" className="mt-3 flex items-center justify-between gap-3">
      <Button variant="outline" onClick={onPrevious} disabled={page <= 1 || fetching}>
        Previous page
      </Button>
      <span className="text-sm text-muted-foreground">Page {page}</span>
      <Button variant="outline" onClick={onNext} disabled={!hasNext || fetching}>
        Next page
      </Button>
    </nav>
  );
}

/** One tab's results. Remounted (so back on page 1) whenever the tab or a filter changes. */
function ScansPane({ filters }: { filters: HistoryFilters }) {
  const [cursors, setCursors] = useState<string[]>([]);
  const query = useHistoryScans(filters, cursors[cursors.length - 1]);
  if (query.isPending) return <LoadingText>Loading scans...</LoadingText>;
  if (query.isError) return <ErrorNotice error={query.error} title="Could not load scans" onRetry={() => void query.refetch()} />;
  const { items, next_cursor: next } = query.data;
  return (
    <>
      {items.length === 0 ? (
        <EmptyState>No scans match these filters.</EmptyState>
      ) : (
        <ScansTable scans={items} />
      )}
      <Pager
        page={cursors.length + 1}
        hasNext={next !== null}
        fetching={query.isFetching}
        onPrevious={() => setCursors((c) => c.slice(0, -1))}
        onNext={() => {
          if (next) setCursors((c) => [...c, next]);
        }}
      />
    </>
  );
}

function FindingsPane({ filters }: { filters: HistoryFilters }) {
  const [cursors, setCursors] = useState<string[]>([]);
  const query = useHistoryFindings(filters, cursors[cursors.length - 1]);
  const nextCursor = query.data?.next_cursor ?? null;
  return (
    <>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          Findings are kept for ever, with their triage state when scanned and today.
        </p>
        <Button asChild variant="outline">
          <a href={findingsCsvUrl(filters)} download>
            Export CSV
          </a>
        </Button>
      </div>
      {query.isPending ? <LoadingText>Loading findings...</LoadingText> : null}
      {query.isError ? (
        <ErrorNotice error={query.error} title="Could not load findings" onRetry={() => void query.refetch()} />
      ) : null}
      {query.data ? (
        <>
          {query.data.items.length === 0 ? (
            <EmptyState>No findings match these filters.</EmptyState>
          ) : (
            <FindingsTable findings={query.data.items} />
          )}
          <Pager
            page={cursors.length + 1}
            hasNext={nextCursor !== null}
            fetching={query.isFetching}
            onPrevious={() => setCursors((c) => c.slice(0, -1))}
            onNext={() => {
              if (nextCursor) setCursors((c) => [...c, nextCursor]);
            }}
          />
        </>
      ) : null}
    </>
  );
}

// ------------------------------------------------------------------------------------------ page

export function HistoryPage() {
  const raw: unknown = useSearch({ strict: false });
  const navigate = useNavigate();
  const { tab, filters } = parseHistorySearch(raw);

  const go = (nextTab: HistoryTab, nextFilters: HistoryFilters) =>
    void navigate({
      to: "/history",
      search: historySearchFromFilters(nextTab, nextFilters),
      replace: true,
    });

  // Remounts the filter bar and the results (page 1) when the URL's filters change.
  const stateKey = tab + "|" + JSON.stringify(historySearchFromFilters(tab, filters));

  return (
    <>
      <PageHeader
        title="Historical data"
        description="Every scan and every finding, kept permanently. Filters are part of the address, so you can bookmark or share a view."
      />
      <Tabs value={tab} onValueChange={(value) => go(value === "findings" ? "findings" : "scans", filters)}>
        <TabsList aria-label="Kind of history">
          <TabsTrigger value="scans">Scans</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
        </TabsList>
        <TabsContent value={tab}>
          <FilterBar key={stateKey} tab={tab} filters={filters} onApply={(next) => go(tab, next)} />
          {activeFilterCount(filters) > 0 ? (
            <p className="mb-3 text-sm text-muted-foreground">
              {activeFilterCount(filters)} filter{activeFilterCount(filters) === 1 ? "" : "s"} applied.
            </p>
          ) : null}
          {tab === "scans" ? (
            <ScansPane key={stateKey} filters={filters} />
          ) : (
            <FindingsPane key={stateKey} filters={filters} />
          )}
        </TabsContent>
      </Tabs>
    </>
  );
}
