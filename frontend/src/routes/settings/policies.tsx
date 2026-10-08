import { type FormEvent, useState } from "react";

import { useApplicationOptions } from "../../api/history";
import {
  type DataClassificationName,
  type Policy,
  type PolicyCreate,
  policyScope,
  type Thresholds,
  useBuiltinPolicy,
  useCreatePolicy,
  usePolicies,
  useUpdatePolicy,
} from "../../api/policies";
import { StatusBadge } from "../../components/StatusBadge";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../../components/ui/dialog";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import { EmptyState, ErrorNotice, Field, LoadingText, PageHeader } from "../../components/ui/page";
import { Select } from "../../components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import { humanize } from "../../lib/format";

const LEVELS = ["critical", "high", "medium", "low", "info"] as const;
const CLASSIFICATIONS: DataClassificationName[] = ["public", "internal", "confidential", "restricted"];

type Scope = "default" | "classification" | "application";

export function describeThresholds(map: Record<string, number> | undefined): string {
  const parts = LEVELS.flatMap((level) => {
    const value = map?.[level];
    return value ? [`${value} ${level}`] : [];
  });
  return parts.length > 0 ? parts.join(", ") : "-";
}

/** Text boxes -> thresholds. A blank box means the severity is not used; anything else must be 1 or more. */
export function thresholdsFromInputs(
  fail: Record<string, string>,
  conditional: Record<string, string>,
): { thresholds: Thresholds } | { error: string } {
  const read = (inputs: Record<string, string>, label: string) => {
    const out: Record<string, number> = {};
    for (const level of LEVELS) {
      const text = (inputs[level] ?? "").trim();
      if (!text) continue;
      if (!/^\d+$/.test(text) || Number(text) < 1) {
        return { error: `${label}: the number for ${level} must be a whole number of 1 or more, or empty.` };
      }
      out[level] = Number(text);
    }
    return { value: out };
  };
  const f = read(fail, "Fail");
  if ("error" in f) return { error: f.error };
  const c = read(conditional, "Conditional");
  if ("error" in c) return { error: c.error };
  if (Object.keys(f.value).length === 0) {
    return { error: "Give at least one number under Fail, for example 1 critical." };
  }
  return { thresholds: { fail: f.value, conditional: c.value } };
}

function inputsFrom(map: Record<string, number> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const level of LEVELS) {
    const value = map?.[level];
    out[level] = value ? String(value) : "";
  }
  return out;
}

function ThresholdInputs({
  idPrefix,
  legend,
  help,
  values,
  onChange,
}: {
  idPrefix: string;
  legend: string;
  help: string;
  values: Record<string, string>;
  onChange: (next: Record<string, string>) => void;
}) {
  return (
    <fieldset className="rounded-md border border-border p-3">
      <legend className="px-1 text-sm font-medium">{legend}</legend>
      <p className="mb-2 text-xs text-muted-foreground">{help}</p>
      <div className="grid grid-cols-5 gap-2">
        {LEVELS.map((level) => (
          <div key={level} className="flex flex-col gap-1">
            <Label htmlFor={`${idPrefix}-${level}`} className="text-xs font-normal">
              {humanize(level)}
            </Label>
            <Input
              id={`${idPrefix}-${level}`}
              inputMode="numeric"
              value={values[level] ?? ""}
              onChange={(e) => onChange({ ...values, [level]: e.target.value })}
              placeholder="-"
            />
          </div>
        ))}
      </div>
    </fieldset>
  );
}

function PolicyDialog({
  open,
  onOpenChange,
  policy,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The policy to edit, or null to create one. */
  policy: Policy | null;
}) {
  const create = useCreatePolicy();
  const update = useUpdatePolicy();
  const applications = useApplicationOptions();
  const builtin = useBuiltinPolicy();
  const [name, setName] = useState(policy?.name ?? "");
  const [scope, setScope] = useState<Scope>("classification");
  const [classification, setClassification] = useState<DataClassificationName>("internal");
  const [applicationId, setApplicationId] = useState("");
  const startFrom = policy?.thresholds ?? builtin.data?.thresholds;
  const [fail, setFail] = useState(inputsFrom(startFrom?.fail));
  const [conditional, setConditional] = useState(inputsFrom(startFrom?.conditional));
  const [problem, setProblem] = useState<string | null>(null);
  const mutation = policy ? update : create;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setProblem(null);
    if (!name.trim()) return setProblem("Give the policy a name.");
    const parsed = thresholdsFromInputs(fail, conditional);
    if ("error" in parsed) return setProblem(parsed.error);
    const done = { onSuccess: () => onOpenChange(false) };
    if (policy) {
      update.mutate({ id: policy.id, name: name.trim(), thresholds: parsed.thresholds }, done);
      return;
    }
    const body: PolicyCreate = { name: name.trim(), thresholds: parsed.thresholds };
    if (scope === "default") body.is_default = true;
    else if (scope === "classification") body.data_classification = classification;
    else {
      if (!applicationId) return setProblem("Choose the application this policy is for.");
      body.application_id = applicationId;
    }
    create.mutate(body, done);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{policy ? `Edit ${policy.name}` : "New verdict policy"}</DialogTitle>
          <DialogDescription>
            A scan fails when any Fail number is reached, otherwise it is conditional when any
            Conditional number is reached, otherwise it passes. Counts are open findings.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-4" aria-label="Policy">
          <Field id="policy-name" label="Name">
            <Input
              id="policy-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={200}
              required
            />
          </Field>
          {policy ? (
            <p className="text-sm text-muted-foreground">Applies to: {policyScope(policy)}. The scope cannot change.</p>
          ) : (
            <>
              <Field id="policy-scope" label="Applies to">
                <Select id="policy-scope" value={scope} onChange={(e) => setScope(e.target.value as Scope)}>
                  <option value="classification">All applications of one data classification</option>
                  <option value="application">One application</option>
                  <option value="default">Everything else (the default)</option>
                </Select>
              </Field>
              {scope === "classification" ? (
                <Field id="policy-classification" label="Data classification">
                  <Select
                    id="policy-classification"
                    value={classification}
                    onChange={(e) => setClassification(e.target.value as DataClassificationName)}
                  >
                    {CLASSIFICATIONS.map((c) => (
                      <option key={c} value={c}>
                        {humanize(c)}
                      </option>
                    ))}
                  </Select>
                </Field>
              ) : null}
              {scope === "application" ? (
                <Field id="policy-application" label="Application">
                  <Select
                    id="policy-application"
                    value={applicationId}
                    onChange={(e) => setApplicationId(e.target.value)}
                  >
                    <option value="">Choose an application</option>
                    {applications.data?.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name}
                      </option>
                    ))}
                  </Select>
                </Field>
              ) : null}
            </>
          )}
          <ThresholdInputs
            idPrefix="fail"
            legend="Fail at"
            help="The scan fails when open findings of any severity reach its number. Leave a box empty to ignore that severity."
            values={fail}
            onChange={setFail}
          />
          <ThresholdInputs
            idPrefix="cond"
            legend="Conditional at"
            help="Otherwise the scan is conditional when any of these numbers is reached."
            values={conditional}
            onChange={setConditional}
          />
          {problem ? (
            <p role="alert" className="text-sm font-medium">
              {problem}
            </p>
          ) : null}
          {mutation.error ? <ErrorNotice error={mutation.error} title="The policy was not saved" /> : null}
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Saving..." : policy ? "Save changes" : "Create policy"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function PoliciesPage() {
  const policies = usePolicies();
  const builtin = useBuiltinPolicy();
  const applications = useApplicationOptions();
  const update = useUpdatePolicy();
  // `editing`: undefined = closed, null = creating, a policy = editing it.
  const [editing, setEditing] = useState<Policy | null | undefined>(undefined);
  const names = new Map((applications.data ?? []).map((a) => [a.id, a.name]));

  return (
    <>
      <PageHeader
        title="Verdict policies"
        description="How many open findings make a scan pass, conditional or fail. The most specific policy wins: one application, then its data classification, then the default."
        actions={<Button onClick={() => setEditing(null)}>New policy</Button>}
      />
      {builtin.data ? (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Built-in default</CardTitle>
            <CardDescription>Used when no policy below matches. It cannot be changed here.</CardDescription>
          </CardHeader>
          <CardContent className="text-sm">
            Fail at: {describeThresholds(builtin.data.thresholds.fail)}. Conditional at:{" "}
            {describeThresholds(builtin.data.thresholds.conditional)}.
          </CardContent>
        </Card>
      ) : null}
      {policies.isPending ? <LoadingText>Loading policies...</LoadingText> : null}
      {policies.isError ? (
        <ErrorNotice error={policies.error} title="Could not load policies" onRetry={() => void policies.refetch()} />
      ) : null}
      {update.error ? <ErrorNotice error={update.error} title="The change was not saved" className="mb-4" /> : null}
      {policies.data ? (
        policies.data.length === 0 ? (
          <EmptyState>No policies yet. Scans use the built-in default.</EmptyState>
        ) : (
          <Table aria-label="Verdict policies">
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Applies to</TableHead>
                <TableHead>Fail at</TableHead>
                <TableHead>Conditional at</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {policies.data.map((policy) => (
                <TableRow key={policy.id}>
                  <TableCell className="font-medium">{policy.name}</TableCell>
                  <TableCell>
                    {policy.application_id
                      ? `Application: ${names.get(policy.application_id) ?? "unknown"}`
                      : policyScope(policy)}
                  </TableCell>
                  <TableCell>{describeThresholds(policy.thresholds.fail)}</TableCell>
                  <TableCell>{describeThresholds(policy.thresholds.conditional)}</TableCell>
                  <TableCell>{policy.version}</TableCell>
                  <TableCell>
                    <StatusBadge
                      status={policy.active ? "active" : "disabled"}
                      label={policy.active ? "In use" : "Switched off"}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={() => setEditing(policy)}>
                        Edit<span className="sr-only"> {policy.name}</span>
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={update.isPending}
                        onClick={() => update.mutate({ id: policy.id, active: !policy.active })}
                      >
                        {policy.active ? "Switch off" : "Switch on"}
                        <span className="sr-only"> {policy.name}</span>
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )
      ) : null}
      {editing !== undefined ? (
        <PolicyDialog
          key={editing?.id ?? "new"}
          open
          onOpenChange={(open) => {
            if (!open) setEditing(undefined);
          }}
          policy={editing}
        />
      ) : null}
    </>
  );
}
