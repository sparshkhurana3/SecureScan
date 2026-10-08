import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";

import { isVendorSaas, useApplications, type Application } from "../api/applications";
import { useMeQuery } from "../api/me";
import {
  newIdempotencyKey,
  profileForMode,
  startDastScan,
  useScanProfiles,
  useScans,
  useVersionMap,
} from "../api/scans";
import {
  archiveTarget,
  authorizationSummary,
  MODE_HINTS,
  MODE_LABELS,
  modesForEnvironment,
  useUrlTargets,
  type DastMode,
  type Target,
} from "../api/targets";
import { ProblemNotice, RadioField, FieldGroup, useGoto } from "../components/FormBits";
import { scanPath, ScanTable } from "../components/ScanTable";
import { TargetForm } from "../components/TargetForm";
import type { Uploader } from "../components/UploadWidget";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { EmptyState, ErrorNotice, Field, LoadingText, PageHeader } from "../components/ui/page";
import { Select } from "../components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";

const ENVIRONMENT_LABELS = { production: "Production", uat: "UAT" } as const;

/** A target's environment tag as an outline badge (a tag, not a status: no colour). */
function EnvironmentTag({ environment }: { environment: Target["environment"] }) {
  if (!environment) return <Badge tone="outline">Not tagged</Badge>;
  return <Badge tone="outline">{ENVIRONMENT_LABELS[environment]}</Badge>;
}

/**
 * Register web addresses, tag them production or UAT, and scan them. The scan modes offered follow the tag:
 * production gets the passive baseline only, UAT gets baseline, full, API and Nuclei. The API enforces the
 * same rule; if it refuses a request its own message is shown.
 */
export function DastPage({ uploader }: { uploader?: Uploader } = {}) {
  const prefix = useId();
  const goto = useGoto();
  const queryClient = useQueryClient();
  const me = useMeQuery();
  const isAdmin = me.data?.role === "Admin";
  const targets = useUrlTargets();
  const applications = useApplications();
  const profiles = useScanProfiles("dast");
  const scans = useScans({ kind: "dast", limit: 25 });

  const targetList = useMemo(() => (targets.data ?? []).filter((target) => target.archived_at === null), [targets.data]);
  const versions = useVersionMap(targetList.map((target) => target.version_id));
  const appById = useMemo(() => {
    const map = new Map<string, Application>();
    for (const application of applications.data ?? []) map.set(application.id, application);
    return map;
  }, [applications.data]);
  const applicationOf = (target: Target): Application | null => {
    const version = versions.get(target.version_id);
    return version ? (appById.get(version.application_id) ?? null) : null;
  };

  // --- registering and editing
  const [editing, setEditing] = useState<"new" | Target | null>(null);
  const formRef = useRef<HTMLDivElement>(null);
  const [archiveAsk, setArchiveAsk] = useState<string | null>(null);
  const [archiveError, setArchiveError] = useState<unknown>(null);

  useEffect(() => {
    if (editing) formRef.current?.scrollIntoView?.({ block: "nearest" });
  }, [editing]);

  const confirmArchive = async (target: Target) => {
    setArchiveError(null);
    try {
      await archiveTarget(target.id);
      setArchiveAsk(null);
      void queryClient.invalidateQueries({ queryKey: ["targets"] });
    } catch (caught) {
      setArchiveError(caught);
    }
  };

  // --- starting a scan
  const [targetId, setTargetId] = useState("");
  const [mode, setMode] = useState<DastMode | "">("");
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const keyRef = useRef<{ fingerprint: string; key: string } | null>(null);

  const selected = targetList.find((target) => target.id === targetId) ?? null;
  const allowedModes = modesForEnvironment(selected?.environment);
  const profileList = profiles.data ?? [];
  const selectedApplication = selected ? applicationOf(selected) : null;
  const profileOfMode = (value: DastMode) => profileForMode(profileList, value);
  const chosenProfile = mode ? profileOfMode(mode) : undefined;
  const modeAllowed = mode !== "" && allowedModes.includes(mode);
  const noProfiles = !profiles.isPending && profileList.length === 0;

  const chooseTarget = (id: string) => {
    setTargetId(id);
    setFailure(null);
    const next = targetList.find((target) => target.id === id);
    const allowed = modesForEnvironment(next?.environment);
    if (mode !== "" && !allowed.includes(mode)) setMode("");
  };

  const start = async (event: FormEvent) => {
    event.preventDefault();
    if (busy || !selected || !mode || !chosenProfile) return;
    setBusy(true);
    setFailure(null);
    try {
      const fingerprint = `${selected.id}:${chosenProfile.name}:${String(chosenProfile.version)}`;
      const known = keyRef.current;
      const entry = known && known.fingerprint === fingerprint ? known : { fingerprint, key: newIdempotencyKey() };
      keyRef.current = entry;
      const detail = await startDastScan(selected, chosenProfile.name, entry.key);
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
      goto(scanPath(detail.id));
    } catch (caught) {
      setFailure(caught); // the backend's refusal is shown as it is
    } finally {
      setBusy(false);
    }
  };

  const editingTarget = editing && editing !== "new" ? editing : null;
  const startDisabled = busy || !selected || !modeAllowed || !chosenProfile;

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title="DAST scan"
        description="Test running web applications. Register the address, tag it production or UAT, then scan it. Production addresses get the passive baseline scan only."
        actions={
          <Button onClick={() => setEditing("new")} disabled={editing === "new"}>
            Register a web address
          </Button>
        }
      />

      {editing ? (
        <div ref={formRef}>
          <Card>
            <CardHeader>
              <CardTitle>{editingTarget ? "Edit the web address" : "Register a web address"}</CardTitle>
              <CardDescription>
                {editingTarget
                  ? editingTarget.locator
                  : "Add an address to scan. It belongs to an application and a version."}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="max-w-3xl">
                <TargetForm
                  key={editingTarget?.id ?? "new"}
                  mode={editingTarget ? "edit" : "create"}
                  target={editingTarget ?? undefined}
                  application={editingTarget ? applicationOf(editingTarget) : null}
                  versionLabel={editingTarget ? versions.get(editingTarget.version_id)?.label : undefined}
                  onDone={() => setEditing(null)}
                  onCancel={() => setEditing(null)}
                  uploader={uploader}
                />
              </div>
            </CardContent>
          </Card>
        </div>
      ) : null}

      <section aria-labelledby={`${prefix}-targets`} className="flex flex-col gap-3">
        <h2 id={`${prefix}-targets`} className="m-0 text-lg font-semibold">
          Registered web addresses
        </h2>
        {archiveError ? <ProblemNotice error={archiveError} title="The address could not be archived" /> : null}
        {targets.isPending ? (
          <LoadingText>Loading the addresses...</LoadingText>
        ) : targets.isError ? (
          <ErrorNotice error={targets.error} title="The addresses could not be loaded" onRetry={() => void targets.refetch()} />
        ) : targetList.length === 0 ? (
          <EmptyState>No web addresses are registered yet. Use "Register a web address" to add one.</EmptyState>
        ) : (
          <Table aria-label="Registered web addresses">
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>Application</TableHead>
                <TableHead>Environment</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Login</TableHead>
                <TableHead>Vendor authorization</TableHead>
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {targetList.map((target) => {
                const application = applicationOf(target);
                const version = versions.get(target.version_id);
                return (
                  <TableRow key={target.id} data-target-id={target.id}>
                    <TableCell className="max-w-xs break-words">
                      <span className="font-medium">{target.locator}</span>
                      {target.name ? <span className="block text-xs text-muted-foreground">{target.name}</span> : null}
                    </TableCell>
                    <TableCell>
                      {application?.name ?? "-"}
                      {version ? <span className="block text-xs text-muted-foreground">Version {version.label}</span> : null}
                    </TableCell>
                    <TableCell>
                      <EnvironmentTag environment={target.environment} />
                    </TableCell>
                    <TableCell className="text-xs">
                      {target.scope_includes.length} in scope, {target.scope_excludes.length} excluded
                      {target.rate_limit_rps ? `, ${String(target.rate_limit_rps)} req/s` : ""}
                      {target.dast_cron ? `, schedule ${target.dast_cron}` : ""}
                    </TableCell>
                    <TableCell>{target.login_profile_id ? "Yes" : "No"}</TableCell>
                    <TableCell>{authorizationSummary(target, application)}</TableCell>
                    <TableCell className="whitespace-nowrap">
                      <div className="flex flex-wrap gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => chooseTarget(target.id)}
                          aria-label={`Scan ${target.locator}`}
                        >
                          Scan
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setEditing(target)}
                          aria-label={`Edit ${target.locator}`}
                        >
                          Edit
                        </Button>
                        {isAdmin ? (
                          archiveAsk === target.id ? (
                            <>
                              <Button
                                size="sm"
                                onClick={() => void confirmArchive(target)}
                                aria-label={`Confirm archiving ${target.locator}`}
                              >
                                Confirm archive
                              </Button>
                              <Button size="sm" variant="ghost" onClick={() => setArchiveAsk(null)}>
                                Keep
                              </Button>
                            </>
                          ) : (
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => setArchiveAsk(target.id)}
                              aria-label={`Archive ${target.locator}`}
                            >
                              Archive
                            </Button>
                          )
                        ) : null}
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </section>

      <Card>
        <CardHeader>
          <CardTitle>Start a web scan</CardTitle>
          <CardDescription>
            Pick a registered address and a scan mode. The modes follow the environment tag of the address.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={(event) => void start(event)} aria-label="Start a web scan" className="flex max-w-3xl flex-col gap-5">
            <Field id={`${prefix}-target`} label="Web address">
              <Select
                id={`${prefix}-target`}
                value={targetId}
                disabled={busy}
                onChange={(event) => chooseTarget(event.target.value)}
              >
                <option value="">Choose a registered address...</option>
                {targetList.map((target) => {
                  const application = applicationOf(target);
                  const tag = target.environment ? ENVIRONMENT_LABELS[target.environment] : "not tagged";
                  return (
                    <option key={target.id} value={target.id}>
                      {application ? `${application.name} - ` : ""}
                      {target.locator} ({tag})
                    </option>
                  );
                })}
              </Select>
            </Field>

            {selected ? (
              <div className="flex flex-col gap-1 text-sm" data-testid="target-summary">
                <p className="m-0">
                  Environment: <EnvironmentTag environment={selected.environment} />
                  {selected.login_profile_id ? " Scans log in with the stored login profile." : ""}
                </p>
                {isVendorSaas(selectedApplication) ? (
                  <p className="m-0">
                    Vendor authorization: {authorizationSummary(selected, selectedApplication)}.
                    {selected.vendor_authorization_artifact_id
                      ? ""
                      : " Add it with Edit; without it the scan is refused."}
                  </p>
                ) : null}
              </div>
            ) : null}

            <FieldGroup legend="Scan mode">
              {!selected ? (
                <p className="m-0 text-sm text-muted-foreground">Choose an address to see the modes it allows.</p>
              ) : allowedModes.length === 0 ? (
                <p className="m-0 text-sm font-medium" role="alert">
                  This address has no environment tag. Edit it and tag it production or UAT first.
                </p>
              ) : (
                allowedModes.map((value) => {
                  const profile = profileOfMode(value);
                  return (
                    <RadioField
                      key={value}
                      name={`${prefix}-mode`}
                      value={value}
                      checked={mode === value}
                      onSelect={() => setMode(value)}
                      label={MODE_LABELS[value]}
                      help={profile ? MODE_HINTS[value] : `${MODE_HINTS[value]} Its scan profile is not installed yet.`}
                      disabled={busy || !profile}
                    />
                  );
                })
              )}
              {selected?.environment === "production" ? (
                <p className="m-0 text-xs text-muted-foreground">
                  Production addresses accept the unauthenticated baseline scan only. Tag the address UAT to use the other modes.
                </p>
              ) : null}
            </FieldGroup>

            {noProfiles ? (
              <p className="m-0 text-sm font-medium" role="alert">
                No web scan profiles are installed yet, so scans cannot be started.
              </p>
            ) : null}

            <ProblemNotice error={failure} title="The scan was refused" />

            <div className="flex flex-wrap items-center gap-3">
              <Button type="submit" disabled={startDisabled}>
                {busy ? "Starting..." : "Start scan"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <section aria-labelledby={`${prefix}-recent`} className="flex flex-col gap-3">
        <h2 id={`${prefix}-recent`} className="m-0 text-lg font-semibold">
          Running and recent web scans
        </h2>
        <ScanTable
          scans={scans.data}
          loading={scans.isPending}
          error={scans.error}
          caption="Running and recent web scans"
          emptyText="No web scans yet."
          showMode
        />
      </section>
    </div>
  );
}
