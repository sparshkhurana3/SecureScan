import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";

import {
  emptyApplicationChoice,
  useApplications,
  type Application,
  type ApplicationChoice,
} from "../api/applications";
import type { GithubRepository } from "../api/github";
import {
  emptySourceState,
  newIdempotencyKey,
  prepareSast,
  sourceToRequest,
  startPreparedScan,
  todayIso,
  toolLabel,
  useScanProfiles,
  useScans,
  validateSastRequest,
  type PreparedSast,
  type SastRequest,
  type SourceState,
} from "../api/scans";
import { CheckField, describedBy, fieldHelp, ProblemNotice, useGoto } from "../components/FormBits";
import { scanPath, ScanTable } from "../components/ScanTable";
import { ApplicationPicker, choiceApplication, SourcePicker, VersionField } from "../components/SourcePicker";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Field, PageHeader } from "../components/ui/page";
import { Select } from "../components/ui/select";
import type { Uploader } from "../components/UploadWidget";

type Pending = { prepared: PreparedSast; request: SastRequest; fingerprint: string };

/** Focus the first field with an error so that keyboard and screen reader users land on it. */
function focusFirstError() {
  window.requestAnimationFrame(() => {
    const first = document.querySelector<HTMLElement>('form [aria-invalid="true"]');
    first?.focus();
  });
}

/**
 * Start a code scan and follow it: where the code comes from, the application and version, internal or
 * vendor, the tools to run; below it the running and recent code scans.
 */
export function SastPage({ uploader }: { uploader?: Uploader } = {}) {
  const prefix = useId();
  const goto = useGoto();
  const queryClient = useQueryClient();
  const applications = useApplications();
  const profiles = useScanProfiles("sast");
  const scans = useScans({ kind: "sast", limit: 25 });

  const [source, setSource] = useState<SourceState>(emptySourceState);
  const [application, setApplication] = useState<ApplicationChoice>(emptyApplicationChoice);
  const [versionLabel, setVersionLabel] = useState("");
  const [ref, setRef] = useState("");
  const [profileName, setProfileName] = useState("");
  const [ticked, setTicked] = useState<string[] | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [copied, setCopied] = useState(false);
  const keyRef = useRef<{ fingerprint: string; key: string } | null>(null);

  const profileList = profiles.data ?? [];
  const profile =
    profileList.find((item) => item.name === profileName) ??
    profileList.find((item) => item.name === "code-standard") ??
    profileList[0];
  const profileTools = profile?.tools ?? [];
  const tools = ticked ?? profileTools;

  // A connected repository belongs to one application.
  const repoApplication: Application | null =
    source.kind === "github" && source.repo
      ? (applications.data?.find((item) => item.id === source.repo?.application_id) ?? null)
      : null;
  const effectiveApplication: ApplicationChoice =
    source.kind === "github" && source.repo ? { kind: "existing", application: repoApplication } : application;
  const applicationFacts = choiceApplication(effectiveApplication);
  const vendorApplication = applicationFacts?.type === "vendor";
  const existingApplicationId =
    effectiveApplication.kind === "existing" ? (effectiveApplication.application?.id ?? null) : null;

  const request: SastRequest = {
    source: sourceToRequest(source),
    application: effectiveApplication,
    versionLabel,
    ref,
    profile: profile?.name ?? "",
    tools,
    profileTools,
  };
  const fingerprint = JSON.stringify(request);
  const shownPending = pending && pending.fingerprint === fingerprint ? pending : null;

  useEffect(() => {
    setCopied(false);
  }, [shownPending?.prepared.deployKey?.id]);

  const onRepositoryChosen = (repo: GithubRepository) => {
    if (!versionLabel.trim()) setVersionLabel(repo.default_branch ?? "main");
  };

  const begin = async (prepared: PreparedSast, sent: SastRequest, sentFingerprint: string) => {
    const known = keyRef.current;
    const entry = known && known.fingerprint === sentFingerprint ? known : { fingerprint: sentFingerprint, key: newIdempotencyKey() };
    keyRef.current = entry;
    const detail = await startPreparedScan(prepared, sent, entry.key);
    void queryClient.invalidateQueries({ queryKey: ["scans"] });
    void queryClient.invalidateQueries({ queryKey: ["applications"] });
    setSource((current) => ({ ...current, token: "" }));
    goto(scanPath(detail.id));
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    const found = validateSastRequest(request, todayIso());
    setErrors(found);
    setFailure(null);
    if (Object.keys(found).length > 0) {
      focusFirstError();
      return;
    }
    setBusy(true);
    try {
      const reuse = pending && pending.fingerprint === fingerprint ? pending : null;
      // Creating a new application turns the form's choice into an existing one; the request that is
      // remembered (and the idempotency key) must be the one the form will show next.
      let sentRequest = request;
      const prepared =
        reuse?.prepared ??
        (await prepareSast(request, {
          onApplication: (created) => {
            sentRequest = { ...request, application: { kind: "existing", application: created } };
            if (application.kind === "new") setApplication({ kind: "existing", application: created });
            void queryClient.invalidateQueries({ queryKey: ["applications"] });
          },
        }));
      const sentFingerprint = reuse ? fingerprint : JSON.stringify(sentRequest);
      if (!reuse) setPending({ prepared, request: sentRequest, fingerprint: sentFingerprint });
      if (prepared.deployKey && !reuse) return; // the vendor has to add the key before the scan can read the repository
      await begin(prepared, sentRequest, sentFingerprint);
    } catch (caught) {
      setFailure(caught);
    } finally {
      setBusy(false);
    }
  };

  const startWithKey = async () => {
    if (!shownPending || busy) return;
    setBusy(true);
    setFailure(null);
    try {
      await begin(shownPending.prepared, shownPending.request, shownPending.fingerprint);
    } catch (caught) {
      setFailure(caught);
    } finally {
      setBusy(false);
    }
  };

  const copyKey = async () => {
    const text = shownPending?.prepared.deployKey?.public_key;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      setCopied(false); // the key stays visible and selectable
    }
  };

  const toggleTool = (tool: string, checked: boolean) => {
    const next = checked ? [...new Set([...tools, tool])] : tools.filter((item) => item !== tool);
    setTicked(profileTools.filter((item) => next.includes(item)));
  };

  const appErrors: Record<string, string> = {};
  for (const [key, message] of Object.entries(errors)) {
    if (key.startsWith("application.")) appErrors[key.slice("application.".length)] = message;
  }
  const deployKey = shownPending?.prepared.deployKey ?? null;

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title="SAST scan"
        description="Scan source code or a container image. Choose where the code comes from, name the application and version, and start. Results go to DefectDojo and a report is made when the scan finishes."
      />

      <Card>
        <CardHeader>
          <CardTitle>Start a code scan</CardTitle>
          <CardDescription>Every field with an error is marked and described next to it.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(event) => void submit(event)}
            noValidate
            aria-label="Start a code scan"
            className="flex max-w-3xl flex-col gap-6"
          >
            <SourcePicker
              idPrefix={prefix}
              value={source}
              onChange={setSource}
              errors={errors}
              vendorApplication={vendorApplication}
              onRepositoryChosen={onRepositoryChosen}
              uploader={uploader}
              disabled={busy}
            />

            <ApplicationPicker
              idPrefix={prefix}
              value={application}
              onChange={setApplication}
              errors={appErrors}
              locked={repoApplication}
              disabled={busy}
            />

            <VersionField
              id={`${prefix}-version`}
              applicationId={existingApplicationId}
              value={versionLabel}
              onChange={setVersionLabel}
              error={errors.versionLabel}
              help="Names this scan's version of the application, for example 1.4.2, main or a release name. Scans of the same label are compared in history."
              disabled={busy}
            />

            {source.kind === "github" || source.kind === "url" ? (
              <Field
                id={`${prefix}-ref`}
                label="Branch, tag or commit (optional)"
                help={fieldHelp(errors.ref, "Leave empty to scan the default branch.")}
              >
                <Input
                  id={`${prefix}-ref`}
                  value={ref}
                  maxLength={255}
                  disabled={busy}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) => setRef(event.target.value)}
                  {...describedBy(`${prefix}-ref`, errors.ref, true)}
                />
              </Field>
            ) : null}

            {profileList.length > 1 ? (
              <Field id={`${prefix}-profile`} label="Scan profile">
                <Select
                  id={`${prefix}-profile`}
                  value={profile?.name ?? ""}
                  disabled={busy}
                  onChange={(event) => {
                    setProfileName(event.target.value);
                    setTicked(null);
                  }}
                >
                  {profileList.map((item) => (
                    <option key={item.name} value={item.name}>
                      {item.name}
                      {item.description ? ` - ${item.description}` : ""}
                    </option>
                  ))}
                </Select>
              </Field>
            ) : null}

            <fieldset className="flex flex-col gap-2 border-0 p-0" aria-describedby={`${prefix}-tools-help`}>
              <legend className="mb-1 p-0 text-sm font-medium">Tools</legend>
              {profiles.isPending ? (
                <p className="m-0 text-sm text-muted-foreground">Loading the tools of the profile...</p>
              ) : profileTools.length === 0 ? (
                <p className="m-0 text-sm font-medium" role="alert">
                  No scan profile is available. An Admin has to add one in Settings.
                </p>
              ) : (
                profileTools.map((tool) => (
                  <CheckField
                    key={tool}
                    id={`${prefix}-tool-${tool}`}
                    label={toolLabel(tool)}
                    checked={tools.includes(tool)}
                    onCheckedChange={(checked) => toggleTool(tool, checked)}
                    disabled={busy}
                  />
                ))
              )}
              <p id={`${prefix}-tools-help`} className="m-0 text-xs text-muted-foreground">
                {errors.tools ? (
                  <span role="alert" className="font-semibold text-foreground">
                    {errors.tools}
                  </span>
                ) : (
                  "Every tool of the profile is ticked. Untick a tool to leave it out of this scan."
                )}
              </p>
            </fieldset>

            <ProblemNotice error={failure} title="The scan could not be started" />

            {deployKey && shownPending ? (
              <section
                aria-label="Deploy key for the vendor"
                className="flex flex-col gap-3 rounded-md border border-foreground p-4"
              >
                <h3 className="m-0 text-base font-semibold">Send this deploy key to the vendor</h3>
                <p className="m-0 text-sm">{deployKey.instructions}</p>
                <label htmlFor={`${prefix}-pubkey`} className="text-sm font-medium">
                  Public key (fingerprint {deployKey.fingerprint ?? "unknown"})
                </label>
                <textarea
                  id={`${prefix}-pubkey`}
                  readOnly
                  rows={3}
                  value={deployKey.public_key ?? ""}
                  onFocus={(event) => event.currentTarget.select()}
                  className="w-full rounded-md border border-input bg-muted p-2 font-mono text-xs"
                />
                <div className="flex flex-wrap items-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => void copyKey()}>
                    Copy the key
                  </Button>
                  <span role="status" className="text-xs text-muted-foreground">
                    {copied ? "Copied." : ""}
                  </span>
                </div>
                <p className="m-0 text-xs text-muted-foreground">
                  Start the scan once the vendor has added the key. Starting it earlier fails because the repository
                  cannot be read.
                </p>
                <div className="flex flex-wrap gap-2">
                  <Button onClick={() => void startWithKey()} disabled={busy}>
                    {busy ? "Starting..." : "The key is added, start the scan"}
                  </Button>
                  <Button variant="outline" onClick={() => setPending(null)} disabled={busy}>
                    Not yet
                  </Button>
                </div>
              </section>
            ) : (
              <div className="flex flex-wrap items-center gap-3">
                <Button type="submit" disabled={busy || profileTools.length === 0}>
                  {busy ? "Starting..." : "Start scan"}
                </Button>
                {busy ? (
                  <span role="status" className="text-sm text-muted-foreground">
                    Preparing the scan...
                  </span>
                ) : null}
              </div>
            )}
          </form>
        </CardContent>
      </Card>

      <section aria-labelledby={`${prefix}-recent`} className="flex flex-col gap-3">
        <h2 id={`${prefix}-recent`} className="m-0 text-lg font-semibold">
          Running and recent code scans
        </h2>
        <ScanTable
          scans={scans.data}
          loading={scans.isPending}
          error={scans.error}
          caption="Running and recent code scans"
          emptyText="No code scans yet. Start one above."
        />
      </section>
    </div>
  );
}
