import { type FormEvent, useState } from "react";

import {
  type GitHubConnection,
  type GitHubConnectionInput,
  isTestRunning,
  type KeySlot,
  useGitHubConnection,
  useSaveGitHubConnection,
  useSyncGitHub,
  useTestGitHubConnection,
} from "../../api/admin";
import { StatusBadge } from "../../components/StatusBadge";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Checkbox } from "../../components/ui/checkbox";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import { ErrorNotice, Field, LoadingText, PageHeader } from "../../components/ui/page";
import { Select } from "../../components/ui/select";
import { Textarea } from "../../components/ui/textarea";
import { formatDateTime, formatRelative } from "../../lib/format";

const DEFAULTS = {
  name: "Corporate GitHub",
  app_id: "",
  client_id: "",
  installation_id: "",
  api_base_url: "https://api.github.com",
  git_host: "github.com",
  api_version: "2026-03-10",
  active_key: 1 as 1 | 2,
  enabled: true,
};

function keyNote(slot: KeySlot): string {
  if (!slot.present) return "No key stored.";
  const source = slot.source === "secret_file" ? "from the server's secret file" : "uploaded";
  const finger = slot.fingerprint ? ` Fingerprint ${slot.fingerprint}.` : "";
  return `A key is stored (${source}).${finger} Paste a new one to replace it.`;
}

function ConnectionForm({ connection }: { connection: GitHubConnection | null }) {
  const save = useSaveGitHubConnection();
  const [form, setForm] = useState({
    name: connection?.name ?? DEFAULTS.name,
    app_id: connection?.app_id ?? DEFAULTS.app_id,
    client_id: connection?.client_id ?? DEFAULTS.client_id,
    installation_id: connection?.installation_id ?? DEFAULTS.installation_id,
    api_base_url: connection?.api_base_url ?? DEFAULTS.api_base_url,
    git_host: connection?.git_host ?? DEFAULTS.git_host,
    api_version: connection?.api_version ?? DEFAULTS.api_version,
    active_key: connection?.active_key ?? DEFAULTS.active_key,
    enabled: connection?.enabled ?? DEFAULTS.enabled,
  });
  const [key1, setKey1] = useState("");
  const [key2, setKey2] = useState("");
  const [clearKey2, setClearKey2] = useState(false);
  const [saved, setSaved] = useState(false);
  const set = <K extends keyof typeof form>(key: K, value: (typeof form)[K]) => {
    setSaved(false);
    setForm((current) => ({ ...current, [key]: value }));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setSaved(false);
    const body: GitHubConnectionInput = {
      ...form,
      name: form.name.trim(),
      app_id: form.app_id.trim(),
      client_id: form.client_id.trim(),
      installation_id: form.installation_id.trim(),
      api_base_url: form.api_base_url.trim(),
      git_host: form.git_host.trim(),
    };
    if (key1.trim()) body.private_key_1 = key1;
    if (key2.trim()) body.private_key_2 = key2;
    if (clearKey2 && !key2.trim()) body.clear_key_2 = true;
    save.mutate(body, {
      onSuccess: () => {
        setSaved(true);
        setKey1(""); // a key is never kept in the page after it is sent
        setKey2("");
        setClearKey2(false);
      },
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Connection</CardTitle>
        <CardDescription>
          The corporate GitHub App SecureScan reads repositories with. It needs read access to
          contents and metadata only. Private keys are encrypted when stored and are never shown
          again.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} aria-label="GitHub connection" className="flex flex-col gap-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field id="gh-name" label="Name">
              <Input id="gh-name" value={form.name} onChange={(e) => set("name", e.target.value)} required />
            </Field>
            <Field id="gh-app-id" label="App ID">
              <Input id="gh-app-id" value={form.app_id} onChange={(e) => set("app_id", e.target.value)} required />
            </Field>
            <Field id="gh-client-id" label="Client ID" help="Shown on the GitHub App's settings page.">
              <Input
                id="gh-client-id"
                value={form.client_id}
                onChange={(e) => set("client_id", e.target.value)}
                required
              />
            </Field>
            <Field id="gh-installation" label="Installation ID" help="The number at the end of the installation's address.">
              <Input
                id="gh-installation"
                inputMode="numeric"
                value={form.installation_id}
                onChange={(e) => set("installation_id", e.target.value)}
                required
              />
            </Field>
            <Field id="gh-api-url" label="API address">
              <Input
                id="gh-api-url"
                type="url"
                value={form.api_base_url}
                onChange={(e) => set("api_base_url", e.target.value)}
                required
              />
            </Field>
            <Field id="gh-git-host" label="Git host">
              <Input
                id="gh-git-host"
                value={form.git_host}
                onChange={(e) => set("git_host", e.target.value)}
                required
              />
            </Field>
            <Field id="gh-api-version" label="API version header" help="Format YYYY-MM-DD.">
              <Input
                id="gh-api-version"
                value={form.api_version}
                onChange={(e) => set("api_version", e.target.value)}
                pattern="\d{4}-\d{2}-\d{2}"
                required
              />
            </Field>
            <Field id="gh-active-key" label="Key in use" help="Add the second key before you switch, then remove the old one in GitHub.">
              <Select
                id="gh-active-key"
                value={String(form.active_key)}
                onChange={(e) => set("active_key", e.target.value === "2" ? 2 : 1)}
              >
                <option value="1">Key 1</option>
                <option value="2">Key 2</option>
              </Select>
            </Field>
          </div>
          <Field
            id="gh-key-1"
            label="Private key 1 (.pem)"
            help={connection ? keyNote(connection.key_1) : "Paste the whole file, from -----BEGIN to -----END."}
          >
            <Textarea
              id="gh-key-1"
              value={key1}
              onChange={(e) => setKey1(e.target.value)}
              rows={4}
              spellCheck={false}
              autoComplete="off"
              className="font-mono text-xs"
              placeholder={connection?.key_1.present ? "Leave empty to keep the stored key" : "-----BEGIN RSA PRIVATE KEY-----"}
            />
          </Field>
          <Field
            id="gh-key-2"
            label="Private key 2 (optional, for key rotation)"
            help={connection ? keyNote(connection.key_2) : "Optional."}
          >
            <Textarea
              id="gh-key-2"
              value={key2}
              onChange={(e) => setKey2(e.target.value)}
              rows={4}
              spellCheck={false}
              autoComplete="off"
              className="font-mono text-xs"
              placeholder={connection?.key_2.present ? "Leave empty to keep the stored key" : ""}
            />
          </Field>
          {connection?.key_2.present ? (
            <div className="flex items-center gap-2">
              <Checkbox id="gh-clear-key-2" checked={clearKey2} onCheckedChange={(c) => setClearKey2(c === true)} />
              <Label htmlFor="gh-clear-key-2" className="font-normal">
                Remove key 2
              </Label>
            </div>
          ) : null}
          <div className="flex items-center gap-2">
            <Checkbox id="gh-enabled" checked={form.enabled} onCheckedChange={(c) => set("enabled", c === true)} />
            <Label htmlFor="gh-enabled" className="font-normal">
              Connection switched on (discovery and change polling run only when it is on)
            </Label>
          </div>
          {save.error ? <ErrorNotice error={save.error} title="The connection was not saved" /> : null}
          {saved ? (
            <p role="status" className="text-sm font-medium">
              Saved. Run the test below to check it.
            </p>
          ) : null}
          <div>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving..." : "Save connection"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function TestResult({ connection }: { connection: GitHubConnection }) {
  if (connection.last_test_at === null && connection.last_test_ok === null) {
    return (
      <p className="text-sm text-muted-foreground">
        {connection.last_test_message ?? "The connection has not been tested yet."}
      </p>
    );
  }
  const lines = (connection.last_test_message ?? "").split("\n").filter(Boolean);
  return (
    <div className="text-sm">
      <p className="flex flex-wrap items-center gap-2">
        <StatusBadge
          status={connection.last_test_ok ? "ok" : "failed"}
          label={connection.last_test_ok ? "Test passed" : "Test failed"}
        />
        <span className="text-muted-foreground">{formatDateTime(connection.last_test_at)}</span>
      </p>
      {lines.length > 0 ? (
        <ul className="mt-2 list-disc pl-5">
          {lines.map((line, index) => (
            <li key={index}>{line}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function StatusCard({ connection }: { connection: GitHubConnection }) {
  const test = useTestGitHubConnection();
  const sync = useSyncGitHub();
  const running = isTestRunning(connection);

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Test and discovery</CardTitle>
        <CardDescription>
          The test gets a token, lists the repositories and checks that git can reach one. It runs in
          the worker and can take up to a minute the first time.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-wrap gap-2">
          <Button
            onClick={() => test.mutate()}
            disabled={test.isPending || running}
          >
            {test.isPending || running ? "Testing..." : "Test connection"}
          </Button>
          <Button variant="outline" onClick={() => sync.mutate()} disabled={sync.isPending}>
            Find repositories now
          </Button>
        </div>
        {test.error ? <ErrorNotice error={test.error} title="The test could not be started" /> : null}
        {sync.error ? <ErrorNotice error={sync.error} title="Discovery could not be started" /> : null}
        {sync.data ? (
          <p role="status" className="text-sm font-medium">
            {sync.data.detail}
          </p>
        ) : null}
        <div aria-live="polite">
          {running ? <p className="text-sm">The test is running...</p> : <TestResult connection={connection} />}
        </div>
        <dl className="m-0 grid gap-3 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Organisation</dt>
            <dd className="m-0">{connection.org_login ?? "-"}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Last discovery</dt>
            <dd className="m-0">
              {formatDateTime(connection.last_sync_at)} ({formatRelative(connection.last_sync_at)})
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Last change poll</dt>
            <dd className="m-0">
              {formatDateTime(connection.last_poll_at)}
              {connection.last_poll_ok === false ? " (failed)" : ""}
              {connection.last_poll_message ? (
                <span className="block text-xs text-muted-foreground">{connection.last_poll_message}</span>
              ) : null}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">GitHub requests left</dt>
            <dd className="m-0">
              {connection.rate_limit_remaining ?? "-"}
              {connection.rate_limit_reset_at ? ` (resets ${formatRelative(connection.rate_limit_reset_at)})` : ""}
            </dd>
          </div>
        </dl>
      </CardContent>
    </Card>
  );
}

export function GitHubPage() {
  const query = useGitHubConnection();
  const connection = query.data?.connection ?? null;

  return (
    <>
      <PageHeader
        title="GitHub connection"
        description="Connect the corporate GitHub App so SecureScan can find repositories, watch for changes and scan them."
      />
      {query.isPending ? <LoadingText>Loading the connection...</LoadingText> : null}
      {query.isError ? (
        <ErrorNotice error={query.error} title="Could not load the connection" onRetry={() => void query.refetch()} />
      ) : null}
      {query.data ? (
        <>
          <ConnectionForm key={connection?.id ?? "new"} connection={connection} />
          {connection ? <StatusCard connection={connection} /> : null}
        </>
      ) : null}
    </>
  );
}
