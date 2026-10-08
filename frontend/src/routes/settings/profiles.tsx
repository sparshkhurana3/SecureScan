import { type FormEvent, useState } from "react";

import {
  type ScanProfile,
  useCreateProfileVersion,
  useProfileDetail,
  useProfiles,
  useSetProfileActive,
} from "../../api/admin";
import { StatusBadge } from "../../components/StatusBadge";
import { Button } from "../../components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../../components/ui/dialog";
import { EmptyState, ErrorNotice, Field, LoadingText, PageHeader } from "../../components/ui/page";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import { Textarea } from "../../components/ui/textarea";
import { formatDateTime } from "../../lib/format";

function YamlDialog({ profile, onClose }: { profile: ScanProfile | null; onClose: () => void }) {
  const detail = useProfileDetail(profile?.id ?? null);
  return (
    <Dialog open={profile !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>
            {profile?.name} version {profile?.version}
          </DialogTitle>
          <DialogDescription>
            A stored version never changes. To change a profile, add a new version.
          </DialogDescription>
        </DialogHeader>
        {detail.isPending ? <LoadingText /> : null}
        {detail.isError ? <ErrorNotice error={detail.error} /> : null}
        {detail.data ? (
          <pre
            tabIndex={0}
            aria-label="Profile YAML"
            className="max-h-[55vh] overflow-auto rounded-md border border-border bg-muted p-3 font-mono text-xs"
          >
            {detail.data.body_yaml}
          </pre>
        ) : null}
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Close</Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function NewVersionForm({ initialYaml }: { initialYaml: string }) {
  const create = useCreateProfileVersion();
  const [yaml, setYaml] = useState(initialYaml);
  const [done, setDone] = useState<string | null>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setDone(null);
    create.mutate(yaml, {
      onSuccess: (profile) => setDone(`Saved ${profile.name} as version ${profile.version}.`),
    });
  };

  return (
    <form onSubmit={submit} aria-label="Add a profile version" className="mt-8 flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Add a profile or a new version</h2>
      <p className="text-sm text-muted-foreground">
        Paste the profile as YAML. If a profile with that name exists, this becomes its next version
        and new scans use it. The YAML is checked against the scanner catalogue before it is saved.
      </p>
      <Field id="profile-yaml" label="Profile YAML">
        <Textarea
          id="profile-yaml"
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
          rows={12}
          spellCheck={false}
          className="font-mono text-xs"
          required
        />
      </Field>
      {create.error ? <ErrorNotice error={create.error} title="The profile was not saved" /> : null}
      {done ? (
        <p role="status" className="text-sm font-medium">
          {done}
        </p>
      ) : null}
      <div>
        <Button type="submit" disabled={create.isPending || yaml.trim().length < 10}>
          {create.isPending ? "Saving..." : "Save profile version"}
        </Button>
      </div>
    </form>
  );
}

const TEMPLATE_YAML = `profile: my-profile
kind: sast
description: What this profile is for
jobs:
  - tool: semgrep
`;

export function ProfilesPage() {
  const profiles = useProfiles(true);
  const setActive = useSetProfileActive();
  const [viewing, setViewing] = useState<ScanProfile | null>(null);

  return (
    <>
      <PageHeader
        title="Scan profiles"
        description="Which tools a scan runs and how. Profiles are versioned: each save adds a version and the newest active version is used."
      />
      {profiles.isPending ? <LoadingText>Loading profiles...</LoadingText> : null}
      {profiles.isError ? (
        <ErrorNotice error={profiles.error} title="Could not load profiles" onRetry={() => void profiles.refetch()} />
      ) : null}
      {setActive.error ? <ErrorNotice error={setActive.error} title="The change was not saved" className="mb-4" /> : null}
      {profiles.data ? (
        profiles.data.length === 0 ? (
          <EmptyState>No profiles yet.</EmptyState>
        ) : (
          <Table aria-label="Scan profiles">
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Tools</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Added</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {profiles.data.map((profile) => (
                <TableRow key={profile.id}>
                  <TableCell className="font-medium">
                    {profile.name}
                    {profile.description ? (
                      <span className="block max-w-sm text-xs font-normal text-muted-foreground">
                        {profile.description}
                      </span>
                    ) : null}
                  </TableCell>
                  <TableCell>{profile.version}</TableCell>
                  <TableCell>
                    {profile.kind.toUpperCase()}
                    {profile.mode ? (
                      <span className="block text-xs text-muted-foreground">{profile.mode}</span>
                    ) : null}
                  </TableCell>
                  <TableCell>{profile.tools.join(", ") || "-"}</TableCell>
                  <TableCell>
                    <StatusBadge
                      status={profile.active ? "active" : "disabled"}
                      label={profile.active ? "In use" : "Switched off"}
                    />
                  </TableCell>
                  <TableCell className="whitespace-nowrap">{formatDateTime(profile.created_at)}</TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={() => setViewing(profile)}>
                        View YAML<span className="sr-only"> of {profile.name} version {profile.version}</span>
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={setActive.isPending}
                        onClick={() => setActive.mutate({ id: profile.id, active: !profile.active })}
                      >
                        {profile.active ? "Switch off" : "Switch on"}
                        <span className="sr-only">
                          {" "}
                          {profile.name} version {profile.version}
                        </span>
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )
      ) : null}
      <NewVersionForm initialYaml={TEMPLATE_YAML} />
      <YamlDialog profile={viewing} onClose={() => setViewing(null)} />
    </>
  );
}
