import { type FormEvent, useRef, useState } from "react";

import {
  defaultTemplateDownloadUrl,
  type ReportKindName,
  type ReportTemplate,
  templateDownloadUrl,
  usePreviewTemplate,
  useSetDefaultTemplate,
  useSetTemplateActive,
  useTemplates,
  useUploadTemplate,
} from "../../api/templates";
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
import { formatDateTime } from "../../lib/format";

function PreviewDialog({
  template,
  onClose,
}: {
  template: ReportTemplate | null;
  onClose: () => void;
}) {
  const [kind, setKind] = useState<ReportKindName>("application");
  const preview = usePreviewTemplate();
  const run = (id: string, nextKind: ReportKindName) => preview.mutate({ id, kind: nextKind });

  return (
    <Dialog
      open={template !== null}
      onOpenChange={(open) => {
        if (!open) {
          preview.reset();
          onClose();
        }
      }}
    >
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>Preview of {template?.name}</DialogTitle>
          <DialogDescription>
            The template is rendered with sample data in a sandbox. Nothing is saved.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-wrap items-end gap-3">
          <Field id="preview-kind" label="Report kind">
            <Select
              id="preview-kind"
              value={kind}
              onChange={(e) => setKind(e.target.value as ReportKindName)}
            >
              <option value="application">Application report</option>
              <option value="vendor">Vendor report</option>
            </Select>
          </Field>
          <Button onClick={() => template && run(template.id, kind)} disabled={preview.isPending}>
            {preview.isPending ? "Rendering..." : preview.data ? "Render again" : "Render preview"}
          </Button>
        </div>
        {preview.error ? <ErrorNotice error={preview.error} title="The preview failed" /> : null}
        {preview.data ? (
          <iframe
            title={`Preview of ${template?.name ?? "template"}`}
            sandbox=""
            srcDoc={preview.data}
            className="h-[60vh] w-full rounded-md border border-border bg-white"
          />
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

function UploadForm() {
  const upload = useUploadTemplate();
  const [name, setName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!file || !name.trim()) return;
    setDone(null);
    upload.mutate(
      { name: name.trim(), file },
      {
        onSuccess: (template) => {
          setDone(`Saved ${template.name} version ${template.version}. Preview it, then make it the default.`);
          setName("");
          setFile(null);
          if (fileInput.current) fileInput.current.value = "";
        },
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Upload a template</CardTitle>
        <CardDescription>
          A zip with <code>template.html</code> at its top level, plus CSS and brand files (.css, .svg,
          .png, .ttf, .otf). It is checked and test-rendered before it is saved. Uploading a name that
          exists adds a new version.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="flex flex-col gap-4" aria-label="Upload a template">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field id="template-name" label="Template name">
              <Input
                id="template-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={200}
                required
              />
            </Field>
            <Field id="template-file" label="Template zip file">
              <Input
                id="template-file"
                type="file"
                accept=".zip,application/zip"
                ref={fileInput}
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                required
              />
            </Field>
          </div>
          {upload.error ? <ErrorNotice error={upload.error} title="The template was not accepted" /> : null}
          {done ? (
            <p role="status" className="text-sm font-medium">
              {done}
            </p>
          ) : null}
          <div>
            <Button type="submit" disabled={upload.isPending || !file || !name.trim()}>
              {upload.isPending ? "Checking and saving..." : "Upload template"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

export function TemplatesPage() {
  const templates = useTemplates(true);
  const setDefault = useSetDefaultTemplate();
  const setActive = useSetTemplateActive();
  const [previewing, setPreviewing] = useState<ReportTemplate | null>(null);

  const error = setDefault.error ?? setActive.error;

  return (
    <>
      <PageHeader
        title="Report templates"
        description="The look of the HTML and PDF reports. Download the SonaComstar template, change it, upload it as a new template and make it the default."
        actions={
          <Button asChild variant="outline">
            <a href={defaultTemplateDownloadUrl()} download>
              Download default template
            </a>
          </Button>
        }
      />
      {templates.isPending ? <LoadingText>Loading templates...</LoadingText> : null}
      {templates.isError ? (
        <ErrorNotice error={templates.error} title="Could not load templates" onRetry={() => void templates.refetch()} />
      ) : null}
      {error ? <ErrorNotice error={error} title="The change was not saved" className="mb-4" /> : null}
      {templates.data ? (
        templates.data.length === 0 ? (
          <EmptyState>No templates yet.</EmptyState>
        ) : (
          <Table aria-label="Report templates">
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Default for</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Added</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {templates.data.map((template) => (
                <TableRow key={template.id}>
                  <TableCell className="font-medium">
                    {template.name}
                    {template.builtin ? (
                      <span className="block text-xs font-normal text-muted-foreground">Built in</span>
                    ) : null}
                  </TableCell>
                  <TableCell>{template.version}</TableCell>
                  <TableCell>
                    {[
                      template.default_for_application ? "Application reports" : null,
                      template.default_for_vendor ? "Vendor reports" : null,
                    ]
                      .filter(Boolean)
                      .join(", ") || "-"}
                  </TableCell>
                  <TableCell>
                    {template.validation_error ? (
                      <StatusBadge status="failed" label="Check failed" />
                    ) : (
                      <StatusBadge
                        status={template.active ? "active" : "disabled"}
                        label={template.active ? "In use" : "Switched off"}
                      />
                    )}
                    {template.validation_error ? (
                      <span className="mt-1 block max-w-xs text-xs">{template.validation_error}</span>
                    ) : null}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">{formatDateTime(template.created_at)}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-2">
                      <Button size="sm" variant="outline" onClick={() => setPreviewing(template)}>
                        Preview<span className="sr-only"> {template.name}</span>
                      </Button>
                      {template.active ? (
                        <>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={template.default_for_application || setDefault.isPending}
                            onClick={() => setDefault.mutate({ id: template.id, kind: "application" })}
                          >
                            Make default for application reports
                            <span className="sr-only">: {template.name}</span>
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={template.default_for_vendor || setDefault.isPending}
                            onClick={() => setDefault.mutate({ id: template.id, kind: "vendor" })}
                          >
                            Make default for vendor reports
                            <span className="sr-only">: {template.name}</span>
                          </Button>
                        </>
                      ) : null}
                      {!template.builtin ? (
                        <Button size="sm" variant="outline" asChild>
                          <a href={templateDownloadUrl(template.id)} download>
                            Download<span className="sr-only"> {template.name}</span>
                          </a>
                        </Button>
                      ) : null}
                      {!template.builtin ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={
                            setActive.isPending ||
                            (template.active && (template.default_for_application || template.default_for_vendor))
                          }
                          onClick={() => setActive.mutate({ id: template.id, active: !template.active })}
                        >
                          {template.active ? "Switch off" : "Switch on"}
                          <span className="sr-only"> {template.name}</span>
                        </Button>
                      ) : null}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )
      ) : null}
      <div className="mt-8">
        <UploadForm />
      </div>
      <PreviewDialog template={previewing} onClose={() => setPreviewing(null)} />
    </>
  );
}
