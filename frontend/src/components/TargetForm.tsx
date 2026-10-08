import { useQueryClient } from "@tanstack/react-query";
import { useId, useState, type FormEvent } from "react";

import {
  emptyApplicationChoice,
  findOrCreateVersion,
  isVendorSaas,
  resolveApplication,
  validateApplicationChoice,
  type Application,
} from "../api/applications";
import {
  buildTargetCreateBody,
  buildTargetUpdateBody,
  createTarget,
  emptyTargetForm,
  loginProfileAllowed,
  targetToForm,
  updateTarget,
  urlTargetsKey,
  validateTargetForm,
  type Target,
  type TargetFormValues,
} from "../api/targets";
import { useMeQuery } from "../api/me";
import type { UploadResult } from "../lib/upload";
import { ApplicationPicker, choiceApplication, VersionField } from "./SourcePicker";
import { UploadWidget, type Uploader } from "./UploadWidget";
import { CheckField, describedBy, fieldHelp, ProblemNotice } from "./FormBits";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Field } from "./ui/page";
import { Select } from "./ui/select";
import { Textarea } from "./ui/textarea";

/**
 * Register a web address for scanning (create) or change a registered one (edit): address, environment
 * tag, scope, exclusions, API definition, request limit, blackout windows, schedule and login profile
 * (UAT only). For a vendor SaaS product it also takes the vendor's written authorization.
 */
export function TargetForm({
  mode,
  target,
  application,
  versionLabel,
  onDone,
  onCancel,
  uploader,
}: {
  mode: "create" | "edit";
  /** The target being edited. */
  target?: Target;
  /** The application of the target being edited. */
  application?: Application | null;
  versionLabel?: string;
  onDone: (target: Target) => void;
  onCancel: () => void;
  uploader?: Uploader;
}) {
  const prefix = useId();
  const queryClient = useQueryClient();
  const me = useMeQuery();
  const isAdmin = me.data?.role === "Admin";
  const [values, setValues] = useState<TargetFormValues>(() =>
    mode === "edit" && target
      ? targetToForm(target, { kind: "existing", application: application ?? null }, versionLabel ?? "")
      : emptyTargetForm(emptyApplicationChoice()),
  );
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const effectiveApplication = choiceApplication(values.application);
  const needsAuthorization = isVendorSaas(effectiveApplication);
  const loginAllowed = loginProfileAllowed(values.environment);
  const set = (patch: Partial<TargetFormValues>) => setValues((current) => ({ ...current, ...patch }));
  const field = (name: string) => `${prefix}-${name}`;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    const found: Record<string, string> = {
      ...validateTargetForm(values, { mode, application: effectiveApplication }),
    };
    if (mode === "create") {
      for (const [key, message] of Object.entries(validateApplicationChoice(values.application))) {
        found[`application.${key}`] = message;
      }
    }
    setErrors(found);
    setFailure(null);
    if (Object.keys(found).length > 0) return;
    setBusy(true);
    try {
      let saved: Target;
      if (mode === "edit" && target) {
        saved = await updateTarget(target.id, buildTargetUpdateBody(values, effectiveApplication, isAdmin, target));
      } else {
        const app = await resolveApplication(values.application);
        // If a later step fails, a second try must reuse the application that now exists.
        set({ application: { kind: "existing", application: app } });
        const version = await findOrCreateVersion(app.id, values.versionLabel, "release");
        saved = await createTarget(version.id, buildTargetCreateBody(values, app, isAdmin));
      }
      void queryClient.invalidateQueries({ queryKey: urlTargetsKey });
      void queryClient.invalidateQueries({ queryKey: ["applications"] });
      void queryClient.invalidateQueries({ queryKey: ["versions"] });
      onDone(saved);
    } catch (caught) {
      setFailure(caught);
    } finally {
      setBusy(false);
    }
  };

  const appErrors: Record<string, string> = {};
  for (const [key, message] of Object.entries(errors)) {
    if (key.startsWith("application.")) appErrors[key.slice("application.".length)] = message;
  }
  const authFile: UploadResult | null = values.vendorAuthorizationArtifactId
    ? {
        uploadId: "",
        artifactId: values.vendorAuthorizationArtifactId,
        sha256: null,
        sizeBytes: 0,
        filename: values.vendorAuthorizationFilename || "Authorization document",
      }
    : null;

  return (
    <form
      onSubmit={(event) => void submit(event)}
      noValidate
      aria-label={mode === "create" ? "Register a web address" : "Edit the web address"}
      className="flex flex-col gap-5"
    >
      {mode === "create" ? (
        <>
          <ApplicationPicker
            idPrefix={prefix}
            value={values.application}
            onChange={(application) => set({ application })}
            errors={appErrors}
            disabled={busy}
          />
          <VersionField
            id={field("version")}
            applicationId={values.application.kind === "existing" ? values.application.application?.id : null}
            value={values.versionLabel}
            onChange={(label) => set({ versionLabel: label })}
            error={errors.versionLabel}
            help="The version of the application this address serves, for example uat or 2.4.0."
            disabled={busy}
          />
        </>
      ) : (
        <p className="m-0 text-sm text-muted-foreground">
          {application?.name ?? "Application"}
          {versionLabel ? `, version ${versionLabel}` : ""}
        </p>
      )}

      <Field
        id={field("url")}
        label="Address (URL)"
        help={fieldHelp(errors.url, "The base address to scan, for example https://app.example.com")}
      >
        <Input
          id={field("url")}
          type="url"
          value={values.url}
          disabled={busy}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => set({ url: event.target.value })}
          {...describedBy(field("url"), errors.url, true)}
        />
      </Field>

      <Field id={field("name")} label="Name (optional)" help={fieldHelp(errors.name, undefined)}>
        <Input
          id={field("name")}
          value={values.name}
          maxLength={200}
          disabled={busy}
          autoComplete="off"
          onChange={(event) => set({ name: event.target.value })}
        />
      </Field>

      <Field
        id={field("environment")}
        label="Environment tag"
        help={fieldHelp(
          errors.environment,
          "Production allows the passive baseline scan only. UAT allows full, API and Nuclei scans and a login profile. Changing the tag is recorded in the audit log.",
        )}
      >
        <Select
          id={field("environment")}
          value={values.environment}
          disabled={busy}
          onChange={(event) =>
            set({ environment: event.target.value as TargetFormValues["environment"] })
          }
          {...describedBy(field("environment"), errors.environment, true)}
        >
          <option value="">Choose...</option>
          <option value="production">Production</option>
          <option value="uat">UAT</option>
        </Select>
      </Field>

      <div className="grid gap-5 md:grid-cols-2">
        <Field
          id={field("includes")}
          label="In scope (one pattern per line)"
          help="Regular expressions for the addresses to test. Leave empty to test everything under the address."
        >
          <Textarea
            id={field("includes")}
            value={values.scopeIncludes}
            disabled={busy}
            spellCheck={false}
            onChange={(event) => set({ scopeIncludes: event.target.value })}
          />
        </Field>
        <Field
          id={field("excludes")}
          label="Excluded (one pattern per line)"
          help="Paths that must not be touched, for example /logout or /admin/delete.*"
        >
          <Textarea
            id={field("excludes")}
            value={values.scopeExcludes}
            disabled={busy}
            spellCheck={false}
            onChange={(event) => set({ scopeExcludes: event.target.value })}
          />
        </Field>
      </div>

      <div className="grid gap-5 md:grid-cols-2">
        <Field
          id={field("rate")}
          label="Request limit (requests per second)"
          help={fieldHelp(errors.rateLimit, "Optional, 1 to 1000. Applied to every tool.")}
        >
          <Input
            id={field("rate")}
            inputMode="numeric"
            value={values.rateLimit}
            disabled={busy}
            onChange={(event) => set({ rateLimit: event.target.value })}
            {...describedBy(field("rate"), errors.rateLimit, true)}
          />
        </Field>
        <Field
          id={field("cron")}
          label="Schedule (cron, UTC)"
          help={fieldHelp(errors.cron, "Optional, five fields, for example 0 2 * * 0 for Sundays at 02:00.")}
        >
          <Input
            id={field("cron")}
            value={values.cron}
            disabled={busy}
            spellCheck={false}
            onChange={(event) => set({ cron: event.target.value })}
            {...describedBy(field("cron"), errors.cron, true)}
          />
        </Field>
      </div>

      <Field
        id={field("blackouts")}
        label="Blackout windows (one per line, UTC)"
        help={fieldHelp(
          errors.blackouts,
          "No scan starts inside a window. Weekly: Mon,Tue 22:00-23:30 nightly batch. One-off: 2026-10-10T22:00Z/2026-10-11T02:00Z release freeze.",
        )}
      >
        <Textarea
          id={field("blackouts")}
          value={values.blackouts}
          disabled={busy}
          spellCheck={false}
          onChange={(event) => set({ blackouts: event.target.value })}
          {...describedBy(field("blackouts"), errors.blackouts, true)}
        />
      </Field>

      <div className="grid gap-5 md:grid-cols-2">
        <Field
          id={field("spec-type")}
          label="API definition type (optional)"
          help={fieldHelp(errors.apiSpecType, "Needed for API scans.")}
        >
          <Select
            id={field("spec-type")}
            value={values.apiSpecType}
            disabled={busy}
            onChange={(event) => set({ apiSpecType: event.target.value as TargetFormValues["apiSpecType"] })}
            {...describedBy(field("spec-type"), errors.apiSpecType, true)}
          >
            <option value="">None</option>
            <option value="openapi">OpenAPI</option>
            <option value="graphql">GraphQL</option>
            <option value="soap">SOAP (WSDL)</option>
          </Select>
        </Field>
        <Field
          id={field("spec-locator")}
          label="API definition address"
          help={fieldHelp(errors.apiSpecLocator, "The address of the definition file or endpoint.")}
        >
          <Input
            id={field("spec-locator")}
            value={values.apiSpecLocator}
            disabled={busy || !values.apiSpecType}
            spellCheck={false}
            onChange={(event) => set({ apiSpecLocator: event.target.value })}
            {...describedBy(field("spec-locator"), errors.apiSpecLocator, true)}
          />
        </Field>
      </div>

      <Field
        id={field("login")}
        label="Login profile (UAT only)"
        help={fieldHelp(
          errors.loginProfileId,
          loginAllowed
            ? "The id of a stored login profile. Leave empty to scan without logging in."
            : "Login profiles are available once the target is tagged UAT. Production is scanned without logging in.",
        )}
      >
        <Input
          id={field("login")}
          value={loginAllowed ? values.loginProfileId : ""}
          disabled={busy || !loginAllowed}
          spellCheck={false}
          autoComplete="off"
          onChange={(event) => set({ loginProfileId: event.target.value })}
          {...describedBy(field("login"), errors.loginProfileId, true)}
        />
      </Field>

      {isAdmin ? (
        <CheckField
          id={field("approved")}
          label="Host approved"
          checked={values.hostApproved}
          onCheckedChange={(hostApproved) => set({ hostApproved })}
          disabled={busy}
          help="Admin only. Allows scanning a host that is outside the allowlisted address ranges."
        />
      ) : null}

      {needsAuthorization ? (
        <fieldset className="flex flex-col gap-4 rounded-md border border-border p-4">
          <legend className="px-1 text-sm font-medium">Vendor authorization (SaaS product)</legend>
          <p className="m-0 text-sm text-muted-foreground">
            A vendor-hosted product counts as production. Scanning it needs the vendor's written authorization, the
            agreed scan window and a contact.
          </p>
          <UploadWidget
            label="Authorization document"
            accept=".pdf,.doc,.docx,.txt,.eml,.msg,.png,.jpg,.jpeg"
            help="The vendor's written permission, for example a signed letter or an email."
            error={errors.vendorAuthorization}
            value={authFile}
            onChange={(result) =>
              set({
                vendorAuthorizationArtifactId: result?.artifactId ?? "",
                vendorAuthorizationFilename: result?.filename ?? "",
              })
            }
            uploader={uploader}
            disabled={busy}
          />
          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              id={field("auth-from")}
              label="Scan window starts"
              help={fieldHelp(errors.vendorAuthorizedFrom, undefined)}
            >
              <Input
                id={field("auth-from")}
                type="date"
                value={values.vendorAuthorizedFrom}
                disabled={busy}
                onChange={(event) => set({ vendorAuthorizedFrom: event.target.value })}
                {...describedBy(field("auth-from"), errors.vendorAuthorizedFrom, false)}
              />
            </Field>
            <Field
              id={field("auth-until")}
              label="Scan window ends"
              help={fieldHelp(errors.vendorAuthorizedUntil, undefined)}
            >
              <Input
                id={field("auth-until")}
                type="date"
                value={values.vendorAuthorizedUntil}
                disabled={busy}
                onChange={(event) => set({ vendorAuthorizedUntil: event.target.value })}
                {...describedBy(field("auth-until"), errors.vendorAuthorizedUntil, false)}
              />
            </Field>
          </div>
          <Field
            id={field("auth-contact")}
            label="Vendor contact"
            help={fieldHelp(errors.vendorContact, "Who to call if the scan causes a problem.")}
          >
            <Input
              id={field("auth-contact")}
              value={values.vendorContact}
              maxLength={2000}
              disabled={busy}
              autoComplete="off"
              onChange={(event) => set({ vendorContact: event.target.value })}
              {...describedBy(field("auth-contact"), errors.vendorContact, true)}
            />
          </Field>
          <Field id={field("auth-notes")} label="Notes (optional)">
            <Textarea
              id={field("auth-notes")}
              value={values.vendorNotes}
              maxLength={4000}
              disabled={busy}
              onChange={(event) => set({ vendorNotes: event.target.value })}
            />
          </Field>
        </fieldset>
      ) : null}

      <ProblemNotice error={failure} title="The address could not be saved" />

      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy}>
          {busy ? "Saving..." : mode === "create" ? "Register address" : "Save changes"}
        </Button>
        <Button variant="outline" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
