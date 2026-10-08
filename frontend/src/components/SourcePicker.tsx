import { useState, type ReactNode } from "react";

import {
  emptyApplicationChoice,
  useApplications,
  useVendors,
  useVersions,
  type Application,
  type ApplicationChoice,
  type Hosting,
} from "../api/applications";
import { useGithubRepositories, type GithubRepository } from "../api/github";
import type { SourceState } from "../api/scans";
import { formatDate } from "../lib/format";
import { describedBy, FieldGroup, fieldHelp, RadioField } from "./FormBits";
import { UploadWidget, type Uploader } from "./UploadWidget";
import { Input } from "./ui/input";
import { Field } from "./ui/page";
import { Select } from "./ui/select";

const NEW = "__new__";

/** The application facts the form needs, also for an application that is about to be created. */
export function choiceApplication(choice: ApplicationChoice): Pick<Application, "type" | "hosting"> | null {
  if (choice.kind === "existing") return choice.application;
  return { type: choice.type, hosting: choice.type === "vendor" && choice.hosting ? choice.hosting : null };
}

// --------------------------------------------------------------------------- application
/**
 * The application of a scan: an existing one, or a new one (name, internal or vendor and, for a vendor,
 * the vendor, the product and whether it is deployable or SaaS). `locked` fixes it (a connected repository
 * belongs to one application).
 */
export function ApplicationPicker({
  idPrefix,
  value,
  onChange,
  errors,
  locked,
  disabled,
}: {
  idPrefix: string;
  value: ApplicationChoice;
  onChange: (value: ApplicationChoice) => void;
  errors: Record<string, string>;
  locked?: Application | null;
  disabled?: boolean;
}) {
  const applications = useApplications();
  const vendors = useVendors();
  const selectId = `${idPrefix}-application`;

  if (locked) {
    return (
      <Field id={selectId} label="Application" help="The application of the chosen repository.">
        <Input id={selectId} value={locked.name} readOnly aria-readonly="true" />
      </Field>
    );
  }

  const selected = value.kind === "existing" ? (value.application?.id ?? "") : NEW;

  const choose = (id: string) => {
    if (id === NEW || id === "") {
      onChange(value.kind === "new" ? value : emptyApplicationChoice());
      return;
    }
    const application = applications.data?.find((item) => item.id === id) ?? null;
    onChange({ kind: "existing", application });
  };

  const update = (patch: Partial<Extract<ApplicationChoice, { kind: "new" }>>) => {
    if (value.kind === "new") onChange({ ...value, ...patch });
  };

  const existing = value.kind === "existing" ? value.application : null;

  return (
    <div className="flex flex-col gap-4">
      <Field id={selectId} label="Application" help={fieldHelp(errors.application, undefined)}>
        <Select
          id={selectId}
          value={selected}
          disabled={disabled}
          onChange={(event) => choose(event.target.value)}
          {...describedBy(selectId, errors.application, false)}
        >
          <option value={NEW}>New application...</option>
          {(applications.data ?? []).map((application) => (
            <option key={application.id} value={application.id}>
              {application.name}
              {application.type === "vendor" ? " (vendor)" : ""}
            </option>
          ))}
        </Select>
      </Field>

      {existing ? (
        <p className="m-0 text-sm text-muted-foreground" data-testid="application-summary">
          {existing.type === "vendor"
            ? `Vendor application${existing.vendor_product ? `, product ${existing.vendor_product}` : ""}${
                existing.hosting === "saas" ? ", SaaS" : existing.hosting === "deployable" ? ", deployable" : ""
              }.`
            : "Internal application."}
          {existing.last_scan_at ? ` Last scanned ${formatDate(existing.last_scan_at)}.` : ""}
        </p>
      ) : null}

      {value.kind === "new" ? (
        <div className="flex flex-col gap-4 rounded-md border border-border p-4">
          <Field
            id={`${idPrefix}-app-name`}
            label="New application name"
            help={fieldHelp(errors.name, "A name people will recognise, for example Payroll portal.")}
          >
            <Input
              id={`${idPrefix}-app-name`}
              value={value.name}
              maxLength={200}
              disabled={disabled}
              autoComplete="off"
              onChange={(event) => update({ name: event.target.value })}
              {...describedBy(`${idPrefix}-app-name`, errors.name, true)}
            />
          </Field>
          <FieldGroup legend="Who owns the code?">
            <RadioField
              name={`${idPrefix}-type`}
              value="internal"
              checked={value.type === "internal"}
              onSelect={() => update({ type: "internal" })}
              label="Internal (we develop it)"
              disabled={disabled}
            />
            <RadioField
              name={`${idPrefix}-type`}
              value="vendor"
              checked={value.type === "vendor"}
              onSelect={() => update({ type: "vendor" })}
              label="Vendor (a supplier develops it)"
              disabled={disabled}
            />
          </FieldGroup>
          {value.type === "vendor" ? (
            <div className="flex flex-col gap-4">
              <Field
                id={`${idPrefix}-vendor`}
                label="Vendor"
                help={fieldHelp(errors.vendor, undefined)}
              >
                <Select
                  id={`${idPrefix}-vendor`}
                  value={value.vendorId}
                  disabled={disabled}
                  onChange={(event) => update({ vendorId: event.target.value })}
                  {...describedBy(`${idPrefix}-vendor`, errors.vendor, false)}
                >
                  <option value="">Choose a vendor...</option>
                  {(vendors.data ?? []).map((vendor) => (
                    <option key={vendor.id} value={vendor.id}>
                      {vendor.name}
                    </option>
                  ))}
                  <option value="new">Add a new vendor...</option>
                </Select>
              </Field>
              {value.vendorId === "new" ? (
                <Field id={`${idPrefix}-vendor-name`} label="New vendor name">
                  <Input
                    id={`${idPrefix}-vendor-name`}
                    value={value.newVendorName}
                    maxLength={200}
                    disabled={disabled}
                    autoComplete="off"
                    onChange={(event) => update({ newVendorName: event.target.value })}
                  />
                </Field>
              ) : null}
              <Field
                id={`${idPrefix}-product`}
                label="Vendor product (optional)"
                help={fieldHelp(errors.vendorProduct, undefined)}
              >
                <Input
                  id={`${idPrefix}-product`}
                  value={value.vendorProduct}
                  maxLength={200}
                  disabled={disabled}
                  autoComplete="off"
                  onChange={(event) => update({ vendorProduct: event.target.value })}
                />
              </Field>
              <FieldGroup legend="How is the product hosted?">
                <RadioField
                  name={`${idPrefix}-hosting`}
                  value="deployable"
                  checked={value.hosting === "deployable"}
                  onSelect={() => update({ hosting: "deployable" as Hosting })}
                  label="Deployable (we install it in our UAT environment)"
                  disabled={disabled}
                />
                <RadioField
                  name={`${idPrefix}-hosting`}
                  value="saas"
                  checked={value.hosting === "saas"}
                  onSelect={() => update({ hosting: "saas" as Hosting })}
                  label="SaaS (the vendor hosts it)"
                  help="Web scans of SaaS products need the vendor's written authorization."
                  disabled={disabled}
                />
                {errors.hosting ? (
                  <p role="alert" className="m-0 text-xs font-semibold">
                    {errors.hosting}
                  </p>
                ) : null}
              </FieldGroup>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

// --------------------------------------------------------------------------- version
/** The version label of a scan: free text with the application's existing labels as suggestions. */
export function VersionField({
  id,
  applicationId,
  value,
  onChange,
  error,
  help,
  disabled,
}: {
  id: string;
  applicationId: string | null | undefined;
  value: string;
  onChange: (value: string) => void;
  error?: string;
  help?: ReactNode;
  disabled?: boolean;
}) {
  const versions = useVersions(applicationId);
  const listId = `${id}-list`;
  return (
    <Field id={id} label="Version label" help={fieldHelp(error, help)}>
      <Input
        id={id}
        value={value}
        maxLength={255}
        list={listId}
        disabled={disabled}
        autoComplete="off"
        onChange={(event) => onChange(event.target.value)}
        {...describedBy(id, error, Boolean(help))}
      />
      <datalist id={listId}>
        {(versions.data ?? []).map((version) => (
          <option key={version.id} value={version.label} />
        ))}
      </datalist>
    </Field>
  );
}

// --------------------------------------------------------------------------- source of the code
const KIND_LABELS: Record<SourceState["kind"], string> = {
  github: "A connected GitHub repository",
  url: "A repository address",
  zip: "A zip file of the source code",
  image: "A Docker image",
};

/**
 * Where the code comes from: a repository found by the GitHub App, a repository address (with the vendor's
 * deploy key or token for a vendor application), a zip file or a Docker image (a reference or a tar file).
 */
export function SourcePicker({
  idPrefix,
  value,
  onChange,
  errors,
  vendorApplication,
  onRepositoryChosen,
  uploader,
  disabled,
}: {
  idPrefix: string;
  value: SourceState;
  onChange: (value: SourceState) => void;
  errors: Record<string, string>;
  /** The application is a vendor's: show the vendor access choices for a repository address. */
  vendorApplication: boolean;
  onRepositoryChosen?: (repository: GithubRepository) => void;
  uploader?: Uploader;
  disabled?: boolean;
}) {
  const [search, setSearch] = useState("");
  const repositories = useGithubRepositories(search);
  const set = (patch: Partial<SourceState>) => onChange({ ...value, ...patch });
  const name = `${idPrefix}-source`;
  const repoId = `${idPrefix}-repo`;
  const urlId = `${idPrefix}-url`;
  const items = repositories.data ?? [];

  return (
    <div className="flex flex-col gap-4">
      <FieldGroup legend="Where is the code?">
        {(Object.keys(KIND_LABELS) as SourceState["kind"][]).map((kind) => (
          <RadioField
            key={kind}
            name={name}
            value={kind}
            checked={value.kind === kind}
            onSelect={() => set({ kind })}
            label={KIND_LABELS[kind]}
            disabled={disabled}
          />
        ))}
      </FieldGroup>

      {value.kind === "github" ? (
        <div className="flex flex-col gap-3">
          <Field id={`${repoId}-search`} label="Search repositories">
            <Input
              id={`${repoId}-search`}
              type="search"
              value={search}
              disabled={disabled}
              autoComplete="off"
              onChange={(event) => setSearch(event.target.value)}
            />
          </Field>
          <Field
            id={repoId}
            label="Repository"
            help={fieldHelp(
              errors.source,
              repositories.isError
                ? "The repository list could not be loaded."
                : items.length === 0 && !repositories.isPending
                  ? "No repositories found. An Admin connects the GitHub App in Settings; until then use a repository address."
                  : undefined,
            )}
          >
            <Select
              id={repoId}
              size={Math.max(2, Math.min(8, items.length))}
              className="h-auto"
              disabled={disabled}
              value={value.repo?.github_repo_id ? String(value.repo.github_repo_id) : ""}
              onChange={(event) => {
                const repo = items.find((item) => String(item.github_repo_id) === event.target.value) ?? null;
                set({ repo });
                if (repo) onRepositoryChosen?.(repo);
              }}
              {...describedBy(repoId, errors.source, true)}
            >
              {items.map((repo) => (
                <option key={repo.github_repo_id} value={String(repo.github_repo_id)}>
                  {repo.full_name}
                  {repo.default_branch ? ` (${repo.default_branch})` : ""}
                </option>
              ))}
            </Select>
          </Field>
        </div>
      ) : null}

      {value.kind === "url" ? (
        <div className="flex flex-col gap-4">
          <Field
            id={urlId}
            label="Repository address"
            help={fieldHelp(
              errors.source,
              "owner/name, an https:// address or an ssh address. Never put a password or token in the address.",
            )}
          >
            <Input
              id={urlId}
              value={value.url}
              disabled={disabled}
              autoComplete="off"
              spellCheck={false}
              placeholder="owner/repository"
              onChange={(event) => set({ url: event.target.value })}
              {...describedBy(urlId, errors.source, true)}
            />
          </Field>
          {vendorApplication ? (
            <FieldGroup legend="Access to the vendor's repository">
              <RadioField
                name={`${idPrefix}-credential`}
                value="existing"
                checked={value.credentialMode === "existing"}
                onSelect={() => set({ credentialMode: "existing" })}
                label="Use the deploy key or token already stored for this repository"
                disabled={disabled}
              />
              <RadioField
                name={`${idPrefix}-credential`}
                value="deploy_key"
                checked={value.credentialMode === "deploy_key"}
                onSelect={() => set({ credentialMode: "deploy_key" })}
                label="Generate a read-only deploy key"
                help="You get a public key to send to the vendor, who adds it to the repository."
                disabled={disabled}
              />
              <RadioField
                name={`${idPrefix}-credential`}
                value="token"
                checked={value.credentialMode === "token"}
                onSelect={() => set({ credentialMode: "token" })}
                label="Enter a token the vendor issued"
                help="A fine-grained token with read access to the repository contents."
                disabled={disabled}
              />
            </FieldGroup>
          ) : (
            <p className="m-0 text-sm text-muted-foreground">
              Internal repositories are read through the company's GitHub App.
            </p>
          )}
          {vendorApplication && value.credentialMode === "token" ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                id={`${idPrefix}-token`}
                label="Vendor token"
                help={fieldHelp(errors.token, "Stored encrypted. It is never shown again.")}
              >
                <Input
                  id={`${idPrefix}-token`}
                  type="password"
                  value={value.token}
                  disabled={disabled}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) => set({ token: event.target.value })}
                  {...describedBy(`${idPrefix}-token`, errors.token, true)}
                />
              </Field>
              <Field
                id={`${idPrefix}-token-expires`}
                label="Token expires on"
                help={fieldHelp(errors.tokenExpires, undefined)}
              >
                <Input
                  id={`${idPrefix}-token-expires`}
                  type="date"
                  value={value.tokenExpires}
                  disabled={disabled}
                  onChange={(event) => set({ tokenExpires: event.target.value })}
                  {...describedBy(`${idPrefix}-token-expires`, errors.tokenExpires, false)}
                />
              </Field>
            </div>
          ) : null}
        </div>
      ) : null}

      {value.kind === "zip" ? (
        <UploadWidget
          label="Zip file"
          accept=".zip,application/zip"
          help="The source code as a .zip file. Large files are sent in pieces and can be resumed."
          error={errors.source}
          value={value.zip}
          onChange={(zip) => set({ zip })}
          uploader={uploader}
          disabled={disabled}
        />
      ) : null}

      {value.kind === "image" ? (
        <div className="flex flex-col gap-4">
          <FieldGroup legend="How do you supply the image?">
            <RadioField
              name={`${idPrefix}-image-mode`}
              value="reference"
              checked={value.imageMode === "reference"}
              onSelect={() => set({ imageMode: "reference" })}
              label="An image reference"
              disabled={disabled}
            />
            <RadioField
              name={`${idPrefix}-image-mode`}
              value="tar"
              checked={value.imageMode === "tar"}
              onSelect={() => set({ imageMode: "tar" })}
              label="An image file (docker save, .tar)"
              disabled={disabled}
            />
          </FieldGroup>
          {value.imageMode === "reference" ? (
            <Field
              id={`${idPrefix}-image`}
              label="Image reference"
              help={fieldHelp(errors.source, "For example registry.example.com/team/app:1.4.2 or an @sha256: digest.")}
            >
              <Input
                id={`${idPrefix}-image`}
                value={value.imageRef}
                disabled={disabled}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => set({ imageRef: event.target.value })}
                {...describedBy(`${idPrefix}-image`, errors.source, true)}
              />
            </Field>
          ) : (
            <UploadWidget
              label="Image file"
              accept=".tar,.tar.gz,.tgz"
              help="An image saved with docker save, as .tar or .tar.gz."
              error={errors.source}
              value={value.imageTar}
              onChange={(imageTar) => set({ imageTar })}
              uploader={uploader}
              disabled={disabled}
            />
          )}
        </div>
      ) : null}
    </div>
  );
}
