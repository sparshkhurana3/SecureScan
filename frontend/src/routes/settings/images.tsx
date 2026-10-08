import { useState } from "react";

import { errorMessage } from "../../api/client";
import {
  type ImageState,
  type ImageVersion,
  useApproveImage,
  useCheckImagesNow,
  useDeactivateImage,
  useImageVersions,
  useRejectImage,
} from "../../api/operations";
import { StatusBadge } from "../../components/StatusBadge";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { EmptyState, ErrorNotice, LoadMore, LoadingText, PageHeader } from "../../components/ui/page";
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

const STATES: { value: ImageState | ""; label: string }[] = [
  { value: "pending", label: "Proposed" },
  { value: "active", label: "Approved and in use" },
  { value: "retired", label: "Retired" },
  { value: "rejected", label: "Rejected" },
  { value: "", label: "All" },
];

/** The backend approves a proposal whose regression run passed, or whose run was skipped after the Admin confirmed. */
export function approvalRule(image: ImageVersion): "ok" | "acknowledge" | "blocked" {
  if (image.regression_result === "passed") return "ok";
  if (image.regression_result === "skipped") return "acknowledge";
  return "blocked";
}

function shortDigest(digest: string): string {
  return `sha256:${digest.replace(/^sha256:/, "").slice(0, 12)}`;
}

function ImageRow({ image }: { image: ImageVersion }) {
  const approve = useApproveImage();
  const reject = useRejectImage();
  const deactivate = useDeactivateImage();
  const [acknowledge, setAcknowledge] = useState(false);
  const rule = approvalRule(image);
  const error = approve.error ?? reject.error ?? deactivate.error;
  const busy = approve.isPending || reject.isPending || deactivate.isPending;
  const label = `${image.tool} ${shortDigest(image.digest)}`;

  return (
    <TableRow>
      <TableCell>
        <span className="font-medium">{image.tool}</span>
        <span className="block text-xs text-muted-foreground">{image.reason ?? image.source}</span>
      </TableCell>
      <TableCell className="font-mono text-xs">
        {image.image}
        {image.tag ? `:${image.tag}` : ""}
        <span className="block text-muted-foreground">{shortDigest(image.digest)}</span>
        {image.previous_digest ? (
          <span className="block text-muted-foreground">was {shortDigest(image.previous_digest)}</span>
        ) : null}
      </TableCell>
      <TableCell>
        <StatusBadge status={image.regression_result} />
      </TableCell>
      <TableCell>
        <StatusBadge status={image.state} />
        <span className="block text-xs text-muted-foreground">
          {formatDateTime(image.approved_at ?? image.proposed_at)}
        </span>
      </TableCell>
      <TableCell>
        {image.state === "pending" ? (
          <div className="flex flex-col gap-2">
            {rule === "acknowledge" ? (
              <label className="flex items-center gap-2 text-xs">
                <Checkbox
                  checked={acknowledge}
                  onCheckedChange={(value) => setAcknowledge(value === true)}
                  aria-label={`I tested ${label} by hand`}
                />
                No regression check exists; I tested it by hand
              </label>
            ) : null}
            {rule === "blocked" ? (
              <p className="m-0 text-xs text-muted-foreground">
                Approval needs a passed regression run (now: {image.regression_result}).
              </p>
            ) : null}
            <div className="flex gap-2">
              <Button
                size="sm"
                disabled={busy || rule === "blocked" || (rule === "acknowledge" && !acknowledge)}
                onClick={() => approve.mutate({ id: image.id, body: { acknowledge_skipped: acknowledge } })}
                aria-label={`Approve ${label}`}
              >
                Approve
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={busy}
                onClick={() => reject.mutate({ id: image.id })}
                aria-label={`Reject ${label}`}
              >
                Reject
              </Button>
            </div>
          </div>
        ) : null}
        {image.state === "active" && image.active ? (
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => deactivate.mutate({ id: image.id })}
            aria-label={`Stop using ${label}`}
          >
            Stop using
          </Button>
        ) : null}
        {error ? (
          <p role="alert" className="mt-2 text-xs font-semibold text-foreground">
            {errorMessage(error)}
          </p>
        ) : null}
      </TableCell>
    </TableRow>
  );
}

export function ImagesPage() {
  const [state, setState] = useState<ImageState | "">("pending");
  const images = useImageVersions(state);
  const check = useCheckImagesNow();
  const rows = images.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <>
      <PageHeader
        title="Scanner images"
        description="A new scanner image is proposed monthly. It is used only after its regression run passed and an Admin approved it. After approving, run python scripts/dev.py pull-images on the server to pull it."
      />
      <div className="mb-4 flex flex-wrap items-end gap-4">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="image-state" className="text-sm font-medium">
            Show
          </label>
          <Select id="image-state" value={state} onChange={(e) => setState(e.target.value as ImageState | "")}>
            {STATES.map((item) => (
              <option key={item.label} value={item.value}>
                {item.label}
              </option>
            ))}
          </Select>
        </div>
        <Button variant="outline" disabled={check.isPending} onClick={() => check.mutate()}>
          Check for new images now
        </Button>
      </div>
      {check.isError ? (
        <p role="alert" className="mb-3 text-sm font-semibold text-foreground">
          {errorMessage(check.error)}
        </p>
      ) : null}
      {check.data ? (
        <p role="status" className="mb-3 text-sm">
          {check.data.detail}
        </p>
      ) : null}
      {images.isPending ? <LoadingText>Loading images...</LoadingText> : null}
      {images.isError ? (
        <ErrorNotice
          error={images.error}
          title="Could not list the scanner images"
          onRetry={() => void images.refetch()}
        />
      ) : null}
      {images.data && rows.length === 0 ? <EmptyState>No images in this state.</EmptyState> : null}
      {rows.length > 0 ? (
        <Table aria-label="Scanner images">
          <TableHeader>
            <TableRow>
              <TableHead>Tool</TableHead>
              <TableHead>Image</TableHead>
              <TableHead>Regression</TableHead>
              <TableHead>State</TableHead>
              <TableHead>Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((image) => (
              <ImageRow key={image.id} image={image} />
            ))}
          </TableBody>
        </Table>
      ) : null}
      <LoadMore
        hasMore={Boolean(images.hasNextPage)}
        loading={images.isFetchingNextPage}
        onClick={() => void images.fetchNextPage()}
      />
    </>
  );
}
