import { useState } from "react";

import {
  type DefectDojoAccount,
  useDefectDojoAccounts,
  useSetAccountActive,
} from "../../api/defectdojo";
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
import { EmptyState, ErrorNotice, LoadingText, LoadMore, PageHeader } from "../../components/ui/page";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import { formatDate, formatDateTime } from "../../lib/format";

function accountState(account: DefectDojoAccount): { status: string; label: string } {
  if (!account.has_account) return { status: "pending", label: "Not created yet" };
  if (account.disabled) return { status: "disabled", label: "Disabled" };
  return { status: "active", label: "Enabled" };
}

export function AccountsPage() {
  const accounts = useDefectDojoAccounts();
  const toggle = useSetAccountActive();
  const [confirming, setConfirming] = useState<DefectDojoAccount | null>(null);
  const items = accounts.data?.pages.flatMap((page) => page.items) ?? [];

  const confirm = () => {
    if (!confirming) return;
    toggle.mutate(
      { userId: confirming.user_id, active: confirming.disabled },
      { onSuccess: () => setConfirming(null) },
    );
  };

  return (
    <>
      <PageHeader
        title="DefectDojo accounts"
        description="Everyone who signs in to SecureScan gets a DefectDojo account at their first sign-in. Accounts that are not used for 90 days are disabled by the system. You can disable or enable one here."
      />
      {accounts.isPending ? <LoadingText>Loading accounts...</LoadingText> : null}
      {accounts.isError ? (
        <ErrorNotice error={accounts.error} title="Could not load accounts" onRetry={() => void accounts.refetch()} />
      ) : null}
      {accounts.data ? (
        items.length === 0 ? (
          <EmptyState>Nobody has signed in yet.</EmptyState>
        ) : (
          <Table aria-label="DefectDojo accounts">
            <TableHeader>
              <TableRow>
                <TableHead>Person</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>DefectDojo user name</TableHead>
                <TableHead>Account</TableHead>
                <TableHead>Last sign-in</TableHead>
                <TableHead>Expires if unused</TableHead>
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((account) => {
                const state = accountState(account);
                const who = account.name ?? account.email ?? account.user_id;
                return (
                  <TableRow key={account.user_id}>
                    <TableCell className="font-medium">
                      {who}
                      {account.email && account.name ? (
                        <span className="block text-xs font-normal text-muted-foreground">
                          {account.email}
                        </span>
                      ) : null}
                    </TableCell>
                    <TableCell>{account.role}</TableCell>
                    <TableCell className="font-mono text-xs">{account.dd_username ?? "-"}</TableCell>
                    <TableCell>
                      <StatusBadge status={state.status} label={state.label} />
                      {account.password_waiting ? (
                        <span className="mt-1 block text-xs text-muted-foreground">
                          First password not yet seen
                        </span>
                      ) : null}
                    </TableCell>
                    <TableCell className="whitespace-nowrap">{formatDateTime(account.last_login)}</TableCell>
                    <TableCell className="whitespace-nowrap">{formatDate(account.expires_at)}</TableCell>
                    <TableCell>
                      {account.has_account ? (
                        <Button size="sm" variant="outline" onClick={() => setConfirming(account)}>
                          {account.disabled ? "Enable" : "Disable"}
                          <span className="sr-only"> the DefectDojo account of {who}</span>
                        </Button>
                      ) : null}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )
      ) : null}
      <LoadMore
        hasMore={Boolean(accounts.hasNextPage)}
        loading={accounts.isFetchingNextPage}
        onClick={() => void accounts.fetchNextPage()}
      />
      <Dialog
        open={confirming !== null}
        onOpenChange={(open) => {
          if (!open) {
            setConfirming(null);
            toggle.reset();
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {confirming?.disabled ? "Enable" : "Disable"} this DefectDojo account?
            </DialogTitle>
            <DialogDescription>
              {confirming?.disabled
                ? "The person can sign in to DefectDojo again."
                : "The person can no longer sign in to DefectDojo. Their findings and history stay. They can still use SecureScan."}
            </DialogDescription>
          </DialogHeader>
          {toggle.error ? <ErrorNotice error={toggle.error} title="The account was not changed" /> : null}
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button onClick={confirm} disabled={toggle.isPending}>
              {toggle.isPending ? "Saving..." : confirming?.disabled ? "Enable account" : "Disable account"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
