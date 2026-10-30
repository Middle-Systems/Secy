import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';

import { useActionItemDetail, useActionItemsPage, useMyOwnedProducts, usePatchActionItem } from '@/api/queries';
import type { FindingSummary, RemediationStatus } from '@/api/types';
import { ActionableDetailPanel } from '@/components/actionable/ActionableDetailPanel';
import { DisputeDialog } from '@/components/my-work/DisputeDialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Pagination } from '@/components/common/Pagination';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EM_DASH, formatDate } from '@/lib/format';

const STATUS_OPTIONS: { value: RemediationStatus | 'ALL'; label: string }[] = [
  { value: 'ALL', label: 'All open (default)' },
  { value: 'OPEN', label: 'Open' },
  { value: 'IN_PROGRESS', label: 'In progress' },
  { value: 'RESOLVED', label: 'Resolved' },
  { value: 'RISK_ACCEPTED', label: 'Risk accepted' },
  { value: 'NOT_AFFECTED', label: 'Not affected' },
];

function statusBadgeVariant(status: RemediationStatus) {
  switch (status) {
    case 'OPEN':
      return 'destructive' as const;
    case 'IN_PROGRESS':
      return 'default' as const;
    case 'RESOLVED':
    case 'NOT_AFFECTED':
      return 'secondary' as const;
    default:
      return 'outline' as const;
  }
}

/**
 * The software-engineer view's home screen (M1k) — `GET /action-items?ownedBy=me`: action items
 * scoped to the products the signed-in user owns. This is the view-level answer to "a software
 * engineer mapped to one product sees only that product's action items" — `GET /action-items`
 * without `ownedBy` stays unrestricted (that's Tenancy hardening's job, not this screen's).
 */
export function MyWorkView() {
  const [page, setPage] = useState(0);
  const [status, setStatus] = useState<RemediationStatus | 'ALL'>('ALL');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [findingDetail, setFindingDetail] = useState<{ id: string; itemType: 'VULNERABILITY' | 'COMPROMISE' } | null>(
    null,
  );
  const [disputeTarget, setDisputeTarget] = useState<{ findingId: string; title: string | null } | null>(null);

  const ownedProducts = useMyOwnedProducts();
  const itemsPage = useActionItemsPage({
    page,
    size: 15,
    ownedBy: 'me',
    status: status === 'ALL' ? undefined : status,
  });
  const selectedDetail = useActionItemDetail(selectedId ?? undefined);
  const patchItem = usePatchActionItem();

  const items = itemsPage.data?.content ?? [];
  const noOwnedProducts = (ownedProducts.data?.length ?? 0) === 0;

  async function transition(id: string, next: RemediationStatus) {
    try {
      await patchItem.mutateAsync({ id, patch: { status: next } });
      toast.success(next === 'IN_PROGRESS' ? 'Marked in progress' : 'Marked resolved');
    } catch {
      toast.error('Could not update the action item. Check the backend and try again.');
    }
  }

  return (
    <div className="flex flex-col gap-4 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">My Action Items</h1>
          <p className="text-sm text-muted-foreground">
            Remediation tasks scoped to the products you own.
          </p>
        </div>
        <Select
          value={status}
          onValueChange={(v) => {
            setStatus(v as RemediationStatus | 'ALL');
            setPage(0);
          }}
        >
          <SelectTrigger className="w-56">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STATUS_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {itemsPage.isPending ? (
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader2 className="mr-2 h-5 w-5 animate-spin" /> Loading your action items…
        </div>
      ) : noOwnedProducts && items.length === 0 ? (
        <p className="py-16 text-center text-sm text-muted-foreground">
          You don&apos;t own any products yet — ask a security engineer to add you as an owner.
        </p>
      ) : items.length === 0 ? (
        <p className="py-16 text-center text-sm text-muted-foreground">
          No action items match this filter for the products you own.
        </p>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Title</TableHead>
                <TableHead>Product</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Score</TableHead>
                <TableHead>Known fix</TableHead>
                <TableHead>Updated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item) => (
                <TableRow
                  key={item.id}
                  className="cursor-pointer"
                  onClick={() => setSelectedId(item.id)}
                >
                  <TableCell className="font-medium">{item.title}</TableCell>
                  <TableCell>{item.productName ?? EM_DASH}</TableCell>
                  <TableCell>
                    <Badge variant={statusBadgeVariant(item.status)}>{item.status}</Badge>
                  </TableCell>
                  <TableCell>{item.score?.maxRiskScore?.toFixed(1) ?? EM_DASH}</TableCell>
                  <TableCell>
                    {item.fixSummary
                      ? `${item.fixSummary.remainingWithKnownFix}/${
                          item.fixSummary.remainingWithKnownFix + item.fixSummary.remainingWithoutKnownFix
                        }`
                      : EM_DASH}
                  </TableCell>
                  <TableCell>{formatDate(item.updatedAt)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {itemsPage.data && (
            <Pagination
              page={itemsPage.data.number}
              size={itemsPage.data.size}
              totalElements={itemsPage.data.totalElements}
              totalPages={itemsPage.data.totalPages}
              onPageChange={setPage}
            />
          )}
        </>
      )}

      <Sheet open={Boolean(selectedId)} onOpenChange={(open) => !open && setSelectedId(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
          {selectedDetail.isPending ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin" />
            </div>
          ) : selectedDetail.data ? (
            <>
              <SheetHeader>
                <SheetTitle>{selectedDetail.data.title}</SheetTitle>
                <SheetDescription>
                  {selectedDetail.data.description ?? 'No description.'}
                </SheetDescription>
              </SheetHeader>

              <div className="mt-4 flex gap-2">
                {selectedDetail.data.status === 'OPEN' && (
                  <Button size="sm" onClick={() => transition(selectedDetail.data!.id, 'IN_PROGRESS')}>
                    Start
                  </Button>
                )}
                {(selectedDetail.data.status === 'OPEN' || selectedDetail.data.status === 'IN_PROGRESS') && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => transition(selectedDetail.data!.id, 'RESOLVED')}
                  >
                    Mark fixed
                  </Button>
                )}
              </div>

              <div className="mt-6 flex flex-col gap-3">
                <h3 className="text-sm font-semibold text-foreground">
                  Findings ({selectedDetail.data.findings.length})
                </h3>
                {selectedDetail.data.findings.map((finding: FindingSummary) => (
                  <div key={`${finding.type}-${finding.id}`} className="rounded-md border border-border p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium text-foreground">
                        {finding.title ?? finding.type}
                      </span>
                      <Badge variant="outline">{finding.type}</Badge>
                    </div>
                    {finding.fix && (
                      <p className="mt-1 text-xs text-muted-foreground">{finding.fix.guidance}</p>
                    )}
                    <div className="mt-2 flex gap-2">
                      {(finding.type === 'VULNERABILITY' || finding.type === 'COMPROMISE') && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            setFindingDetail({ id: finding.id, itemType: finding.type as 'VULNERABILITY' | 'COMPROMISE' })
                          }
                        >
                          View finding
                        </Button>
                      )}
                      {finding.type === 'VULNERABILITY' && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            setDisputeTarget({ findingId: finding.id, title: finding.title })
                          }
                        >
                          Dispute
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : null}
        </SheetContent>
      </Sheet>

      <ActionableDetailPanel
        id={findingDetail?.id ?? null}
        itemType={findingDetail?.itemType ?? null}
        onOpenChange={(open) => !open && setFindingDetail(null)}
      />

      {disputeTarget && selectedId && (
        <DisputeDialog
          open={Boolean(disputeTarget)}
          onOpenChange={(open) => !open && setDisputeTarget(null)}
          actionItemId={selectedId}
          findingId={disputeTarget.findingId}
          findingTitle={disputeTarget.title}
        />
      )}
    </div>
  );
}

export default MyWorkView;
