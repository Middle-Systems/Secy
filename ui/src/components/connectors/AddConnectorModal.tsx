import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';

import { useCreateConnector } from '@/api/queries';
import type { SourceConnectorType } from '@/api/types';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';

interface AddConnectorModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * What `scope` means per connector type — one instance-wide credential per
 * provider (read server-side, never entered here), so the only per-connector
 * input is where within that provider to look.
 */
const SCOPE_FIELD: Record<
  SourceConnectorType,
  { label: string; placeholder: string; help: string }
> = {
  GITHUB: {
    label: 'GitHub org or user',
    placeholder: 'e.g. acme-corp',
    help: 'Every repo under this org/user is enumerated, unless narrowed by the allowlist below.',
  },
  AWS: {
    label: 'AWS region',
    placeholder: 'e.g. us-east-1',
    help: 'EC2, ECR and Lambda resources in this region are enumerated and scanned via Inspector2.',
  },
  AZURE: {
    label: 'Azure subscription ID',
    placeholder: 'e.g. 11111111-2222-3333-4444-555555555555',
    help: 'VMs and ACR registries in this subscription are enumerated and scanned via Defender for Cloud.',
  },
};

/**
 * Splits a comma- or newline-separated textarea into trimmed, deduped
 * `owner/repo` names. A simple parse, not a tag-input component — the
 * allowlist is a handful of names, not a first-class editing surface.
 */
function parseRepoAllowlist(raw: string): string[] {
  const names = raw
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
  return Array.from(new Set(names));
}

/**
 * "Add connector" dialog — registers a `SourceConnector` but does not trigger
 * a sync (per the API contract: `POST /connectors` never queues a job, only
 * `POST /connectors/{id}/sync` does — creating and syncing are deliberately
 * separate steps). GitHub, AWS and Azure are all agentless connector types;
 * the host agent (Phase 10) is a separate, not-yet-built thing.
 */
export function AddConnectorModal({ open, onOpenChange }: AddConnectorModalProps) {
  const createConnector = useCreateConnector();

  const [type, setType] = useState<SourceConnectorType>('GITHUB');
  const [name, setName] = useState('');
  const [scope, setScope] = useState('');
  const [repos, setRepos] = useState('');

  const reset = () => {
    setType('GITHUB');
    setName('');
    setScope('');
    setRepos('');
  };

  const handleOpenChange = (next: boolean) => {
    if (!next) reset();
    onOpenChange(next);
  };

  const handleSubmit = async () => {
    const repoAllowlist = parseRepoAllowlist(repos);
    const trimmedName = name.trim();
    try {
      await createConnector.mutateAsync({
        type,
        name: trimmedName,
        scope: scope.trim(),
        ...(type === 'GITHUB' && repoAllowlist.length > 0 ? { repoAllowlist } : {}),
      });
      toast.success(`Connector "${trimmedName}" created. Sync it from the list when you're ready.`);
      handleOpenChange(false);
    } catch {
      toast.error('Could not create the connector. Check the backend and try again.');
    }
  };

  const scopeField = SCOPE_FIELD[type];
  const canSubmit = name.trim().length > 0 && scope.trim().length > 0;

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Add connector</DialogTitle>
          <DialogDescription>
            Point Secy at a GitHub org/user, an AWS region or an Azure subscription to pull its
            inventory agentlessly. This does not start a sync — use "Sync now" from the list once
            it's created.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="connector-type-select">Type</Label>
            <Select
              value={type}
              onValueChange={(value) => {
                setType(value as SourceConnectorType);
                setScope('');
              }}
              disabled={createConnector.isPending}
            >
              <SelectTrigger id="connector-type-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="GITHUB">GitHub</SelectItem>
                <SelectItem value="AWS">AWS</SelectItem>
                <SelectItem value="AZURE">Azure</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="connector-name">Name</Label>
            <Input
              id="connector-name"
              placeholder="e.g. Acme org"
              value={name}
              onChange={(event) => setName(event.target.value)}
              disabled={createConnector.isPending}
            />
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="connector-scope">{scopeField.label}</Label>
            <Input
              id="connector-scope"
              placeholder={scopeField.placeholder}
              value={scope}
              onChange={(event) => setScope(event.target.value)}
              disabled={createConnector.isPending}
            />
            <p className="text-xs text-muted-foreground">{scopeField.help}</p>
          </div>

          {type === 'GITHUB' && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="connector-repos">Repo allowlist (optional)</Label>
              <Textarea
                id="connector-repos"
                placeholder={'acme-corp/api\nacme-corp/web'}
                rows={4}
                value={repos}
                onChange={(event) => setRepos(event.target.value)}
                disabled={createConnector.isPending}
              />
              <p className="text-xs text-muted-foreground">
                One `owner/repo` per line (or comma-separated). Leave blank to sync every repo
                under the scope above.
              </p>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => handleOpenChange(false)}
            disabled={createConnector.isPending}
          >
            Cancel
          </Button>
          <Button
            type="button"
            onClick={() => void handleSubmit()}
            disabled={!canSubmit || createConnector.isPending}
          >
            {createConnector.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Add connector
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
