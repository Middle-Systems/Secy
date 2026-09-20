import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';

import { useCreateConnector } from '@/api/queries';
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
 * separate steps). `type` is fixed to GitHub for this pass, since the roadmap
 * locks Phase 6b to GitHub-only/agentless; the select stays visible-but-fixed
 * rather than hidden, so it reads as a real field once AWS/Azure adapters land.
 */
export function AddConnectorModal({ open, onOpenChange }: AddConnectorModalProps) {
  const createConnector = useCreateConnector();

  const [name, setName] = useState('');
  const [scope, setScope] = useState('');
  const [repos, setRepos] = useState('');

  const reset = () => {
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
        type: 'GITHUB',
        name: trimmedName,
        scope: scope.trim(),
        ...(repoAllowlist.length > 0 ? { repoAllowlist } : {}),
      });
      toast.success(`Connector "${trimmedName}" created. Sync it from the list when you're ready.`);
      handleOpenChange(false);
    } catch {
      toast.error('Could not create the connector. Check the backend and try again.');
    }
  };

  const canSubmit = name.trim().length > 0 && scope.trim().length > 0;

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Add connector</DialogTitle>
          <DialogDescription>
            Point Secy at a GitHub org or user to pull each repo's dependency-graph SBOM. This does
            not start a sync — use "Sync now" from the list once it's created.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="connector-type-select">Type</Label>
            <Select value="GITHUB" disabled>
              <SelectTrigger id="connector-type-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="GITHUB">GitHub</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              The only source connector this pass supports.
            </p>
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
            <Label htmlFor="connector-scope">GitHub org or user</Label>
            <Input
              id="connector-scope"
              placeholder="e.g. acme-corp"
              value={scope}
              onChange={(event) => setScope(event.target.value)}
              disabled={createConnector.isPending}
            />
          </div>

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
              One `owner/repo` per line (or comma-separated). Leave blank to sync every repo under
              the scope above.
            </p>
          </div>
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
