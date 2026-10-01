import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { z } from 'zod';

import { useDisputeFinding } from '@/api/queries';
import type { VexJustification } from '@/api/types';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';

const JUSTIFICATIONS: { value: VexJustification; label: string }[] = [
  { value: 'COMPONENT_NOT_PRESENT', label: 'Component not present' },
  { value: 'VULNERABLE_CODE_NOT_PRESENT', label: 'Vulnerable code not present' },
  { value: 'VULNERABLE_CODE_NOT_IN_EXECUTE_PATH', label: 'Vulnerable code not in execute path' },
  {
    value: 'VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY',
    label: 'Vulnerable code cannot be controlled by an adversary',
  },
  { value: 'INLINE_MITIGATIONS_ALREADY_EXIST', label: 'Inline mitigations already exist' },
];

const schema = z.object({
  justification: z.custom<VexJustification>().optional(),
  impactStatement: z
    .string()
    .trim()
    .min(1, 'An impact statement is required.')
    .max(4096, 'Keep it under 4096 characters.'),
});

type FormValues = z.infer<typeof schema>;

interface DisputeDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  actionItemId: string;
  findingId: string;
  findingTitle: string | null;
}

/**
 * "Dispute with a VEX justification" (M1k). A dispute is an authored TENANT OpenVEX
 * `not_affected` statement, run through the existing VEX ingestion pipeline — see
 * `ActionItemDisputeService`. Only ever shown for a `VULNERABILITY` finding (the caller is
 * responsible for that — see `MyWorkView`).
 */
export function DisputeDialog({
  open,
  onOpenChange,
  actionItemId,
  findingId,
  findingTitle,
}: DisputeDialogProps) {
  const disputeFinding = useDisputeFinding();
  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { justification: undefined, impactStatement: '' },
  });

  const submit = async (values: FormValues) => {
    try {
      await disputeFinding.mutateAsync({
        id: actionItemId,
        payload: {
          findingId,
          justification: values.justification,
          impactStatement: values.impactStatement,
        },
      });
      toast.success('Dispute queued — the VEX statement is being ingested.');
      form.reset();
      onOpenChange(false);
    } catch {
      toast.error('Could not queue the dispute. Check the backend and try again.');
    }
  };

  const handleOpenChange = (next: boolean) => {
    if (!next) form.reset();
    onOpenChange(next);
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Dispute {findingTitle ?? 'this finding'}</DialogTitle>
          <DialogDescription>
            This authors a tenant-origin VEX "not affected" statement and queues it for ingestion —
            it takes effect as soon as that job finishes, with no approval step.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(submit)} className="flex flex-col gap-4">
            <FormField
              control={form.control}
              name="justification"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Justification</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Optional — pick the closest reason" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {JUSTIFICATIONS.map((j) => (
                        <SelectItem key={j.value} value={j.value}>
                          {j.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    Optional if the impact statement below explains why on its own.
                  </FormDescription>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="impactStatement"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Impact statement</FormLabel>
                  <FormControl>
                    <Textarea
                      rows={4}
                      placeholder="Explain why this finding doesn't apply here…"
                      autoFocus
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => handleOpenChange(false)}
                disabled={disputeFinding.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={disputeFinding.isPending}>
                {disputeFinding.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                Queue dispute
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
