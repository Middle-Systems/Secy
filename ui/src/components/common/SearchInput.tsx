import { useEffect, useRef, useState } from 'react';
import { Search, X } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

interface SearchInputProps {
  /**
   * Current search term. Treated as the initial value and kept in sync when it
   * changes externally (e.g. a "clear filters" button in the parent). The input
   * is otherwise self-managed between debounce ticks.
   */
  value: string;
  /** Fired `debounceMs` after typing stops, and only when the term actually changed. */
  onDebouncedChange: (value: string) => void;
  placeholder?: string;
  /** Debounce delay in ms. Default 400 (matches the Angular `debounceTime(400)`). */
  debounceMs?: number;
  className?: string;
  'aria-label'?: string;
}

/**
 * Debounced search box with a leading icon and a clear button — the React
 * equivalent of the Angular `debounceTime(400), distinctUntilChanged()` pipe.
 *
 * @example
 * const [search, setSearch] = useState('');
 * <SearchInput
 *   value={search}
 *   onDebouncedChange={(v) => { setSearch(v); setPage(0); }}
 *   placeholder="Search Vendor, Product, or CVE…"
 * />
 */
export function SearchInput({
  value,
  onDebouncedChange,
  placeholder = 'Search…',
  debounceMs = 400,
  className,
  'aria-label': ariaLabel = 'Search',
}: SearchInputProps) {
  const [draft, setDraft] = useState(value);
  // The last value we emitted / received, for distinctUntilChanged semantics.
  const lastEmitted = useRef(value);
  const onChangeRef = useRef(onDebouncedChange);
  onChangeRef.current = onDebouncedChange;

  // Keep the field in sync if the parent resets the term.
  useEffect(() => {
    if (value !== lastEmitted.current) {
      lastEmitted.current = value;
      setDraft(value);
    }
  }, [value]);

  useEffect(() => {
    if (draft === lastEmitted.current) return;
    const id = setTimeout(() => {
      lastEmitted.current = draft;
      onChangeRef.current(draft);
    }, debounceMs);
    return () => clearTimeout(id);
  }, [draft, debounceMs]);

  return (
    <div className={cn('relative', className)}>
      <Search
        className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
        aria-hidden="true"
      />
      <Input
        type="search"
        role="searchbox"
        aria-label={ariaLabel}
        value={draft}
        placeholder={placeholder}
        onChange={(e) => setDraft(e.target.value)}
        className="pl-9 pr-9 [&::-webkit-search-cancel-button]:appearance-none"
      />
      {draft && (
        <Button
          type="button"
          variant="ghost"
          size="icon"
          aria-label="Clear search"
          onClick={() => setDraft('')}
          className="absolute right-1 top-1/2 h-7 w-7 -translate-y-1/2 text-muted-foreground"
        >
          <X className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}
