package net.jdesive.secy.model.actionable;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

/**
 * A {@link Pageable} addressed by absolute offset rather than by page number.
 *
 * <h2>Why this has to exist</h2>
 *
 * <p>{@code GET /actionable} pages over the concatenation of two independent queries — every
 * compromise finding, then every vulnerability alert. A requested page can straddle the boundary:
 * with 7 compromise findings and {@code size=5}, page 1 is the last 2 findings followed by the first
 * 3 alerts. The alert half therefore has to start at offset 0 while the finding half starts at
 * offset 5, and on page 2 the alert half starts at offset 3 — which is not a multiple of any page
 * size.
 *
 * <p>{@code PageRequest} computes {@code offset = page * size} and cannot express that.
 * Rather than rounding to a page boundary and trimming in Java (which would over-fetch by up to a
 * page on every request, forever) this passes the offset straight through. Spring Data JPA reads
 * {@link #getOffset()} and {@link #getPageSize()} when it builds the query and never asks for the
 * page number, so nothing else about the repository call changes.
 *
 * <p>Immutable, and the navigation methods are deliberately minimal: this is only ever handed
 * straight to a repository, never returned to a caller who might page off it. {@link #getPageNumber()}
 * reports the offset divided by the size, which is right when the offset happens to be aligned and
 * meaningless otherwise — nothing reads it.
 */
public final class OffsetLimitRequest implements Pageable {

    private final long offset;

    private final int limit;

    private final Sort sort;

    private OffsetLimitRequest(long offset, int limit, Sort sort) {
        this.offset = Math.max(0, offset);
        this.limit = Math.max(1, limit);
        this.sort = sort == null ? Sort.unsorted() : sort;
    }

    /**
     * {@code limit} rows starting at {@code offset}, unsorted — the ordering comes from the
     * {@code Specification}'s own {@code ORDER BY}, exactly as it does for the plain
     * {@code PageRequest} calls elsewhere in {@code ActionableService}.
     */
    public static OffsetLimitRequest of(long offset, int limit) {
        return new OffsetLimitRequest(offset, limit, Sort.unsorted());
    }

    @Override
    public long getOffset() {
        return offset;
    }

    @Override
    public int getPageSize() {
        return limit;
    }

    @Override
    public int getPageNumber() {
        return (int) (offset / limit);
    }

    @Override
    public Sort getSort() {
        return sort;
    }

    @Override
    public boolean isPaged() {
        return true;
    }

    @Override
    public Pageable next() {
        return new OffsetLimitRequest(offset + limit, limit, sort);
    }

    @Override
    public Pageable previousOrFirst() {
        return hasPrevious() ? new OffsetLimitRequest(offset - limit, limit, sort) : first();
    }

    @Override
    public Pageable first() {
        return new OffsetLimitRequest(0, limit, sort);
    }

    @Override
    public Pageable withPage(int pageNumber) {
        return new OffsetLimitRequest((long) pageNumber * limit, limit, sort);
    }

    @Override
    public boolean hasPrevious() {
        return offset > 0;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof OffsetLimitRequest that)) {
            return false;
        }
        return offset == that.offset && limit == that.limit && sort.equals(that.sort);
    }

    @Override
    public int hashCode() {
        return (int) (31 * (31 * offset + limit) + sort.hashCode());
    }

    @Override
    public String toString() {
        return "OffsetLimitRequest[offset=" + offset + ", limit=" + limit + "]";
    }

}
