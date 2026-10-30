package net.jdesive.secy.persistence.entity;

/**
 * How an {@link OwnershipSource#INFERRED} {@link OwnershipLink} was derived. Non-null exactly when
 * {@code source == INFERRED} (enforced by migration {@code 020}'s {@code ck_ownership_link_source_method}
 * and by {@code OwnershipService} for the H2 test schema, which lacks the CHECK).
 *
 * <p>No writer exists yet for any of these — they are reserved for future milestones:
 * <ul>
 *     <li>{@link #CODEOWNERS} and {@link #GITHUB_TEAM_PERMISSION} — M2's
 *     {@code GitHubSyncService}, parsing a repo's CODEOWNERS file and team repo permissions.</li>
 *     <li>{@link #CLOUD_RESOURCE_TAG} — M3's {@code AwsSyncService} / {@code AzureSyncService},
 *     reading a cloud resource's owner tag.</li>
 * </ul>
 *
 * <p>Deliberately not DB-value-checked (unlike {@link OwnershipSource}), so adding a future value
 * here needs no migration.
 */
public enum OwnershipInferenceMethod {
    CODEOWNERS,
    GITHUB_TEAM_PERMISSION,
    CLOUD_RESOURCE_TAG
}
