package net.jdesive.secy.model.vex;

/** {@code POST /vex/reconcile}'s response. */
public record VexReconcileResponse(int alertsEvaluated, int alertsChanged) {
}
