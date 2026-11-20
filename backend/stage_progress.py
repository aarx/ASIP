"""Small, bounded progress records for the scan orchestrator."""

from datetime import datetime, timezone
import json

def progress_payload(
    scan_id, stage, *, selected=None, total=None, processed=None,
    completed=None, succeeded=None, failed=0, skipped=0,
    elapsed_seconds=0.0, status="RUNNING",
):
    elapsed = max(0.0, float(elapsed_seconds))
    measured_rate = processed / elapsed if isinstance(processed, int) and elapsed > 0 else None
    throughput = round(measured_rate, 3) if measured_rate is not None else None
    eta = None
    if (status in {"RUNNING", "SUCCEEDED"}
            and isinstance(total, int) and isinstance(processed, int)
            and measured_rate is not None and measured_rate > 0 and processed <= total):
        eta = round(max(0, total - processed) / measured_rate, 3)
    return {
        "scan_id": int(scan_id),
        "stage": str(stage),
        "status": status,
        "selected": selected,
        "total": total,
        "processed": processed,
        "completed": completed,
        "succeeded": succeeded,
        "failed": failed,
        "skipped": skipped,
        "elapsed_seconds": round(elapsed, 3),
        "throughput": throughput,
        "estimated_remaining_seconds": eta,
        "last_progress_at": datetime.now(timezone.utc).isoformat(),
    }


def emit_stage_progress(
    scan_id, stage, *, selected=None, total=None, processed=None,
    completed=None, succeeded=None, failed=0, skipped=0,
    elapsed_seconds=0.0, status="RUNNING",
):
    payload = progress_payload(
        scan_id, stage, selected=selected, total=total, processed=processed,
        completed=completed, succeeded=succeeded, failed=failed, skipped=skipped,
        elapsed_seconds=elapsed_seconds, status=status,
    )
    print("ASIP_STAGE_PROGRESS " + json.dumps(payload, separators=(",", ":")), flush=True)
