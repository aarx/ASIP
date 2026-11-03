"""Shared current-scan classification and organizational risk reporting."""

from ownership import reporting_asset_class_sql
from risk_engine import calculate_scan_risks


def current_scan_asset_classes(cursor, scan_id):
    """Resolve effective classes for members of one authoritative scan."""
    classification = reporting_asset_class_sql("d.domain", "d.ownership_status")
    cursor.execute(f"""
        SELECT d.id, {classification} AS asset_class
        FROM scan_results sr
        JOIN domains d ON d.id = sr.domain_id
        WHERE sr.scan_id = %s
    """, (scan_id,))
    return dict(cursor.fetchall())


def current_scan_risks(cursor, scan_id, asset_classes=None, *, risk_calculator=None):
    """Return canonical risks only for current trusted KNOWN/SHADOW members."""
    if asset_classes is None:
        asset_classes = current_scan_asset_classes(cursor, scan_id)
    eligible_ids = {
        domain_id for domain_id, asset_class in asset_classes.items()
        if asset_class in ("KNOWN", "SHADOW")
    }
    calculate = risk_calculator or calculate_scan_risks
    return [
        risk for risk in calculate(cursor, scan_id)
        if risk.domain_id in eligible_ids
    ]
