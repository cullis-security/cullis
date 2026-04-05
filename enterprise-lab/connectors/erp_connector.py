"""
ERPNext Connector — wraps the Frappe REST API for inventory and purchasing.

Used by the buyer agent to:
  1. Check stock levels (Bin doctype)
  2. Read item reorder thresholds
  3. Create Purchase Orders from negotiation results

Authentication: API key + secret (server-to-server).

Usage:
    erp = ERPNextConnector("http://erpnext:8080", "api_key", "api_secret")
    items = erp.get_low_stock_items()
    erp.create_purchase_order("SUP-001", [{"item_code": "BLT-M8", "qty": 5000, "rate": 0.045}])
"""
import logging
from dataclasses import dataclass

import httpx

_log = logging.getLogger("agent_trust.erp")

_TIMEOUT = 15.0


@dataclass
class StockItem:
    item_code: str
    item_name: str
    warehouse: str
    actual_qty: float
    reorder_level: float
    reorder_qty: float
    unit: str


class ERPNextConnector:
    """Thin wrapper around ERPNext REST API."""

    def __init__(self, base_url: str, api_key: str, api_secret: str,
                 site_name: str = "erp.localhost"):
        self._base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"token {api_key}:{api_secret}",
            "Content-Type": "application/json",
            "Host": site_name,
        }

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self._base_url}{path}"
        resp = httpx.get(url, headers=self._headers, params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: dict) -> dict:
        url = f"{self._base_url}{path}"
        resp = httpx.post(url, headers=self._headers, json=data, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _put(self, path: str, data: dict) -> dict:
        url = f"{self._base_url}{path}"
        resp = httpx.put(url, headers=self._headers, json=data, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    # ── Stock queries ────────────────────────────────────────────────────

    def get_stock_levels(self, warehouse: str | None = None) -> list[StockItem]:
        """Get current stock levels from Bin doctype, joined with reorder info."""
        filters = []
        if warehouse:
            filters.append(["warehouse", "=", warehouse])

        bins = self._get("/api/resource/Bin", {
            "filters": str(filters) if filters else "[]",
            "fields": '["item_code","warehouse","actual_qty","projected_qty"]',
            "limit_page_length": 500,
        })

        items = []
        for b in bins.get("data", []):
            # Fetch item details for reorder info
            item_info = self._get_item_reorder(b["item_code"], b["warehouse"])
            items.append(StockItem(
                item_code=b["item_code"],
                item_name=item_info.get("item_name", b["item_code"]),
                warehouse=b["warehouse"],
                actual_qty=b["actual_qty"],
                reorder_level=item_info.get("reorder_level", 0),
                reorder_qty=item_info.get("reorder_qty", 0),
                unit=item_info.get("stock_uom", "Nos"),
            ))
        return items

    def _get_item_reorder(self, item_code: str, warehouse: str) -> dict:
        """Get reorder levels for an item in a specific warehouse."""
        try:
            item = self._get(f"/api/resource/Item/{item_code}", {
                "fields": '["item_name","stock_uom","reorder_levels"]',
            })
            data = item.get("data", {})
            result = {
                "item_name": data.get("item_name", item_code),
                "stock_uom": data.get("stock_uom", "Nos"),
                "reorder_level": 0,
                "reorder_qty": 0,
            }
            # Find matching warehouse reorder level
            for rl in data.get("reorder_levels", []):
                if rl.get("warehouse") == warehouse:
                    result["reorder_level"] = rl.get("warehouse_reorder_level", 0)
                    result["reorder_qty"] = rl.get("warehouse_reorder_qty", 0)
                    break
            return result
        except Exception as exc:
            _log.warning("Failed to get reorder info for %s: %s", item_code, exc)
            return {"item_name": item_code, "stock_uom": "Nos",
                    "reorder_level": 0, "reorder_qty": 0}

    def get_low_stock_items(self, warehouse: str | None = None) -> list[StockItem]:
        """Return items where actual_qty < reorder_level."""
        all_items = self.get_stock_levels(warehouse)
        return [i for i in all_items if i.reorder_level > 0 and i.actual_qty < i.reorder_level]

    def get_stock_balance(self, item_code: str, warehouse: str) -> float:
        """Get current stock balance for a specific item + warehouse."""
        try:
            resp = self._get("/api/method/erpnext.stock.utils.get_stock_balance", {
                "item_code": item_code,
                "warehouse": warehouse,
            })
            return float(resp.get("message", 0))
        except Exception:
            return 0.0

    # ── Purchase Orders ──────────────────────────────────────────────────

    def create_purchase_order(
        self,
        supplier: str,
        items: list[dict],
        schedule_date: str | None = None,
    ) -> str:
        """Create and submit a Purchase Order.

        items: [{"item_code": "...", "qty": N, "rate": N.NN, "warehouse": "..."}]
        Returns the PO name (e.g. "PO-00001").
        """
        import datetime
        if not schedule_date:
            schedule_date = (datetime.date.today() + datetime.timedelta(days=7)).isoformat()

        po_items = []
        for item in items:
            po_items.append({
                "item_code": item["item_code"],
                "qty": item["qty"],
                "rate": item["rate"],
                "schedule_date": schedule_date,
                "warehouse": item.get("warehouse", "Stores - E"),
            })

        resp = self._post("/api/resource/Purchase Order", {
            "supplier": supplier,
            "items": po_items,
        })
        po_name = resp.get("data", {}).get("name", "unknown")
        _log.info("Created Purchase Order: %s", po_name)

        # Submit the PO (docstatus=1)
        try:
            self._put(f"/api/resource/Purchase Order/{po_name}", {
                "docstatus": 1,
            })
            _log.info("Submitted Purchase Order: %s", po_name)
        except Exception as exc:
            _log.warning("PO created but not submitted: %s — %s", po_name, exc)

        return po_name

    # ── Health check ─────────────────────────────────────────────────────

    def ping(self) -> bool:
        """Check if ERPNext is reachable."""
        try:
            resp = httpx.get(
                f"{self._base_url}/api/method/frappe.client.get_count",
                headers=self._headers,
                params={"doctype": "Item"},
                timeout=5.0,
            )
            return resp.status_code == 200
        except Exception:
            return False
