"""
Odoo CE Connector — wraps the XML-RPC API for catalog and sales.

Used by the supplier agent to:
  1. Read product catalog (product.product)
  2. Read price lists (product.pricelist.item)
  3. Create Sale Orders from confirmed negotiations

Authentication: XML-RPC with database, username, password.

Usage:
    crm = OdooConnector("http://odoo:8069", "odoo", "admin", "admin")
    catalog = crm.get_catalog()
    crm.create_sale_order(partner_id=7, lines=[{"product_id": 1, "qty": 100, "price": 0.045}])
"""
import logging
import xmlrpc.client
from dataclasses import dataclass, field

_log = logging.getLogger("agent_trust.crm")


@dataclass
class CatalogProduct:
    product_id: int
    name: str
    default_code: str  # SKU / internal reference
    list_price: float
    qty_available: float
    uom: str
    categ: str
    discounts: dict = field(default_factory=dict)  # qty_threshold -> discount_pct


class OdooConnector:
    """Thin wrapper around Odoo CE XML-RPC API."""

    def __init__(self, url: str, db: str, username: str, password: str):
        self._url = url.rstrip("/")
        self._db = db
        self._username = username
        self._password = password
        self._uid: int | None = None
        self._models: xmlrpc.client.ServerProxy | None = None

    def _connect(self) -> None:
        """Authenticate and cache uid + models proxy."""
        if self._uid is not None:
            return
        common = xmlrpc.client.ServerProxy(f"{self._url}/xmlrpc/2/common")
        self._uid = common.authenticate(self._db, self._username, self._password, {})
        if not self._uid:
            raise RuntimeError(f"Odoo authentication failed for user '{self._username}'")
        self._models = xmlrpc.client.ServerProxy(f"{self._url}/xmlrpc/2/object")
        _log.info("Connected to Odoo (uid=%d)", self._uid)

    def _execute(self, model: str, method: str, *args, **kwargs):
        """Execute an Odoo RPC call."""
        self._connect()
        return self._models.execute_kw(
            self._db, self._uid, self._password,
            model, method, list(args), kwargs,
        )

    # ── Catalog ──────────────────────────────────────────────────────────

    def get_catalog(self, only_saleable: bool = True) -> list[CatalogProduct]:
        """Read all saleable products from Odoo."""
        domain = [["sale_ok", "=", True]] if only_saleable else []

        products = self._execute(
            "product.product", "search_read",
            domain,
            fields=["name", "default_code", "lst_price", "qty_available",
                     "uom_id", "categ_id", "type"],
            limit=200,
        )

        # Load pricelist discounts
        discounts = self._get_pricelist_discounts()

        catalog = []
        for p in products:
            if p.get("type") != "product":  # skip services and consumables
                continue
            product_id = p["id"]
            catalog.append(CatalogProduct(
                product_id=product_id,
                name=p.get("name", ""),
                default_code=p.get("default_code") or "",
                list_price=p.get("lst_price", 0.0),
                qty_available=p.get("qty_available", 0.0),
                uom=p.get("uom_id", [0, "Unit"])[1] if isinstance(p.get("uom_id"), list) else "Unit",
                categ=p.get("categ_id", [0, ""])[1] if isinstance(p.get("categ_id"), list) else "",
                discounts=discounts.get(product_id, {}),
            ))

        _log.info("Loaded %d products from Odoo catalog", len(catalog))
        return catalog

    def get_product_by_sku(self, sku: str) -> CatalogProduct | None:
        """Find a product by its internal reference (default_code / SKU)."""
        catalog = self.get_catalog()
        for p in catalog:
            if p.default_code == sku:
                return p
        return None

    def _get_pricelist_discounts(self) -> dict[int, dict]:
        """Load volume discounts from the default pricelist.

        Returns: {product_id: {min_qty: discount_pct, ...}}
        """
        try:
            items = self._execute(
                "product.pricelist.item", "search_read",
                [["pricelist_id.name", "=", "Public Pricelist"]],
                fields=["product_id", "product_tmpl_id", "min_quantity",
                         "percent_price", "compute_price", "fixed_price"],
                limit=500,
            )

            discounts: dict[int, dict] = {}
            for item in items:
                if item.get("compute_price") != "percentage":
                    continue
                pid = item.get("product_id")
                if isinstance(pid, list):
                    pid = pid[0]
                if not pid:
                    continue
                discounts.setdefault(pid, {})
                min_qty = int(item.get("min_quantity", 0))
                discounts[pid][str(min_qty)] = item.get("percent_price", 0)

            return discounts
        except Exception as exc:
            _log.warning("Failed to load pricelist discounts: %s", exc)
            return {}

    # ── Sale Orders ──────────────────────────────────────────────────────

    def create_sale_order(
        self,
        partner_id: int,
        lines: list[dict],
        confirm: bool = True,
    ) -> int:
        """Create a Sale Order in Odoo.

        lines: [{"product_id": int, "qty": float, "price": float}]
        Returns the sale.order ID.
        """
        order_lines = []
        for line in lines:
            order_lines.append((0, 0, {
                "product_id": line["product_id"],
                "product_uom_qty": line["qty"],
                "price_unit": line["price"],
            }))

        order_id = self._execute(
            "sale.order", "create",
            {
                "partner_id": partner_id,
                "order_line": order_lines,
            },
        )
        _log.info("Created Odoo Sale Order: %d", order_id)

        if confirm:
            try:
                self._execute("sale.order", "action_confirm", [order_id])
                _log.info("Confirmed Sale Order: %d", order_id)
            except Exception as exc:
                _log.warning("SO created but not confirmed: %d — %s", order_id, exc)

        return order_id

    def get_or_create_partner(self, name: str, org_id: str) -> int:
        """Find or create a customer partner by org_id."""
        existing = self._execute(
            "res.partner", "search_read",
            [[["ref", "=", org_id]]],
            fields=["id", "name"],
            limit=1,
        )
        if existing:
            return existing[0]["id"]

        partner_id = self._execute(
            "res.partner", "create",
            {"name": name, "ref": org_id, "customer_rank": 1},
        )
        _log.info("Created Odoo partner: %s (id=%d)", name, partner_id)
        return partner_id

    # ── Health check ─────────────────────────────────────────────────────

    def ping(self) -> bool:
        """Check if Odoo is reachable."""
        try:
            common = xmlrpc.client.ServerProxy(
                f"{self._url}/xmlrpc/2/common",
            )
            version = common.version()
            return bool(version)
        except Exception:
            return False
