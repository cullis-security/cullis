"""
Seed Odoo CE with demo data for the enterprise lab.

Creates:
  - Product category: "Industrial Fasteners"
  - Products with SKUs matching the buyer's inventory
  - Price list with volume discounts
  - Customer partner for ElectroStore

Usage:
  python seed_odoo.py [--url http://localhost:8069] [--db odoo] [--password admin]
"""
import argparse
import sys
import time
import xmlrpc.client

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
CYAN = "\033[36m"
RED = "\033[31m"
YELLOW = "\033[33m"


def ok(msg):
    print(f"  {GREEN}✓{RESET}  {msg}")


def skip(msg):
    print(f"  {YELLOW}→{RESET}  {msg} (already exists)")


def fail(msg):
    print(f"  {RED}✗{RESET}  {msg}")


class OdooSeeder:
    def __init__(self, url: str, db: str, username: str, password: str):
        self._url = url.rstrip("/")
        self._db = db
        self._password = password

        common = xmlrpc.client.ServerProxy(f"{self._url}/xmlrpc/2/common")
        self._uid = common.authenticate(db, username, password, {})
        if not self._uid:
            fail("Odoo authentication failed")
            sys.exit(1)
        self._models = xmlrpc.client.ServerProxy(f"{self._url}/xmlrpc/2/object")
        ok(f"Logged in as {username} (uid={self._uid})")

    def _execute(self, model, method, *args, **kwargs):
        return self._models.execute_kw(
            self._db, self._uid, self._password,
            model, method, list(args), kwargs,
        )

    def _search(self, model, domain, limit=1):
        return self._execute(model, "search", domain, limit=limit)

    def _search_read(self, model, domain, fields, limit=10):
        return self._execute(model, "search_read", domain, fields=fields, limit=limit)

    def create_category(self) -> int:
        """Create product category 'Industrial Fasteners'."""
        existing = self._search("product.category", [["name", "=", "Industrial Fasteners"]])
        if existing:
            skip("Category 'Industrial Fasteners'")
            return existing[0]

        cat_id = self._execute("product.category", "create", {
            "name": "Industrial Fasteners",
        })
        ok("Category 'Industrial Fasteners' created")
        return cat_id

    def create_products(self, categ_id: int) -> dict[str, int]:
        """Create products matching the buyer's inventory SKUs.
        Returns {sku: product_id}."""
        products = [
            {
                "name": "Zinc-plated M8 bolts",
                "default_code": "BLT-M8-ZN",
                "list_price": 0.048,
                "standard_price": 0.025,
                "initial_qty": 85000,
            },
            {
                "name": "Zinc-plated M10 bolts",
                "default_code": "BLT-M10-ZN",
                "list_price": 0.075,
                "standard_price": 0.040,
                "initial_qty": 32000,
            },
            {
                "name": "Stainless M6 screws",
                "default_code": "SCR-M6-IX",
                "list_price": 0.032,
                "standard_price": 0.015,
                "initial_qty": 120000,
            },
            {
                "name": "Stainless M8 flat washers",
                "default_code": "WSH-M8-SS",
                "list_price": 0.018,
                "standard_price": 0.008,
                "initial_qty": 200000,
            },
        ]

        sku_map = {}
        for p in products:
            existing = self._search_read(
                "product.product",
                [["default_code", "=", p["default_code"]]],
                fields=["id"],
            )
            if existing:
                skip(f"Product '{p['default_code']}'")
                sku_map[p["default_code"]] = existing[0]["id"]
                continue

            pid = self._execute("product.product", "create", {
                "name": p["name"],
                "default_code": p["default_code"],
                "list_price": p["list_price"],
                "standard_price": p["standard_price"],
                "categ_id": categ_id,
                "type": "product",  # storable product
                "sale_ok": True,
                "purchase_ok": True,
            })
            sku_map[p["default_code"]] = pid
            ok(f"Product '{p['default_code']}' — {p['name']} (€{p['list_price']}/unit)")

            # Set initial stock via stock.quant
            self._set_stock(pid, p["initial_qty"])

        return sku_map

    def _set_stock(self, product_id: int, qty: float):
        """Set initial stock quantity via inventory adjustment."""
        try:
            # Find the default warehouse
            warehouses = self._search_read(
                "stock.warehouse", [],
                fields=["id", "lot_stock_id"], limit=1,
            )
            if not warehouses:
                return
            location_id = warehouses[0]["lot_stock_id"]
            if isinstance(location_id, list):
                location_id = location_id[0]

            # Create or update quant
            self._execute("stock.quant", "create", {
                "product_id": product_id,
                "location_id": location_id,
                "inventory_quantity": qty,
            })
            # Apply the inventory
            quants = self._search("stock.quant", [
                ["product_id", "=", product_id],
                ["location_id", "=", location_id],
            ])
            if quants:
                self._execute("stock.quant", "action_apply_inventory", [quants])
            ok(f"  Stock: {int(qty)} units")
        except Exception as exc:
            # Stock adjustment methods vary by Odoo version, non-critical
            skip(f"  Stock set skipped: {exc}")

    def create_pricelist_discounts(self, sku_map: dict[str, int]):
        """Create volume discounts on the default pricelist."""
        # Find the default pricelist
        pricelists = self._search_read(
            "product.pricelist", [],
            fields=["id", "name"], limit=1,
        )
        if not pricelists:
            fail("No pricelist found")
            return

        pricelist_id = pricelists[0]["id"]

        discounts = [
            # (sku, min_qty, discount_pct)
            ("BLT-M8-ZN", 500, 5.0),
            ("BLT-M8-ZN", 2000, 10.0),
            ("BLT-M10-ZN", 500, 5.0),
            ("SCR-M6-IX", 5000, 8.0),
            ("WSH-M8-SS", 1000, 5.0),
            ("WSH-M8-SS", 5000, 12.0),
        ]

        for sku, min_qty, discount in discounts:
            product_id = sku_map.get(sku)
            if not product_id:
                continue

            # Check if rule already exists
            existing = self._search("product.pricelist.item", [
                ["pricelist_id", "=", pricelist_id],
                ["product_id", "=", product_id],
                ["min_quantity", "=", min_qty],
            ])
            if existing:
                skip(f"Discount {sku} ≥{min_qty}: {discount}%")
                continue

            self._execute("product.pricelist.item", "create", {
                "pricelist_id": pricelist_id,
                "product_id": product_id,
                "min_quantity": min_qty,
                "compute_price": "percentage",
                "percent_price": discount,
            })
            ok(f"Discount {sku} ≥{min_qty}: {discount}% off")

    def create_customer(self) -> int:
        """Create ElectroStore as a customer partner."""
        existing = self._search_read(
            "res.partner",
            [["ref", "=", "electrostore"]],
            fields=["id"],
        )
        if existing:
            skip("Customer 'ElectroStore'")
            return existing[0]["id"]

        partner_id = self._execute("res.partner", "create", {
            "name": "ElectroStore S.r.l.",
            "ref": "electrostore",
            "customer_rank": 1,
            "country_id": self._get_country_id("IT"),
            "city": "Milan",
        })
        ok("Customer 'ElectroStore S.r.l.' created")
        return partner_id

    def _get_country_id(self, code: str) -> int | None:
        result = self._search("res.country", [["code", "=", code]])
        return result[0] if result else None

    def seed(self) -> dict:
        """Run all seed operations. Returns config dict."""
        print(f"\n{BOLD}Seeding Odoo (ChipFactory){RESET}\n")

        categ_id = self.create_category()
        sku_map = self.create_products(categ_id)
        self.create_pricelist_discounts(sku_map)
        partner_id = self.create_customer()

        config = {
            "odoo_url": self._url,
            "odoo_db": self._db,
            "odoo_user": "admin",
            "odoo_password": self._password,
            "customer_partner_id": partner_id,
            "sku_map": sku_map,
        }

        print(f"\n{BOLD}Odoo config:{RESET}")
        for k, v in config.items():
            if k != "sku_map":
                print(f"  {CYAN}{k}{RESET} = {v}")
        print(f"  {CYAN}products{RESET} = {len(sku_map)} items")
        print()

        return config


def wait_for_odoo(url: str, timeout: int = 120):
    """Wait until Odoo is ready."""
    print(f"  Waiting for Odoo at {url}...", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        try:
            common = xmlrpc.client.ServerProxy(f"{url}/xmlrpc/2/common")
            version = common.version()
            if version:
                print(f" {GREEN}ready (v{version.get('server_version', '?')}){RESET}")
                return
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(3)
    print(f" {RED}timeout{RESET}")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Seed Odoo for enterprise demo")
    parser.add_argument("--url", default="http://localhost:8069", help="Odoo URL")
    parser.add_argument("--db", default="odoo", help="Odoo database name")
    parser.add_argument("--password", default="admin", help="Admin password")
    parser.add_argument("--wait", action="store_true", help="Wait for Odoo to be ready")
    args = parser.parse_args()

    if args.wait:
        wait_for_odoo(args.url)

    seeder = OdooSeeder(args.url, args.db, "admin", args.password)
    seeder.seed()


if __name__ == "__main__":
    main()
