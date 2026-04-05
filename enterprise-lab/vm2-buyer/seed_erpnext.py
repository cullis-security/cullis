"""
Seed ERPNext with demo data for the enterprise lab.

Creates:
  - Warehouse: "Main Warehouse - ES"
  - Supplier: "ChipFactory S.p.A."
  - Items with reorder levels (some below threshold to trigger the buyer agent)
  - Stock entries to set initial quantities
  - API key for the buyer agent

Usage:
  python seed_erpnext.py [--url http://localhost:8080] [--admin-password admin]
"""
import argparse
import sys
import time

import httpx

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
CYAN = "\033[36m"
RED = "\033[31m"
YELLOW = "\033[33m"

BASE_URL = "http://localhost:8080"


def ok(msg):
    print(f"  {GREEN}✓{RESET}  {msg}")


def skip(msg):
    print(f"  {YELLOW}→{RESET}  {msg} (already exists)")


def fail(msg):
    print(f"  {RED}✗{RESET}  {msg}")


class ERPNextSeeder:
    def __init__(self, base_url: str, admin_password: str):
        self._url = base_url.rstrip("/")
        self._session = httpx.Client(timeout=30.0)
        self._login(admin_password)

    def _login(self, password: str):
        """Login as Administrator to get session cookie."""
        resp = self._session.post(f"{self._url}/api/method/login", json={
            "usr": "Administrator",
            "pwd": password,
        })
        if resp.status_code != 200:
            fail(f"Login failed: {resp.status_code} — {resp.text}")
            sys.exit(1)
        ok("Logged in as Administrator")

    def _get(self, path: str, params: dict | None = None):
        resp = self._session.get(f"{self._url}{path}", params=params)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: dict):
        resp = self._session.post(f"{self._url}{path}", json=data)
        return resp

    def _exists(self, doctype: str, name: str) -> bool:
        try:
            self._get(f"/api/resource/{doctype}/{name}")
            return True
        except Exception:
            return False

    def create_company(self):
        """Ensure ElectroStore company exists."""
        if self._exists("Company", "ElectroStore"):
            skip("Company 'ElectroStore'")
            return
        resp = self._post("/api/resource/Company", {
            "company_name": "ElectroStore",
            "abbr": "ES",
            "default_currency": "EUR",
            "country": "Italy",
        })
        if resp.status_code in (200, 201):
            ok("Company 'ElectroStore' created")
        else:
            fail(f"Company: {resp.text}")

    def create_warehouse(self):
        """Create the main warehouse."""
        name = "Main Warehouse - ES"
        if self._exists("Warehouse", name):
            skip(f"Warehouse '{name}'")
            return
        resp = self._post("/api/resource/Warehouse", {
            "warehouse_name": "Main Warehouse",
            "company": "ElectroStore",
        })
        if resp.status_code in (200, 201):
            ok(f"Warehouse '{name}' created")
        else:
            # Might already exist with different naming
            skip(f"Warehouse: {resp.status_code}")

    def create_supplier(self):
        """Create ChipFactory as a supplier."""
        if self._exists("Supplier", "ChipFactory S.p.A."):
            skip("Supplier 'ChipFactory S.p.A.'")
            return
        resp = self._post("/api/resource/Supplier", {
            "supplier_name": "ChipFactory S.p.A.",
            "supplier_group": "Raw Material",
            "country": "Italy",
        })
        if resp.status_code in (200, 201):
            ok("Supplier 'ChipFactory S.p.A.' created")
        else:
            fail(f"Supplier: {resp.text}")

    def create_items(self):
        """Create inventory items with reorder levels."""
        items = [
            {
                "item_code": "BLT-M8-ZN",
                "item_name": "Zinc-plated M8 bolts",
                "item_group": "Raw Material",
                "stock_uom": "Nos",
                "initial_stock": 450,
                "reorder_level": 500,
                "reorder_qty": 5000,
            },
            {
                "item_code": "SCR-M6-IX",
                "item_name": "Stainless M6 screws",
                "item_group": "Raw Material",
                "stock_uom": "Nos",
                "initial_stock": 8000,
                "reorder_level": 2000,
                "reorder_qty": 10000,
            },
            {
                "item_code": "BLT-M10-ZN",
                "item_name": "Zinc-plated M10 bolts",
                "item_group": "Raw Material",
                "stock_uom": "Nos",
                "initial_stock": 120,
                "reorder_level": 200,
                "reorder_qty": 2000,
            },
            {
                "item_code": "WSH-M8-SS",
                "item_name": "Stainless M8 flat washers",
                "item_group": "Raw Material",
                "stock_uom": "Nos",
                "initial_stock": 3000,
                "reorder_level": 1000,
                "reorder_qty": 5000,
            },
        ]

        warehouse = "Main Warehouse - ES"

        for item in items:
            if self._exists("Item", item["item_code"]):
                skip(f"Item '{item['item_code']}'")
                continue

            resp = self._post("/api/resource/Item", {
                "item_code": item["item_code"],
                "item_name": item["item_name"],
                "item_group": item["item_group"],
                "stock_uom": item["stock_uom"],
                "is_stock_item": 1,
                "reorder_levels": [{
                    "warehouse": warehouse,
                    "warehouse_reorder_level": item["reorder_level"],
                    "warehouse_reorder_qty": item["reorder_qty"],
                    "material_request_type": "Purchase",
                }],
            })
            if resp.status_code in (200, 201):
                ok(f"Item '{item['item_code']}' — {item['item_name']}")
                # Create stock entry for initial quantity
                self._create_stock_entry(
                    item["item_code"], item["initial_stock"], warehouse
                )
            else:
                fail(f"Item '{item['item_code']}': {resp.text[:200]}")

    def _create_stock_entry(self, item_code: str, qty: float, warehouse: str):
        """Create a Material Receipt stock entry to set initial quantity."""
        resp = self._post("/api/resource/Stock Entry", {
            "stock_entry_type": "Material Receipt",
            "items": [{
                "item_code": item_code,
                "qty": qty,
                "t_warehouse": warehouse,
                "basic_rate": 1,  # nominal value
            }],
        })
        if resp.status_code in (200, 201):
            se_name = resp.json().get("data", {}).get("name", "?")
            # Submit the stock entry
            try:
                self._session.put(
                    f"{self._url}/api/resource/Stock Entry/{se_name}",
                    json={"docstatus": 1},
                )
            except Exception:
                pass
            ok(f"  Stock: {qty} x {item_code} → {warehouse}")

    def create_api_user(self) -> tuple[str, str]:
        """Create an API user for the buyer agent and return (api_key, api_secret)."""
        user_email = "buyer-agent@electrostore.local"

        if self._exists("User", user_email):
            skip(f"API user '{user_email}'")
            # Try to get existing keys
            try:
                keys = self._get(f"/api/method/frappe.core.doctype.user.user.generate_keys", {
                    "user": user_email,
                })
                api_secret = keys.get("message", {}).get("api_secret", "")
                user = self._get(f"/api/resource/User/{user_email}")
                api_key = user.get("data", {}).get("api_key", "")
                return api_key, api_secret
            except Exception:
                return "", ""

        resp = self._post("/api/resource/User", {
            "email": user_email,
            "first_name": "Buyer",
            "last_name": "Agent",
            "user_type": "System User",
            "roles": [
                {"role": "Stock User"},
                {"role": "Purchase User"},
                {"role": "Purchase Manager"},
            ],
        })
        if resp.status_code not in (200, 201):
            fail(f"API user: {resp.text[:200]}")
            return "", ""

        ok(f"API user '{user_email}' created")

        # Generate API keys
        keys = self._post("/api/method/frappe.core.doctype.user.user.generate_keys", {
            "user": user_email,
        })
        if keys.status_code == 200:
            api_secret = keys.json().get("message", {}).get("api_secret", "")
            user = self._get(f"/api/resource/User/{user_email}")
            api_key = user.get("data", {}).get("api_key", "")
            ok(f"API keys generated")
            return api_key, api_secret

        return "", ""

    def seed(self) -> dict:
        """Run all seed operations. Returns config dict."""
        print(f"\n{BOLD}Seeding ERPNext (ElectroStore){RESET}\n")

        self.create_company()
        self.create_warehouse()
        self.create_supplier()
        self.create_items()
        api_key, api_secret = self.create_api_user()

        config = {
            "erpnext_url": self._url,
            "api_key": api_key,
            "api_secret": api_secret,
            "warehouse": "Main Warehouse - ES",
            "supplier": "ChipFactory S.p.A.",
        }

        print(f"\n{BOLD}ERPNext config:{RESET}")
        for k, v in config.items():
            print(f"  {CYAN}{k}{RESET} = {v}")
        print()

        return config


def wait_for_erpnext(url: str, timeout: int = 120):
    """Wait until ERPNext is ready."""
    print(f"  Waiting for ERPNext at {url}...", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = httpx.get(f"{url}/api/method/frappe.client.get_count",
                             params={"doctype": "DocType"}, timeout=5)
            if resp.status_code == 200:
                print(f" {GREEN}ready{RESET}")
                return
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(3)
    print(f" {RED}timeout{RESET}")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Seed ERPNext for enterprise demo")
    parser.add_argument("--url", default=BASE_URL, help="ERPNext URL")
    parser.add_argument("--admin-password", default="admin", help="Admin password")
    parser.add_argument("--wait", action="store_true", help="Wait for ERPNext to be ready")
    args = parser.parse_args()

    if args.wait:
        wait_for_erpnext(args.url)

    seeder = ERPNextSeeder(args.url, args.admin_password)
    seeder.seed()


if __name__ == "__main__":
    main()
