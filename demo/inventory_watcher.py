"""
Inventory Watcher — simulates an ERP trigger.

Monitors inventory.json every N seconds. When an item's stock drops below
its reorder_threshold, launches the buyer agent as a subprocess.

This is what the customer's IT team would replace with their real ERP
integration (SAP event, Kafka consumer, database trigger, etc.).

Usage:
  python demo/inventory_watcher.py
"""
import json
import subprocess
import sys
import time
from pathlib import Path

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
RED    = "\033[31m"
GRAY   = "\033[90m"

INVENTORY_PATH = Path(__file__).parent / "inventory.json"
BUYER_SCRIPT   = Path(__file__).parent / "buyer_agent.py"
CHECK_INTERVAL = 5  # seconds

# Track which items we already triggered (don't re-trigger on same run)
_triggered: set[str] = set()


def load_inventory() -> tuple[str, list[dict]]:
    data = json.loads(INVENTORY_PATH.read_text())
    return data["buyer_agent_config"], data["items"]


def check_low_stock(items: list[dict]) -> list[dict]:
    """Return items where stock < reorder_threshold and not yet triggered."""
    low = []
    for item in items:
        if item["sku"] in _triggered:
            continue
        if item["stock"] < item["reorder_threshold"]:
            low.append(item)
    return low


def trigger_buyer(item: dict, agent_config: str) -> None:
    """Launch the buyer agent for a specific item."""
    sku      = item["sku"]
    name     = item["name"]
    quantity = item["reorder_quantity"]
    supplier = item.get("preferred_supplier_org", "")

    print(f"  {RED}{BOLD}ALERT{RESET}  {name} ({sku}): stock={item['stock']} < threshold={item['reorder_threshold']}")
    print(f"  {CYAN}>{RESET}  Launching buyer agent: {quantity} x {name} from {supplier}")
    print()

    _triggered.add(sku)

    cmd = [
        sys.executable,
        str(BUYER_SCRIPT),
        "--config", agent_config,
        "--sku", sku,
        "--item", name,
        "--quantity", str(quantity),
        "--supplier-org", supplier,
    ]
    subprocess.Popen(cmd)


def main():
    print(f"\n{BOLD}{'='*50}{RESET}")
    print(f"{BOLD}  Inventory Watcher — ERP Trigger Simulator{RESET}")
    print(f"{BOLD}{'='*50}{RESET}")
    print(f"  Monitoring: {INVENTORY_PATH}")
    print(f"  Interval:   {CHECK_INTERVAL}s")
    print(f"{BOLD}{'='*50}{RESET}\n")

    while True:
        try:
            agent_config, items = load_inventory()
            low = check_low_stock(items)

            if low:
                for item in low:
                    trigger_buyer(item, agent_config)
            else:
                now = time.strftime("%H:%M:%S")
                print(f"  {GRAY}[{now}] All stock levels OK{RESET}", end="\r")

            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print(f"\n\n  {YELLOW}Watcher stopped.{RESET}\n")
            break
        except Exception as e:
            print(f"  {RED}Error: {e}{RESET}")
            time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
