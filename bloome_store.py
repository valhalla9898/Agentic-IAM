"""Bloome storefront data and helper utilities.

This module keeps the storefront content and business helpers separate from the
Streamlit UI so they can be tested without launching the app.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


STORE_NAME = "Bloome"


@dataclass(frozen=True)
class BloomeProduct:
    name: str
    category: str
    price_egp: int
    description: str
    skin_type: str = "All skin types"
    size: str = ""
    badge: str = ""


BLOOME_CATALOG: Dict[str, List[BloomeProduct]] = {
    "Skin Care": [
        BloomeProduct(
            name="Glow Reset Cleanser",
            category="Skin Care",
            price_egp=620,
            description="Gentle daily cleanser with niacinamide and green tea.",
            skin_type="Normal / Oily",
            size="150ml",
            badge="Best Seller",
        ),
        BloomeProduct(
            name="Velvet Barrier Moisturizer",
            category="Skin Care",
            price_egp=980,
            description="Ceramide-rich moisturizer for calm, hydrated skin.",
            skin_type="Dry / Sensitive",
            size="50ml",
            badge="Hydration",
        ),
        BloomeProduct(
            name="Radiance SPF Fluid",
            category="Skin Care",
            price_egp=1120,
            description="Lightweight SPF 50 with a satin finish and no white cast.",
            skin_type="All skin types",
            size="40ml",
            badge="Daily SPF",
        ),
    ],
    "Perfume": [
        BloomeProduct(
            name="Noor Eau de Parfum",
            category="Perfume",
            price_egp=1850,
            description="Warm amber, white musk, and a soft citrus opening.",
            size="50ml",
            badge="Signature",
        ),
        BloomeProduct(
            name="Bloom Noir",
            category="Perfume",
            price_egp=2100,
            description="Modern floral-woody scent with jasmine and cedar.",
            size="75ml",
            badge="New Arrival",
        ),
        BloomeProduct(
            name="Velour Mist",
            category="Perfume",
            price_egp=1250,
            description="Fresh powdery mist for an everyday clean presence.",
            size="100ml",
            badge="Everyday",
        ),
    ],
    "Bundles": [
        BloomeProduct(
            name="The Morning Ritual",
            category="Bundles",
            price_egp=1980,
            description="Cleanser, moisturizer, and SPF together for a full routine.",
            size="3 items",
            badge="Starter Kit",
        ),
        BloomeProduct(
            name="Gift of Glow Set",
            category="Bundles",
            price_egp=2990,
            description="Perfume + skincare duo with premium packaging.",
            size="2 items",
            badge="Gift Ready",
        ),
    ],
}


def format_price(price_egp: int) -> str:
    return f"EGP {price_egp:,}"


def get_featured_products(limit: int = 4) -> List[BloomeProduct]:
    products: List[BloomeProduct] = []
    for category in ("Skin Care", "Perfume", "Bundles"):
        products.extend(BLOOME_CATALOG.get(category, []))
    return products[:limit]


def get_catalog_summary() -> Dict[str, int]:
    return {category: len(items) for category, items in BLOOME_CATALOG.items()}


def build_consultation_details(
    customer_name: str,
    email: str,
    product_interest: str,
    skin_concern: str,
    budget_egp: int,
) -> str:
    return (
        f"customer={customer_name}; email={email}; interest={product_interest}; "
        f"concern={skin_concern}; budget_egp={budget_egp}"
    )


def get_brand_story() -> str:
    return (
        "Bloome is a premium beauty storefront focused on skincare routines, "
        "signature perfumes, and giftable bundles with clear pricing and "
        "concierge-style consultation."
    )
