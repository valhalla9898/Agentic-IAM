from bloome_store import (
    BLOOME_CATALOG,
    STORE_NAME,
    build_consultation_details,
    format_price,
    get_brand_story,
    get_catalog_summary,
    get_featured_products,
)


def test_bloome_catalog_summary_matches_catalog():
    summary = get_catalog_summary()

    assert STORE_NAME == "Bloome"
    assert summary == {category: len(items) for category, items in BLOOME_CATALOG.items()}
    assert sum(summary.values()) >= 8


def test_bloome_featured_products_are_ordered_and_formatted():
    featured = get_featured_products(limit=4)

    assert len(featured) == 4
    assert featured[0].name == "Glow Reset Cleanser"
    assert format_price(featured[0].price_egp) == "EGP 620"
    assert "premium beauty storefront" in get_brand_story().lower()


def test_bloome_consultation_details_include_inputs():
    details = build_consultation_details(
        customer_name="Mona",
        email="mona@example.com",
        product_interest="Perfume",
        skin_concern="Dry skin",
        budget_egp=1800,
    )

    assert "customer=Mona" in details
    assert "email=mona@example.com" in details
    assert "interest=Perfume" in details
    assert "budget_egp=1800" in details
