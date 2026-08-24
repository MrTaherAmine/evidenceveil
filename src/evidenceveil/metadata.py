from __future__ import annotations

PRODUCT_NAME = "EvidenceVeil"
TAGLINE = "Share incident data without exposing the incident."
AUTHOR_NAME = "Taher Amine ELHOUARI"
MAINTAINER_NAME = AUTHOR_NAME
WEBSITE = "https://www.taheramine.org"
GITHUB_HANDLE = "MrTaherAmine"
REPOSITORY = "https://github.com/MrTaherAmine/evidenceveil"
LICENSE_ID = "Apache-2.0"
COPYRIGHT = "Copyright 2026 Taher Amine ELHOUARI"


def attribution_dict() -> dict[str, str]:
    return {
        "author": AUTHOR_NAME,
        "maintainer": MAINTAINER_NAME,
        "website": WEBSITE,
        "github": GITHUB_HANDLE,
        "repository": REPOSITORY,
        "license": LICENSE_ID,
        "copyright": COPYRIGHT,
    }
