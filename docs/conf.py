# Sphinx configuration for the igloo_driver documentation.
#
# Design notes:
#   * Plain `sphinx-build docs/ _build/` builds the whole site — no Docker, no
#     running kernel. This differs from Penguin (which builds its docs from a
#     live runtime image to introspect Python plugins); igloo_driver is pure C
#     with no runtime doc path, so a static build is correct and simpler.
#   * The C API reference is auto-extracted from src/ by Doxygen and rendered
#     through Breathe. Doxygen is invoked HERE, at conf import time, so a bare
#     sphinx-build is self-contained (RTD-style pattern).
#   * Theme/extension choices mirror Penguin's generated conf.py (furo, MyST,
#     copybutton, sphinxemoji) so the two sites read as a family.

import os
import subprocess
from pathlib import Path

# -- Paths -------------------------------------------------------------------
DOCS_DIR = Path(__file__).resolve().parent
REPO_ROOT = DOCS_DIR.parent
SRC_DIR = REPO_ROOT / "src"
DOXYGEN_OUTPUT = DOCS_DIR / "_doxygen"
DOXYGEN_XML = DOXYGEN_OUTPUT / "xml"

# -- Project information -----------------------------------------------------
project = "igloo_driver"
author = "The IGLOO / Penguin rehosting team"
copyright = "The IGLOO / Penguin rehosting team"

# Version: prefer an explicitly injected value (CI passes the release tag),
# else leave unset — there is no in-tree version file to read.
release = os.environ.get("IGLOO_DRIVER_VERSION", "")
version = release

# -- Run Doxygen -------------------------------------------------------------
def run_doxygen():
    """Generate Doxygen XML from src/ so Breathe has something to read.

    Runs unless IGLOO_DOCS_SKIP_DOXYGEN is set (useful when iterating on prose
    and the XML is already present)."""
    if os.environ.get("IGLOO_DOCS_SKIP_DOXYGEN"):
        return
    env = dict(os.environ)
    env["DOXYGEN_INPUT"] = str(SRC_DIR)
    env["DOXYGEN_OUTPUT"] = str(DOXYGEN_OUTPUT)
    DOXYGEN_OUTPUT.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["doxygen", str(DOCS_DIR / "Doxyfile")],
            cwd=str(DOCS_DIR),
            env=env,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        # Don't hard-fail the whole build if Doxygen is missing locally; the
        # Breathe directives will emit their own (visible) errors instead.
        print(f"WARNING: Doxygen did not run cleanly: {e}")


run_doxygen()

# -- General configuration ---------------------------------------------------
extensions = [
    "myst_parser",
    "breathe",
    "sphinx_copybutton",
    "sphinxemoji.sphinxemoji",
    "notfound.extension",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "_doxygen", "Thumbs.db", ".DS_Store"]

source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
master_doc = "index"
language = "en"

# -- Breathe -----------------------------------------------------------------
breathe_projects = {"igloo_driver": str(DOXYGEN_XML)}
breathe_default_project = "igloo_driver"
breathe_domain_by_extension = {"h": "c", "c": "c"}
breathe_show_include = False

# -- MyST --------------------------------------------------------------------
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "fieldlist",
    "attrs_inline",
    "substitution",
    "linkify",
    "smartquotes",
    "replacements",
    "tasklist",
    "html_image",
]
myst_heading_anchors = 3

# -- HTML output -------------------------------------------------------------
html_theme = "furo"
html_static_path = ["_static"]
html_title = "igloo_driver docs"
html_theme_options = {
    "sidebar_hide_name": False,
    "navigation_with_keys": True,
}

# -- LaTeX / PDF output ------------------------------------------------------
latex_engine = "pdflatex"
latex_documents = [
    (master_doc, "igloo_driver.tex", "igloo_driver Documentation", author, "manual"),
]

# -- Warning hygiene ---------------------------------------------------------
# Keep the build clean without turning off useful signal. These are the same
# categories of noise Penguin suppresses (MyST cross-ref heuristics, Pygments
# highlight failures on pseudo-code).
suppress_warnings = [
    "misc.highlighting_failure",
    "myst.header",
    "myst.xref_missing",
]
