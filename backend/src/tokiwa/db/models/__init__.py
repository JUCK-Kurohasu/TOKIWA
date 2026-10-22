"""ORM models. Every module in this package is imported automatically so its tables get registered.

Add a new file here for new tables owned by your module instead of editing existing files.
Column names should match the Pydantic schema field names so ``Schema.model_validate(row)`` works.
"""

import importlib
import pkgutil

for _mod in pkgutil.iter_modules(__path__):
    importlib.import_module(f"{__name__}.{_mod.name}")
