"""One module per resource. Each module defines ``router = APIRouter(prefix="/api/v1/<resource>", tags=[...])``.

Ownership is listed in docs/api-contract.md. Do not edit another module's routes; add a new module instead.
"""
