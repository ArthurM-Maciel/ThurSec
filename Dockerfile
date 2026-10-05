# ThurSec — slim runtime image.
#
# Builds a lean image that installs the `thursec` package and exposes the
# `thursec` CLI as the entrypoint. The toolkit's passive modules are
# pure-Python and work out of the box.
#
# Some ACTIVE modules shell out to external binaries that are intentionally
# NOT bundled here, to keep the base image small:
#   - recon.nmap_scan  -> nmap
#   - vuln.nuclei      -> nuclei
# These are optional. If you need those modules, install the binaries in a
# derived image (e.g. `RUN apt-get update && apt-get install -y nmap`) or run
# ThurSec on a host that already has them. The scope gate still applies.
FROM python:3.12-slim

# Don't buffer stdout/stderr, don't write .pyc files.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Copy project metadata and sources, then install (non-editable).
COPY pyproject.toml README.md ./
COPY thursec ./thursec

RUN pip install .

# Run as a non-root user.
RUN useradd --create-home --uid 1000 thursec
USER thursec

ENTRYPOINT ["thursec"]
CMD ["--help"]
