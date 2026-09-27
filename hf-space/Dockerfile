# AutoBounty on HuggingFace Spaces — a free, persistent parallel runner node.
# It runs the autopilot loop here and syncs state to the GitHub repo, so coverage
# accumulates in parallel with the GitHub Actions runner and the Termux box.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      golang-go git ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir requests pyyaml

# Pull the accumulated state from the GitHub repo so this node continues
# where the others left off (git is the shared database).
ARG GIT_REPO_URL=""
RUN if [ -n "$GIT_REPO_URL" ]; then \
      git clone --depth 1 "$GIT_REPO_URL" /state && \
      cp -r /state/data /state/reports /app/ 2>/dev/null || true ; \
    fi

ENV PYTHONUNBUFFERED=1
CMD ["python3", "autopilot.py"]
