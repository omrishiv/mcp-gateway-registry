---
name: search-benchmark
description: Generate a search quality benchmark for the AI Registry. Generates ground truth from the registry's assets, runs 100+ queries against the semantic search API, evaluates results using NDCG@10/MRR/Recall, and produces a markdown report. Use when you want to measure search quality after changes to the scoring algorithm, embedding model, or indexed content.
license: Apache-2.0
metadata:
  author: mcp-gateway-registry
  version: "1.0"
---

# Search Benchmark Skill

Measure semantic search quality against a deployed AI Registry. Generates a ground truth dataset from the registry's own assets, runs queries against the live API, evaluates results using standard information retrieval metrics (NDCG@10, MRR, Recall@10), and produces a markdown report.

## Prerequisites

1. **Registry URL** - The base URL of the deployed registry (e.g., `https://d2xl2zfuhgc4l0.cloudfront.net`)
2. **JWT Token** - A valid admin token in `.token` file (get from "Get JWT Token" button in registry UI)
3. **Registry must have assets indexed** - At least some servers, agents, or skills registered

The `.token` file supports both raw JWT format and the full JSON response from the registry UI.

## Input

```
/search-benchmark [REGISTRY_URL] [TOKEN_FILE]
```

- **REGISTRY_URL** - Base URL of the registry to benchmark (default: reads from user or uses `http://localhost`)
- **TOKEN_FILE** - Path to the token file (default: `.token`)

## Workflow

### Step 1: Check for Existing Ground Truth

Check if a ground truth dataset already exists:

```bash
ls tests/fixtures/search_dataset/generated_ground_truth.json 2>/dev/null
```

If the file exists, ask the user: "A ground truth dataset already exists (N queries). Do you want to use it or generate a new one from the registry?"

- If **use existing**: skip to Step 2
- If **generate new**: proceed to generate

### Step 1b: Generate Ground Truth (if needed)

Generate a ground truth dataset from the registry's assets. This pulls all servers, agents, and skills and creates test queries from their names, tags, and descriptions.

```bash
uv run python scripts/benchmark_search.py \
    --url {REGISTRY_URL} \
    --token-file {TOKEN_FILE} \
    --generate-ground-truth
```

Output: `tests/fixtures/search_dataset/generated_ground_truth.json`

Tell the user how many queries were generated and across which categories. Note that these are programmatically generated queries (a starting point, not a substitute for hand-curated queries).

### Step 2: Run Benchmark

Run all queries against the live semantic search API and generate a report:

```bash
uv run python scripts/benchmark_search.py \
    --url {REGISTRY_URL} \
    --token-file {TOKEN_FILE} \
    --queries tests/fixtures/search_dataset/generated_ground_truth.json
```

Output:
- `tests/fixtures/search_dataset/benchmark_results.json` (raw results)
- `tests/fixtures/search_dataset/benchmark_results.md` (markdown report)

### Step 3: Review Report

Show the user the key metrics from the report:

1. **Quality Metrics** - NDCG@10 > 0.7 is good, > 0.8 is excellent
2. **Score Health** - Saturated scores at 1.0 should be < 15% (if higher, scoring formula may have issues)
3. **Quality by Category** - Identify weak areas (e.g., agent-focused queries underperforming)
4. **Per-query results** - Check specific queries that scored 0.0 (complete miss) or low NDCG

Open the report in the editor for the user to review.

### Step 4: Compare Before/After (Optional)

If asked to compare two runs (e.g., before and after a scoring algorithm change):

```bash
uv run python scripts/benchmark_search.py \
    --compare tests/fixtures/search_dataset/benchmark_results.json other_results.json
```

## Output Format

The report includes:

- **Registry metadata**: version, database backend, server/agent/skill counts
- **Quality Metrics**: NDCG@10, MRR, Recall@10 averaged across all queries
- **Score Health**: saturation analysis (unique scores, % at 1.0, range)
- **Quality by Category**: breakdown per query type
- **Per-query results**: top 5 results with scores and ground truth comparison

## Interpreting Metrics

| Metric | Good | Excellent | Poor |
|--------|------|-----------|------|
| NDCG@10 | > 0.65 | > 0.80 | < 0.50 |
| MRR | > 0.70 | > 0.85 | < 0.50 |
| Recall@10 | > 0.75 | > 0.90 | < 0.60 |
| Score saturation | < 15% | < 5% | > 30% |

## Example

```
$ /search-benchmark https://d2xl2zfuhgc4l0.cloudfront.net .token
```

This will:
1. Generate ~90 queries from the registry's assets
2. Run each query against the semantic search API
3. Produce a report showing search quality metrics
4. Open the report for review

## Troubleshooting

- **401 errors**: Token expired. Get a fresh one from the registry UI "Get JWT Token" button.
- **0 assets found**: Registry has no servers/agents/skills registered, or token lacks permissions.
- **Low NDCG on "description-derived" category**: Expected for programmatically generated queries. Add hand-curated queries for better evaluation.
- **High saturation (>30% at 1.0)**: Scoring formula may be using the legacy additive method. Set `SEARCH_FUSION_METHOD=rrf` on the registry.

## Related

- [Search Evaluation Harness README](tests/fixtures/search_dataset/README.md) - Full documentation on the evaluation system
- [Search Quality Benchmark (reference)](docs/benchmarks/search_quality_benchmark.md) - Sample results from development registry
- [Hybrid Search Architecture](docs/design/hybrid-search-architecture.md) - How scoring works
