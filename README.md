# GPT Quant public research data

This repository serves a public, read-only static research evidence API at `https://l-zeus.github.io/gpt-quant-public-research-data`.

- Data as of: `2026-09-30`; generated at: `2026-10-04T14:16:34+08:00`.
- Daily observations only; no live quote or executable price. `execution_status` is `EXECUTION_DATA_INSUFFICIENT`.
- Static contexts contain no Predictor decision. The existing Custom GPT remains the only reasoning layer.
- The aggressive scan is a preliminary screen. Its score is not a Predictor score, alpha estimate, or recommendation.
- `PIT_STATUS=PIT_APPROXIMATE`, `FRESH_ENABLED=false`, `ALPHA_PROVEN=false`, `AUTO_ORDER=false`.
- Baseline paths return explicit `NOT_AVAILABLE`; dynamic backtest and prediction-record writes are disabled.

The GitHub Actions publishing workflow validates and deploys the committed snapshot when `docs/api/**` changes on `main`, and it remains available for manual dispatch. It does not fetch market data.

The separate `Update static research data` workflow has a weekday 19:00 Asia/Shanghai schedule and a manual refresh/expansion dispatch. Its versioned exchange calendar prevents requests on holidays and before the publication window. The production provider authorization gate is currently closed, so a trading-day run stops before requesting market data; refresh and expansion remain unavailable until an authorized, timestamped provider adapter is configured and verified. Publication remains disabled unless every release gate passes.
