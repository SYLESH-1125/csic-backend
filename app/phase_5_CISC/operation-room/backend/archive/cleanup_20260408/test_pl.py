import polars as pl
import datetime

data = [
    {"actor": "A", "ts": "2026-04-04T10:00:00Z", "id": 1},
    {"actor": "A", "ts": "2026-04-04T10:01:00Z", "id": 2},
    {"actor": "A", "ts": "2026-04-04T10:06:00Z", "id": 3}
]
df = pl.DataFrame(data)
df = df.with_columns(pl.col("ts").str.replace("Z", "+00:00").str.to_datetime(strict=False))
df = df.sort("ts")
res = df.rolling(index_column="ts", by="actor", period="5m").agg(
    pl.count("id").alias("count"),
    pl.col("id").alias("ids")
)
print(res)
