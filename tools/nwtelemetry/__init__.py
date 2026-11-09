"""Northwind pipeline telemetry: ship scanner findings and CI job events to
OpenSearch, and report trends from it.

Standard library only, so it runs in any python:3 image and offline.

  python -m nwtelemetry.ship       (CI report job) normalise reports, ship them
  python -m nwtelemetry.trend      trend report: --since 7d --format table|json
  python -m nwtelemetry.dashboard  print the Dashboards saved objects (ndjson)
"""
