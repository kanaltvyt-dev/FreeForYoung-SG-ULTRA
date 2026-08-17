# FreeForYoung SG ULTRA

Singapore-only public-node aggregator.

Pipeline:
1. Collect from several public feeds.
2. GeoIP filter to Singapore.
3. Exclude common CDN/edge IPs.
4. TCP-check candidates.
5. Start a real Xray local SOCKS proxy for the best candidates.
6. Send real HTTPS requests through Xray.
7. Publish only nodes that pass the real proxy test.
8. Refresh hourly.

Outputs:
- output/singapore.txt
- output/singapore-base64.txt
- output/singapore-stats.json

The real proxy test runs from GitHub Actions. It proves a node can forward
real HTTPS traffic from the runner at build time; it does not guarantee
availability from every ISP in Russia.
