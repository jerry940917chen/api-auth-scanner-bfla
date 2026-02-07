.PHONY: demo-up demo-down demo-scan

demo-up:
	docker-compose up -d --build

demo-down:
	docker-compose down -v

demo-scan:
	pwsh ./scripts/demo_scan_vampi.ps1
