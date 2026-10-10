.PHONY: bootstrap up down logs migrate test race vet fmt

bootstrap:
	cp -n .env.example .env
	@key=$$(openssl rand -base64 32); \
		perl -i -pe "s|REPLACE_WITH_BASE64_32_BYTE_KEY|$$key|" .env

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f api

migrate:
	docker compose run --rm migrate

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')
