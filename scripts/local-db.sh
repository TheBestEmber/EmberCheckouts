#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
pg_bin=${PG_BIN:-"$(brew --prefix postgresql@17)/bin"}
data_dir="$root/.local/postgres"
log_file="$root/.local/postgres.log"
port=${POSTGRES_PORT:-55432}

export PATH="$pg_bin:$PATH"

start() {
	mkdir -p "$root/.local"
	if [ ! -f "$data_dir/PG_VERSION" ]; then
		initdb -D "$data_dir" --username=ember --auth=trust >/dev/null
	fi
	if ! pg_ctl -D "$data_dir" status >/dev/null 2>&1; then
		pg_ctl -D "$data_dir" -l "$log_file" -o "-h 127.0.0.1 -p $port" start >/dev/null
	fi
	exists=$(psql -h 127.0.0.1 -p "$port" -U ember -d postgres -tAc \
		"SELECT 1 FROM pg_database WHERE datname = 'ember_checkouts'")
	if [ "$exists" != "1" ]; then
		createdb -h 127.0.0.1 -p "$port" -U ember ember_checkouts
	fi
	for migration in "$root"/migrations/*.sql; do
		psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$port" -U ember \
			-d ember_checkouts -f "$migration" >/dev/null
	done
	echo "PostgreSQL ready on 127.0.0.1:$port"
}

case "${1:-start}" in
	start)
		start
		;;
	stop)
		if [ -f "$data_dir/PG_VERSION" ] && pg_ctl -D "$data_dir" status >/dev/null 2>&1; then
			pg_ctl -D "$data_dir" stop >/dev/null
		fi
		;;
	status)
		pg_ctl -D "$data_dir" status
		;;
	*)
		echo "usage: $0 [start|stop|status]" >&2
		exit 2
		;;
esac
