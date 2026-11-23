package migrations

import "embed"

// FS embeds all SQL migration files in execution order.
//
//go:embed *.sql
var FS embed.FS
