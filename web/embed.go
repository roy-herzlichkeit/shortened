// Package web holds the static page. It is embedded so the API binary serves
// it from the same origin as the API, which the session cookie relies on.
package web

import "embed"

//go:embed index.html app.js style.css
var FS embed.FS
