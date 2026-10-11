// fp-go-sql.go: Go database/sql with placeholders — SAFE
package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")
	// SAFE: parameterized query with placeholders
	row := db.QueryRow("SELECT * FROM users WHERE id = $1", userId)
	_ = row
}
