package handlers

import (
	"html/template"
	"net/http"

	"github.com/russmckendrick/ssl-toolkit/internal/web/templates"
)

func HandleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmpl := template.Must(template.New("home").Parse(templates.BaseTemplate))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
} 