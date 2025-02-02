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

	data := struct {
		Title string
	}{
		Title: "SSL Certificate Checker",
	}

	tmpl := template.Must(template.New("home").Parse(templates.HomeTemplate))
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}