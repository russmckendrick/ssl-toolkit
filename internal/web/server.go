package web

import (
	"fmt"
	"net/http"

	"github.com/russmckendrick/ssl-toolkit/internal/web/handlers"
)

// Server represents the web server
type Server struct {
	Router *http.ServeMux
}

// NewServer creates a new web server instance
func NewServer() *Server {
	return &Server{
		Router: http.NewServeMux(),
	}
}

// SetupRoutes configures all the routes for the web server
func (s *Server) SetupRoutes() {
	fmt.Printf("Setting up routes...\n")
	// Add routes
	s.Router.HandleFunc("/", handlers.HandleHome)
	s.Router.HandleFunc("/check", handlers.HandleCheck)
	s.Router.HandleFunc("/download-chain", handlers.HandleDownloadChain)
	s.Router.HandleFunc("/calendar-reminder", handlers.HandleCalendarReminder)
	fmt.Printf("Routes registered: /, /check, /download-chain, /calendar-reminder\n")
}

// Start starts the web server
func (s *Server) Start(addr string) error {
	return http.ListenAndServe(addr, s.Router)
} 