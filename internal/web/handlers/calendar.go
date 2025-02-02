package handlers

import (
    "fmt"
    "net/http"
    
    "github.com/russmckendrick/ssl-toolkit/internal/certificate"
    "github.com/russmckendrick/ssl-toolkit/internal/utils"
)

// HandleCalendarReminder handles requests to download the calendar reminder
func HandleCalendarReminder(w http.ResponseWriter, r *http.Request) {
    fmt.Printf("Calendar reminder handler called for URL: %s\n", r.URL.String())
    domain := r.URL.Query().Get("domain")
    if domain == "" {
        fmt.Printf("No domain parameter provided\n")
        http.Error(w, "Domain parameter is required", http.StatusBadRequest)
        return
    }

    domain, err := utils.CleanDomain(domain)
    if err != nil {
        http.Error(w, "Invalid domain: "+err.Error(), http.StatusBadRequest)
        return
    }

    // Get certificate information
    certInfo, err := certificate.GetCertificateInfo(domain)
    if err != nil {
        http.Error(w, "Error getting certificate: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Generate iCal content
    icalContent := certificate.GenerateExpiryReminder(domain, certInfo.NotAfter)

    // Set headers for iCal download
    w.Header().Set("Content-Type", "text/calendar")
    w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-cert-expiry.ics"`, domain))
    
    w.Write(icalContent)
} 