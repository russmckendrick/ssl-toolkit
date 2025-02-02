package certificate

import (
	"fmt"
	"time"
)

func GenerateExpiryReminder(domain string, expiryDate time.Time) []byte {
	// Set reminder for 30 days before expiry
	reminderDate := expiryDate.AddDate(0, 0, -30)
	
	// Generate unique identifier
	uid := fmt.Sprintf("cert-expiry-%s-%d@ssl-toolkit", domain, expiryDate.Unix())
	
	// Create iCal content
	ical := fmt.Sprintf(`BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//SSL Toolkit//Certificate Expiry Reminder//EN
BEGIN:VEVENT
UID:%s
DTSTAMP:%s
DTSTART:%s
DTEND:%s
SUMMARY:SSL Certificate Expiry Reminder for %s
DESCRIPTION:The SSL certificate for %s will expire in 30 days (on %s).\n\nPlease ensure you renew the certificate before the expiry date to avoid any service disruption.
BEGIN:VALARM
TRIGGER:-P7D
ACTION:DISPLAY
DESCRIPTION:SSL Certificate Expiry Reminder
END:VALARM
END:VEVENT
END:VCALENDAR`,
		uid,
		time.Now().UTC().Format("20060102T150405Z"),
		reminderDate.UTC().Format("20060102T150405Z"),
		reminderDate.UTC().Add(1*time.Hour).Format("20060102T150405Z"),
		domain,
		domain,
		expiryDate.Format("2006-01-02"),
	)
	
	return []byte(ical)
} 