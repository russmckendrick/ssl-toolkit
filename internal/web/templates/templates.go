package templates

const (
	HomeTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>SSL Certificate Checker</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 p-8">
    <div class="max-w-2xl mx-auto">
        <h1 class="text-3xl font-bold mb-8">SSL Certificate Checker 🔒</h1>
        <form action="/check" method="GET" class="mb-8">
            <div class="flex gap-4">
                <input type="text" name="domain" placeholder="Enter domain (e.g., example.com)" 
                    class="flex-1 p-2 border rounded">
                <button type="submit" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                    Check Certificate
                </button>
            </div>
        </form>
    </div>
</body>
</html>
`

	ResultTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>SSL Certificate Check Results - {{.Domain}}</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 p-8">
    <div class="max-w-4xl mx-auto">
        <div class="flex justify-between items-center mb-8">
            <h1 class="text-3xl font-bold">Results for {{.Domain}} 🔍</h1>
            <a href="/" class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">New Check</a>
        </div>

        {{if .Certificate}}
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 class="text-2xl font-bold mb-4">🔒 SSL Certificate Information</h2>
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <p class="font-semibold">Issuer:</p>
                    <p>{{.Certificate.Issuer.CommonName}}</p>
                </div>
                <div>
                    <p class="font-semibold">Valid From:</p>
                    <p>{{.Certificate.NotBefore.Format "2006-01-02 15:04:05 UTC"}}</p>
                </div>
                <div>
                    <p class="font-semibold">Valid Until:</p>
                    <p>{{.Certificate.NotAfter.Format "2006-01-02 15:04:05 UTC"}}</p>
                </div>
                <div>
                    <p class="font-semibold">Status:</p>
                    <p>{{if .Certificate.IsValid}}
                        <span class="text-green-600">✅ Valid and Trusted</span>
                    {{else}}
                        <span class="text-red-600">❌ Invalid</span>
                    {{end}}</p>
                </div>
                <div>
                    <p class="font-semibold">Trust Status:</p>
                    <p>{{if eq .Certificate.TrustStatus "trusted"}}
                        <span class="text-green-600">✅ Certificate chain is trusted</span>
                    {{else if eq .Certificate.TrustStatus "revoked"}}
                        <span class="text-red-600">🚫 Certificate has been revoked</span>
                    {{else if eq .Certificate.TrustStatus "untrusted_root"}}
                        <span class="text-yellow-600">⚠️ Chain contains untrusted root</span>
                    {{else if eq .Certificate.TrustStatus "expired"}}
                        <span class="text-red-600">📛 Certificate has expired</span>
                    {{else if eq .Certificate.TrustStatus "valid"}}
                        <span class="text-yellow-600">⚠️ Certificate appears valid but chain verification incomplete</span>
                    {{else}}
                        <span class="text-red-600">❌ Certificate validation failed</span>
                    {{end}}</p>
                </div>
            </div>
        </div>
        {{end}}

        {{if .Chain}}
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 class="text-2xl font-bold mb-4">🔗 Certificate Chain</h2>
            {{range $index, $cert := .Chain}}
            <div class="{{if gt $index 0}}mt-6 pt-6 border-t border-gray-200{{end}}">
                <h3 class="text-xl font-bold mb-4">📜 Certificate {{add $index 1}}</h3>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <p class="font-semibold">Version:</p>
                        <p>{{.Version}}</p>
                    </div>
                    <div>
                        <p class="font-semibold">Serial Number:</p>
                        <p class="font-mono text-sm">{{.SerialNumber}}</p>
                    </div>
                    <div class="col-span-2">
                        <p class="font-semibold">Subject:</p>
                        <p>{{.Subject.CommonName}}</p>
                        {{if .Subject.Organization}}
                        <p class="text-sm text-gray-600">{{join .Subject.Organization ", "}}</p>
                        {{end}}
                    </div>
                    <div class="col-span-2">
                        <p class="font-semibold">Issuer:</p>
                        <p>{{.Issuer.CommonName}}</p>
                        {{if .Issuer.Organization}}
                        <p class="text-sm text-gray-600">{{join .Issuer.Organization ", "}}</p>
                        {{end}}
                    </div>
                    <div>
                        <p class="font-semibold">Valid From:</p>
                        <p>{{.NotBefore.Format "2006-01-02 15:04:05 UTC"}}</p>
                    </div>
                    <div>
                        <p class="font-semibold">Valid Until:</p>
                        <p>{{.NotAfter.Format "2006-01-02 15:04:05 UTC"}}</p>
                    </div>
                    <div class="col-span-2">
                        <p class="font-semibold">Signature Algorithm:</p>
                        <p>{{.SignatureAlg}}</p>
                    </div>
                    {{if .SubjectAltNames}}
                    <div class="col-span-2">
                        <p class="font-semibold">Subject Alternative Names:</p>
                        <div class="mt-2 space-y-1">
                            {{range .SubjectAltNames}}
                            <p class="text-sm font-mono">{{.}}</p>
                            {{end}}
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>
        {{end}}

        {{if .HPKP}}
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 class="text-2xl font-bold mb-4">📌 HPKP Information</h2>
            {{if .HPKP.HasHPKP}}
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <p class="font-semibold">Status:</p>
                    <p class="text-green-600">✅ HPKP is enabled</p>
                </div>
                {{if .HPKP.ReportOnly}}
                <div>
                    <p class="font-semibold">Mode:</p>
                    <p class="text-yellow-600">⚠️ Report-Only Mode</p>
                </div>
                {{end}}
                <div>
                    <p class="font-semibold">Max Age:</p>
                    <p>{{.HPKP.MaxAge}} seconds</p>
                </div>
            </div>
            {{else}}
            <p class="text-yellow-600">❌ HPKP is not enabled</p>
            {{end}}
        </div>
        {{end}}

        {{if .DNS}}
        <div class="bg-white rounded-lg shadow-md p-6">
            <h2 class="text-2xl font-bold mb-4">🌐 DNS Information</h2>
            {{if .DNS.IPv4Addresses}}
            <div class="mb-6">
                <h3 class="text-xl font-bold mb-4">📍 IPv4 Addresses</h3>
                <div class="grid grid-cols-1 gap-2">
                    {{range .DNS.IPv4Addresses}}
                    <p class="font-mono">{{.}}</p>
                    {{end}}
                </div>
            </div>
            {{end}}

            {{if .DNS.IPDetails}}
            <div>
                <h3 class="text-2xl font-bold mb-4">🌍 IP Information</h3>
                <div class="grid grid-cols-1 gap-6">
                    {{range .DNS.IPDetails}}
                    <div class="border-t border-gray-200 pt-4">
                        <p class="font-semibold">🔍 {{.IP}}</p>
                        <div class="grid grid-cols-2 gap-2 mt-2">
                            <p><span class="font-semibold">Country:</span> {{.Country}}</p>
                            <p><span class="font-semibold">City:</span> {{.City}}</p>
                            <p class="col-span-2"><span class="font-semibold">Organization:</span> {{.Organization}}</p>
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>
        {{end}}
    </div>
</body>
</html>
`
) 