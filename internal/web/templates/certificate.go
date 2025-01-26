package templates

const CertificateSection = `
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
{{end}}`

const ChainSection = `
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
{{end}}` 