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

const ChainVisualization = `
<div class="bg-white rounded-lg shadow-md p-6 mb-6">
    <div class="flex justify-between items-center mb-4">
        <h2 class="text-2xl font-bold">🔗 Certificate Chain Structure</h2>
        {{if .Chain}}
            <a href="/download-chain?domain={{.Domain}}" 
               class="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 
                      text-white font-medium rounded-lg shadow-sm transition-colors duration-200">
                <span class="mr-2">⬇️</span>
                Download Full Chain
            </a>
        {{end}}
    </div>
    {{if not (isCompleteChain .Chain)}}
        <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-4">
            <div class="flex">
                <div class="flex-shrink-0">
                    <svg class="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
                    </svg>
                </div>
                <div class="ml-3">
                    <p class="text-sm text-yellow-700">
                        This chain is incomplete. The root certificate ({{(lastCert .Chain).Issuer.CommonName}}) is not included in the server response.
                        Use the download button to get the complete chain including the root certificate.
                    </p>
                </div>
            </div>
        </div>
    {{end}}
    <div class="flex flex-col items-center space-y-8 py-4">
        {{range $i, $cert := .Chain}}
            {{if gt $i 0}}
                <div class="h-8 w-0.5 bg-gradient-to-b from-green-500 to-green-500"></div>
            {{end}}
            <div class="w-full max-w-md bg-gradient-to-r from-gray-50 to-gray-100 border-2 
                        {{if eq $i 0}}
                            border-blue-500 shadow-blue-100
                        {{else if eq $i (sub (len $.Chain) 1)}}
                            border-green-500 shadow-green-100
                        {{else}}
                            border-gray-300 shadow-gray-100
                        {{end}}
                        rounded-lg p-4 relative shadow-lg hover:shadow-xl transition-shadow duration-200">
                {{if gt $i 0}}
                    <div class="absolute -top-8 left-1/2 transform -translate-x-1/2 w-0.5 h-8 bg-gradient-to-t from-green-500 to-green-500"></div>
                {{end}}
                <div class="text-center">
                    <div class="font-mono text-lg font-semibold mb-2">
                        {{if eq $i 0}}
                            🌐 {{$cert.Subject.CommonName}}
                        {{else if eq $i (sub (len $.Chain) 1)}}
                            🔐 {{$cert.Subject.CommonName}}
                        {{else}}
                            🔗 {{$cert.Subject.CommonName}}
                        {{end}}
                    </div>
                    {{if $cert.Subject.Organization}}
                        <div class="text-gray-600 text-sm mt-1">({{join $cert.Subject.Organization ", "}})</div>
                    {{end}}
                    <div class="text-xs text-gray-500 mt-2">
                        Valid until {{$cert.NotAfter.Format "2006-01-02"}}
                    </div>
                </div>
            </div>
        {{end}}
    </div>
</div>`

const ChainSection = `
{{if .Chain}}
` + ChainVisualization + `
<div class="bg-white rounded-lg shadow-md p-6 mb-6">
    <h2 class="text-2xl font-bold mb-4">📜 Certificate Details</h2>
    {{range $index, $cert := .Chain}}
    <div class="{{if gt $index 0}}mt-6 pt-6 border-t border-gray-200{{end}}">
        <h3 class="text-xl font-bold mb-4">Certificate {{add $index 1}}</h3>
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