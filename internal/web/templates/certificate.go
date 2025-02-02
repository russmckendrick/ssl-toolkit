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
    </div>

    <div class="flex flex-col items-center space-y-2 py-4">
        {{range $i, $cert := .Chain}}
            {{if gt $i 0}}
                <div class="h-2 w-0 border-l-2 border-dashed border-gray-300"></div>
            {{end}}
            <div class="w-full max-w-md bg-gradient-to-r from-gray-50 to-gray-100 border-2 
                        {{if eq $i 0}}
                            border-blue-500 shadow-blue-100
                        {{else if eq $i (sub (len $.Chain) 1)}}
                            border-green-500 shadow-green-100
                        {{else}}
                            border-gray-300 shadow-gray-100
                        {{end}}
                        rounded-lg p-4 relative hover:shadow-sm transition-shadow duration-200">
                {{if gt $i 0}}
                    <div class="absolute -top-2 left-1/2 transform -translate-x-1/2 w-0 h-2 border-l-2 border-dashed border-gray-300"></div>
                {{end}}
                <div class="text-center">
                    <div class="font-mono text-lg font-semibold mb-2">
                        {{if eq $i 0}}
                            🌐 {{$cert.Subject.CommonName}}
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

        {{if and (not (isCompleteChain .Chain)) (not (isSelfSigned (lastCert .Chain)))}}
            <div class="h-2 w-0 border-l-2 border-dashed border-gray-300"></div>
            <div class="w-full max-w-md border-2 border-dashed border-gray-300 
                       rounded-lg p-4 relative opacity-50 bg-gray-50">
                <div class="text-center">
                    <div class="font-mono text-lg font-semibold mb-2 text-gray-500">
                        🔐 {{(lastCert .Chain).Issuer.CommonName}}
                    </div>
                    <div class="text-xs text-gray-500 mt-2">
                        Root Certificate (Not Included)
                    </div>
                </div>
            </div>
        {{end}}
    </div>

    <div class="mt-8 flex flex-col sm:flex-row justify-between items-center space-y-4 sm:space-y-0">
        {{if and (not (isCompleteChain .Chain)) (not (isSelfSigned (lastCert .Chain)))}}
            <div class="text-sm text-gray-600 flex items-center">
                <span class="mr-2">ℹ️</span>
                Note: Root certificate ({{(lastCert .Chain).Issuer.CommonName}}) is not included in the server response, which is normal.
            </div>
        {{end}}
        {{if .Chain}}
            <a href="/download-chain?domain={{.Domain}}" 
               class="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 
                      text-white font-medium rounded-lg shadow-sm transition-colors duration-200">
                <span class="mr-2">⬇️</span>
                Download Full Chain
            </a>
        {{end}}
    </div>
</div>`

const ChainSection = `
{{if .Chain}}
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