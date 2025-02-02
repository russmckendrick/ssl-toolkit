package templates

const ResultTemplate = BaseHeader + `
    <div class="flex justify-between items-center mb-8">
        <h1 class="text-3xl font-bold">Results for {{.Domain}} 🔍</h1>
        <a href="/" class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">New Check</a>
    </div>

    {{if .ErrorMessage}}
    <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-6">
        <div class="flex items-center">
            <div class="flex-shrink-0">
                ❌
            </div>
            <div class="ml-3">
                <p class="text-sm">{{.ErrorMessage}}</p>
                {{if .ShowRetryWithoutIP}}
                <div class="mt-4">
                    <a href="/check?domain={{.Domain}}" 
                       class="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded text-sm inline-flex items-center">
                        🔄 Retry without custom IP
                    </a>
                </div>
                {{end}}
            </div>
        </div>
    </div>
    {{else}}
        {{if .TargetIP}}
        <div class="bg-blue-100 border-l-4 border-blue-500 text-blue-700 p-4 mb-6">
            <p>Certificate checked at IP: {{.TargetIP}}</p>
        </div>
        {{end}}
        
        ` + CertificateSection + ChainVisualization + ChainSection + HPKPSection + DNSSection + `
    {{end}}
` + BaseFooter 