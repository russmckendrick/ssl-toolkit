package templates

const ResultTemplate = BaseHeader + `
    <div class="flex justify-between items-center mb-8">
        <h1 class="text-3xl font-bold">Results for {{.Domain}} 🔍</h1>
        <a href="/" class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">New Check</a>
    </div>
` + CertificateSection + ChainVisualization + ChainSection + HPKPSection + DNSSection + BaseFooter 