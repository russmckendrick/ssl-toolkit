package templates

const (
    BaseHeader = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen p-8">
    <div class="max-w-6xl mx-auto">`

    BaseFooter = `
    </div>
</body>
</html>`
)

// HomeContent is the content for the home page
const HomeContent = `
<div class="bg-white rounded-lg shadow-md p-6">
    <h1 class="text-3xl font-bold mb-8">SSL Certificate Checker 🔒</h1>
    <form action="/check" method="get" class="flex gap-4">
        <input type="text" name="domain" 
            placeholder="Enter domain (e.g., example.com)" 
            class="flex-1 p-2 border rounded-lg">
        <button type="submit" 
            class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
            Check
        </button>
    </form>
</div>
`

// CheckContent combines all the certificate templates
const CheckContent = CertificateSection + ChainVisualization + ChainSection + HPKPSection + DNSSection 