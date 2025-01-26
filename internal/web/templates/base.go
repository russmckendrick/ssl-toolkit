package templates

const (
	BaseHeader = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 p-8">
    <div class="max-w-4xl mx-auto">`

	BaseFooter = `
    </div>
</body>
</html>`
) 