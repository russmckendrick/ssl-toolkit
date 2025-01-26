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
    <!-- ... rest of the template ... -->
</body>
</html>
`
) 