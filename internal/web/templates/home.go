package templates

const HomeTemplate = BaseHeader + `
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
` + BaseFooter 