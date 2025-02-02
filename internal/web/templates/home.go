package templates

const HomeTemplate = BaseHeader + `
    <div class="max-w-2xl mx-auto">
        <h1 class="text-3xl font-bold mb-8">SSL Certificate Checker 🔒</h1>
        <form action="/check" method="GET" class="mb-8">
            <div class="flex flex-col space-y-4">
                <div>
                    <input type="text" name="domain" placeholder="Enter domain (e.g., example.com)" 
                        class="w-full p-2 border rounded">
                </div>
                <div>
                    <input type="text" name="ip" placeholder="Target IP (optional)" 
                        class="w-full p-2 border rounded">
                </div>
                <div>
                    <button type="submit" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                        Check Certificate
                    </button>
                </div>
            </div>
        </form>
    </div>
` + BaseFooter 