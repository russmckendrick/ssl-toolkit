package templates

const DNSSection = `
{{if .DNS}}
<div class="bg-white rounded-lg shadow-md p-6">
    <h2 class="text-2xl font-bold mb-4">🌐 DNS Information</h2>

    <div class="mb-6">
        <h3 class="text-xl font-bold mb-4">🔍 Nameserver Consistency</h3>
        {{if .DNS.IsConsistent}}
        <div class="p-4 bg-green-100 text-green-700 rounded-lg">
            <p>✅ All nameservers are returning consistent records</p>
        </div>
        {{else}}
        <div class="p-4 bg-red-100 text-red-700 rounded-lg">
            <p>⚠️ Inconsistencies detected between nameservers</p>
        </div>
        {{end}}

        <div class="mt-4 space-y-4">
        {{range .DNS.NameserverChecks}}
            <div class="border rounded-lg p-4">
                <h4 class="font-bold">📡 {{.Nameserver}}</h4>
                {{if .IsConsistent}}
                <p class="text-green-600">✓ Records match canonical records</p>
                {{else}}
                <p class="text-red-600">✗ Records differ from canonical records</p>
                {{end}}
                {{if .IPv4Addresses}}
                <div class="mt-2">
                    <p class="font-semibold">IPv4 Records:</p>
                    {{range .IPv4Addresses}}
                    <p class="font-mono ml-4">{{.}}</p>
                    {{end}}
                </div>
                {{end}}
                {{if .IPv6Addresses}}
                <div class="mt-2">
                    <p class="font-semibold">IPv6 Records:</p>
                    {{range .IPv6Addresses}}
                    <p class="font-mono ml-4">{{.}}</p>
                    {{end}}
                </div>
                {{end}}
            </div>
        {{end}}
        </div>
    </div>

    {{if .DNS.IPv4Addresses}}
    <div class="mb-6">
        <h3 class="text-xl font-bold mb-4">📍 IPv4 Addresses</h3>
        <div class="grid grid-cols-1 gap-4">
            {{range $i, $ip := .DNS.IPv4Addresses}}
            <div class="border-t border-gray-200 pt-4">
                <p class="font-mono font-semibold">{{$ip}}</p>
                {{if index $.DNS.IPv4Details $i}}
                <div class="grid grid-cols-2 gap-2 mt-2">
                    {{with index $.DNS.IPv4Details $i}}
                        {{if .Country}}<p><span class="font-semibold">Country:</span> {{.Country}}</p>{{end}}
                        {{if .City}}<p><span class="font-semibold">City:</span> {{.City}}</p>{{end}}
                        {{if .Organization}}<p class="col-span-2"><span class="font-semibold">Organization:</span> {{.Organization}}</p>{{end}}
                    {{end}}
                </div>
                {{end}}
            </div>
            {{end}}
        </div>
    </div>
    {{end}}

    {{if .DNS.IPv6Addresses}}
    <div class="mb-6">
        <h3 class="text-xl font-bold mb-4">📍 IPv6 Addresses</h3>
        <div class="grid grid-cols-1 gap-4">
            {{range $i, $ip := .DNS.IPv6Addresses}}
            <div class="border-t border-gray-200 pt-4">
                <p class="font-mono font-semibold">{{$ip}}</p>
                {{if index $.DNS.IPv6Details $i}}
                <div class="grid grid-cols-2 gap-2 mt-2">
                    {{with index $.DNS.IPv6Details $i}}
                        {{if .Country}}<p><span class="font-semibold">Country:</span> {{.Country}}</p>{{end}}
                        {{if .City}}<p><span class="font-semibold">City:</span> {{.City}}</p>{{end}}
                        {{if .Organization}}<p class="col-span-2"><span class="font-semibold">Organization:</span> {{.Organization}}</p>{{end}}
                    {{end}}
                </div>
                {{end}}
            </div>
            {{end}}
        </div>
    </div>
    {{end}}
</div>
{{end}}` 