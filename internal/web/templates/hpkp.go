package templates

const HPKPSection = `
{{if .HPKP}}
<div class="bg-white rounded-lg shadow-md p-6 mb-6">
    <h2 class="text-2xl font-bold mb-4">📌 HPKP Information</h2>
    {{if .HPKP.HasHPKP}}
    <!-- ... HPKP details ... -->
    {{else}}
    <p class="text-yellow-600">❌ HPKP is not enabled</p>
    {{end}}
</div>
{{end}}` 