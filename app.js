// Función para consultar VirusTotal a través de un proxy CORS
async function consultarVirusTotal(ioc, apiKey) {
    const url = `https://www.virustotal.com/api/v3/search?query=${ioc}`;
    const proxyUrl = `https://cors-anywhere.herokuapp.com/${url}`;
    const headers = {
        "x-apikey": apiKey
    };

    const response = await fetch(proxyUrl, {
        headers: headers
    });

    if (response.ok) {
        return await response.json();
    } else {
        return null;
    }
}

// Función para filtrar y extraer hashes, URLs, dominios e IPv4
function filtrarIOCs(texto) {
    const lines = texto.split('\n');
    const hashes = [];
    const urls = [];
    const domains = [];
    const ips = [];

    const hashPattern = /FileHash-(MD5|SHA1|SHA256)\s+([a-f0-9]+)/;
    const urlPattern = /https?:\/\/[^\s]+/;
    const domainPattern = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b/;
    const ipv4Pattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;

    lines.forEach(line => {
        const hashMatch = line.match(hashPattern);
        const urlMatch = line.match(urlPattern);
        const domainMatch = line.match(domainPattern);
        const ipv4Match = line.match(ipv4Pattern);

        if (hashMatch) hashes.push(hashMatch[2]);
        if (urlMatch) urls.push(urlMatch[0]);
        if (domainMatch) domains.push(domainMatch[0]);
        if (ipv4Match) ips.push(ipv4Match[0]);
    });

    return { hashes, urls, domains, ips };
}

// Función para procesar los IOCs
async function procesarIOCs() {
    const texto = document.getElementById('ioc-input').value.trim();
    const apiKey = document.getElementById('api-key').value.trim();
    const modo = document.querySelector('input[name="modo"]:checked').value;
    const progressBar = document.getElementById('progress-bar');
    const resultCount = document.getElementById('result-count');

    if (!apiKey) {
        alert("Por favor, introduce la API Key de VirusTotal.");
        return;
    }

    let iocs;
    if (modo === "Filtrado") {
        const { hashes, urls, domains, ips } = filtrarIOCs(texto);
        iocs = [...hashes, ...urls, ...domains, ...ips];
    } else {
        iocs = texto.split('\n');
    }

    let resultadosText = "";
    let positivos = 0;

    progressBar.style.display = 'block';
    resultCount.textContent = '';

    for (const ioc of iocs) {
        const resultado = await consultarVirusTotal(ioc, apiKey);
        if (resultado && resultado.data && resultado.data.length > 0) {
            const attributes = resultado.data[0].attributes;
            const detectedUrls = attributes.last_analysis_stats.malicious || 0;
            if (detectedUrls > 0) {
                resultadosText += `IOC: ${ioc} - ${detectedUrls}\n`;
                positivos++;
            }
        }
    }

    progressBar.style.display = 'none';
    document.getElementById('resultados').value = resultadosText;

    if (positivos > 0) {
        resultCount.textContent = `Positivos ${positivos} de ${iocs.length}`;
    } else {
        resultCount.textContent = "No hay resultados en VirusTotal";
    }
}

// Función para copiar resultados al portapapeles
function copiarResultados() {
    const resultados = document.getElementById('resultados').value;
    navigator.clipboard.writeText(resultados).then(() => {
        alert("Resultados copiados al portapapeles.");
    });
}

// Función para borrar la lista de IOCs
function clearIOCs() {
    document.getElementById('ioc-input').value = '';
}
